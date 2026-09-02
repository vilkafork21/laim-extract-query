"""Собрать SQL чтения готового train/test-окна из витрины ЦДИО."""

from __future__ import annotations

import json
import re
from typing import NoReturn

from laim_extract_profiles.profile_contract import (
    CDIO_SOURCE,
    QUERY_SELECTION_SCHEMA_VERSION,
    SELECTION_IDENTITY_FIELDS,
    compute_selection_id,
)


REQUIRED_SELECTION_FIELDS = set(SELECTION_IDENTITY_FIELDS) | {
    "run_id",
    "selection_id",
    "source",
}


def fail_query(message: str) -> NoReturn:
    raise ValueError(f"LAIM Extract Query Date Window: {message}")


def _parse_selection(value: object) -> dict:
    if isinstance(value, str):
        if not value.strip():
            fail_query("не пришли параметры временной выборки")
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            fail_query(f"параметры выборки пришли строкой, но это не JSON: {error}")
    if not isinstance(value, dict) or not value:
        fail_query("не пришли параметры временной выборки")
    return dict(value)


def _safe_identifier(value: object, field_name: str, *, dotted: bool = False) -> str:
    text = str(value or "").strip()
    identifier_pattern = r"[A-Za-z_][A-Za-z0-9_]*"
    parts = text.split(".") if dotted else [text]
    if not text or not all(re.fullmatch(identifier_pattern, part) for part in parts):
        fail_query(f"{field_name} не является безопасным SQL-идентификатором")
    return text


def _safe_sql_text(value: object, field_name: str, max_length: int = 1000) -> str:
    text = str(value or "")
    if text != text.strip():
        fail_query(f"{field_name} содержит внешние пробелы")
    if not text:
        fail_query(f"{field_name} не заполнен")
    if len(text) > max_length:
        fail_query(f"{field_name} длиннее {max_length} символов")
    for forbidden in ("'", '"', ";", "--", "\\", "\n", "\r"):
        if forbidden in text:
            fail_query(f"недопустимая последовательность в {field_name}: {forbidden!r}")
    return text


def _strict_integer(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail_query(f"{field_name} должен быть целым числом")
    return value


def validate_window_selection(value: object) -> dict:
    selection = _parse_selection(value)
    missing_fields = sorted(REQUIRED_SELECTION_FIELDS - set(selection))
    if missing_fields:
        fail_query(f"в параметрах выборки отсутствуют поля: {missing_fields}")

    if selection["schema_version"] != QUERY_SELECTION_SCHEMA_VERSION:
        fail_query("неподдерживаемая версия параметров временной выборки")

    source = selection["source"]
    if not isinstance(source, dict):
        fail_query("описание источника должно быть объектом")
    expected_source = {
        key: value for key, value in CDIO_SOURCE.items() if key != "label"
    }
    actual_source = {key: source.get(key) for key in expected_source}
    if actual_source != expected_source:
        fail_query("поддерживается только утверждённый источник cdio_prod")

    _safe_identifier(source["table"], "source.table", dotted=True)
    for source_field in (
        "agent_column",
        "version_column",
        "start_column",
        "end_column",
        "trace_column",
        "span_column",
    ):
        _safe_identifier(source[source_field], f"source.{source_field}")

    _safe_sql_text(selection["agent_ci"], "agent_ci")
    _safe_sql_text(selection["distributive"], "distributive")
    ts_ns = _strict_integer(selection["ts_ns"], "ts_ns")
    te_ns = _strict_integer(selection["te_ns"], "te_ns")
    scan_lo_ns = _strict_integer(selection["scan_lo_ns"], "scan_lo_ns")
    scan_hi_ns = _strict_integer(selection["scan_hi_ns"], "scan_hi_ns")
    if not scan_lo_ns <= ts_ns < te_ns <= scan_hi_ns:
        fail_query("нарушен порядок наносекундных границ scan_lo <= ts < te <= scan_hi")

    selection_id = str(selection["selection_id"])
    if not re.fullmatch(r"[0-9a-f]{64}", selection_id):
        fail_query("selection_id должен быть SHA-256")
    if compute_selection_id(selection) != selection_id:
        fail_query("selection_id не соответствует параметрам выборки")
    if not str(selection["run_id"]).strip():
        fail_query("run_id не заполнен")
    return selection


def _source_filter(selection: dict, alias: str = "") -> str:
    source = selection["source"]
    column_prefix = f"{alias}." if alias else ""
    agent_column = source["agent_column"]
    version_column = source["version_column"]
    agent_id = _safe_sql_text(selection["agent_ci"], "agent_ci")
    distributive = _safe_sql_text(selection["distributive"], "distributive")
    return (
        f"{column_prefix}{agent_column} = '{agent_id}'\n"
        f"    AND {column_prefix}{version_column} = '{distributive}'"
    )


def _compile_window_sql(selection: dict) -> str:
    source = selection["source"]
    table = source["table"]
    trace_column = source["trace_column"]
    span_column = source["span_column"]
    start_column = source["start_column"]
    end_column = source["end_column"]
    ts_ns = selection["ts_ns"]
    te_ns = selection["te_ns"]

    return f"""WITH universe AS (
  SELECT {trace_column} AS trace_id,
         CAST({start_column} AS BIGINT) AS start_ns,
         CAST({end_column} AS BIGINT) AS end_ns,
         session_id,
         aef_kind,
         input_text,
         output_text
  FROM {table}
  WHERE {trace_column} IS NOT NULL
    AND {_source_filter(selection)}
),
trace_bounds AS (
  SELECT trace_id,
         MIN(start_ns) AS trace_start_ns,
         MAX(end_ns) AS trace_end_ns,
         SUM(CASE
           WHEN aef_kind IN ('input_request', 'start_agent')
             AND COALESCE(session_id, '') != ''
             AND COALESCE(input_text, '') != ''
             AND COALESCE(output_text, '') != ''
           THEN 1 ELSE 0
         END) AS good_agent_spans
  FROM universe
  GROUP BY trace_id
),
selected_traces AS (
  SELECT trace_id
  FROM trace_bounds
  WHERE (trace_end_ns >= {ts_ns} AND trace_end_ns < {te_ns})
    AND good_agent_spans >= 1
)
SELECT source_rows.*
FROM {table} source_rows
JOIN selected_traces
  ON source_rows.{trace_column} = selected_traces.trace_id
WHERE source_rows.{trace_column} IS NOT NULL
  AND {_source_filter(selection, "source_rows")}
ORDER BY CAST(source_rows.{start_column} AS BIGINT) ASC,
         source_rows.{trace_column} ASC,
         source_rows.{span_column} ASC"""


def build_window_sql(selection_value: object) -> str:
    return _compile_window_sql(validate_window_selection(selection_value))


def main(selection: object = None) -> dict[str, dict[str, str]]:
    query_selection = validate_window_selection(selection)
    sql = _compile_window_sql(query_selection)
    print(
        "LAIM Extract Query Date Window | "
        f"agent={query_selection['agent_ci']} | "
        f"period=[{query_selection['ts_ns']}, {query_selection['te_ns']}) | "
        f"selection={str(query_selection['selection_id'])[:12]}"
    )
    return {"sql_dict": {"sql": sql}}
