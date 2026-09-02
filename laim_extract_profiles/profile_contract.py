"""Строгий генератор параметров временной выборки для LAIM Extract Query."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import NoReturn


QUERY_SELECTION_SCHEMA_VERSION = 2
NS_PER_DAY = 86_400 * 10**9
SIGNED_BIGINT_MAX_NS = 2**63 - 1
TRACE_SCAN_BACK_DAYS = 3
TRACE_SCAN_FORWARD_DAYS = 1
MOSCOW_TIMEZONE = timezone(timedelta(hours=3), name="MSK")

CDIO_SOURCE = {
    "source_id": "cdio_prod",
    "label": "Прод-витрина ЦДИО",
    "table": "t_team_cdiotraces.aef_trace_expanded",
    "agent_column": "agent_id",
    "version_column": "distributive",
    "start_column": "start_time_ns",
    "end_column": "end_time_ns",
    "trace_column": "trace_id",
    "span_column": "span_id",
}

SELECTION_IDENTITY_FIELDS = (
    "schema_version",
    "agent_ci",
    "distributive",
    "date_from",
    "date_to",
    "tz",
    "ts_ns",
    "te_ns",
    "scan_lo_ns",
    "scan_hi_ns",
    "modes",
    "unit",
    "target_consumer",
    "require_agent_span",
    "vol_max",
    "hard_max_spans",
    "test_pct",
    "split_method",
    "seed",
    "detector_enabled",
    "consistency_mode",
    "strict_full_trace",
)


def fail_profile(message: str) -> NoReturn:
    raise ValueError(f"профиль временной выборки: {message}")


def parse_calendar_date(value: object, parameter_name: str) -> date:
    text = str(value or "")
    if text != text.strip():
        fail_profile(f"{parameter_name} содержит внешние пробелы")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
        fail_profile(
            f"{parameter_name} должна быть датой ГГГГ-ММ-ДД, получено: {text!r}"
        )
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        fail_profile(
            f"{parameter_name} должна быть датой ГГГГ-ММ-ДД, получено: {text!r}"
        )


def resolve_timezone(timezone_name: str) -> timezone:
    if timezone_name == "Europe/Moscow":
        return MOSCOW_TIMEZONE
    if timezone_name == "UTC":
        return timezone.utc
    fail_profile(
        "часовой пояс (tz) должен быть Europe/Moscow или UTC, "
        f"получено: {timezone_name!r}"
    )


def validate_exact_text(
    value: object, parameter_name: str, max_length: int = 1000
) -> str:
    text = str(value or "")
    if text != text.strip():
        fail_profile(f"{parameter_name} содержит внешние пробелы")
    if len(text) > max_length:
        fail_profile(f"{parameter_name} длиннее {max_length} символов")
    for forbidden in ("'", '"', ";", "--", "\\", "\n", "\r"):
        if forbidden in text:
            fail_profile(
                f"недопустимая последовательность {forbidden!r} в {parameter_name}"
            )
    return text


def normalize_agent_id(value: object) -> str:
    normalized_agent_id = validate_exact_text(value, "agent_id").upper()
    if not re.fullmatch(r"C[IE][0-9]{6,12}", normalized_agent_id):
        fail_profile(
            f"agent_id должен быть CI/CE и 6–12 цифр, получено: {normalized_agent_id!r}"
        )
    return normalized_agent_id


def _start_of_day_ns(day: date, period_timezone: timezone) -> int:
    local_midnight = datetime(day.year, day.month, day.day, tzinfo=period_timezone)
    unix_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    since_epoch = local_midnight.astimezone(timezone.utc) - unix_epoch
    seconds_since_epoch = since_epoch.days * 86_400 + since_epoch.seconds
    return seconds_since_epoch * 10**9 + since_epoch.microseconds * 1000


def _canonical_json_sha256(payload: dict) -> str:
    raw = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def compute_selection_id(selection_identity: dict) -> str:
    hash_payload = {key: selection_identity[key] for key in SELECTION_IDENTITY_FIELDS}
    hash_payload["source"] = {
        key: value
        for key, value in selection_identity["source"].items()
        if key != "label"
    }
    return _canonical_json_sha256(hash_payload)


def build_query_selection(
    *,
    agent_id: object,
    distributive: object,
    period_start_date: date,
    period_end_date: date,
    timezone_name: str,
) -> dict:
    """Собрать параметры Query, не открывая оператору защитные настройки."""
    normalized_agent_id = normalize_agent_id(agent_id)
    exact_distributive = validate_exact_text(distributive, "distributive")
    if not exact_distributive:
        fail_profile("distributive обязателен для пары agent × distributive")

    period_timezone = resolve_timezone(str(timezone_name or ""))
    if period_start_date > period_end_date:
        fail_profile(
            f"начальная дата {period_start_date} позже конечной даты {period_end_date}"
        )

    try:
        exclusive_end_date = period_end_date + timedelta(days=1)
    except OverflowError:
        fail_profile("период не помещается в signed BIGINT наносекунд витрины")
    ts_ns = _start_of_day_ns(period_start_date, period_timezone)
    te_ns = _start_of_day_ns(exclusive_end_date, period_timezone)
    scan_lo_ns = ts_ns - TRACE_SCAN_BACK_DAYS * NS_PER_DAY
    scan_hi_ns = te_ns + TRACE_SCAN_FORWARD_DAYS * NS_PER_DAY
    if scan_lo_ns < 0:
        fail_profile("период до 1970-01-04 не поддерживается наносекундным контрактом")
    if scan_hi_ns > SIGNED_BIGINT_MAX_NS:
        fail_profile("период не помещается в signed BIGINT наносекунд витрины")
    selection_identity = {
        "schema_version": QUERY_SELECTION_SCHEMA_VERSION,
        "source": dict(CDIO_SOURCE),
        "agent_ci": normalized_agent_id,
        "distributive": exact_distributive,
        "date_from": period_start_date.isoformat(),
        "date_to": period_end_date.isoformat(),
        "tz": timezone_name,
        "ts_ns": ts_ns,
        "te_ns": te_ns,
        "scan_lo_ns": scan_lo_ns,
        "scan_hi_ns": scan_hi_ns,
        # full + before эквивалентны принадлежности по max(end_time_ns).
        "modes": ["full", "before"],
        "unit": "trace",
        "target_consumer": "dataset_converter",
        "require_agent_span": True,
        "vol_max": 0,
        "hard_max_spans": 0,
        # Служебные поля опубликованного контракта; Query Date Window split не применяет.
        "test_pct": 20,
        "split_method": "random",
        "seed": "42",
        "detector_enabled": False,
        "consistency_mode": "datasource_sql",
        "strict_full_trace": True,
    }
    selection_digest = compute_selection_id(selection_identity)
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        + "_"
        + uuid.uuid4().hex[:8]
    )
    query_selection = {
        **selection_identity,
        "selection_id": selection_digest,
        "run_id": run_id,
        "artifact_scope": f"sel_{selection_digest[:12]}_{run_id[-8:]}",
        "event_id": "",
        "params_source": "manual",
    }
    return {"selection": query_selection}
