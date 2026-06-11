from enum import StrEnum

from .errors import AppError


class PolicyName(StrEnum):
    PASSWORD = "password"
    PCR = "pcr"


def validate_policy_inputs(policy: str, auth: str | None, pcrs: str | None = None) -> PolicyName:
    try:
        selected = PolicyName(policy)
    except ValueError as exc:
        supported = ", ".join(item.value for item in PolicyName)
        raise AppError(f"Unsupported policy '{policy}'. Supported policies: {supported}.") from exc

    if selected == PolicyName.PASSWORD and not auth:
        raise AppError("Password policy requires --auth.")
    if selected == PolicyName.PCR and not pcrs:
        raise AppError("PCR policy requires --pcrs.")
    return selected


def parse_pcrs(pcrs: str) -> list[int]:
    try:
        values = [int(item.strip()) for item in pcrs.split(",") if item.strip()]
    except ValueError as exc:
        raise AppError("PCR indexes must be integers, for example: --pcrs 7 or --pcrs 7,16.") from exc

    if not values:
        raise AppError("PCR policy requires at least one PCR index.")
    if len(values) != len(set(values)):
        raise AppError("PCR indexes must not contain duplicates.")
    for value in values:
        if value < 0 or value > 23:
            raise AppError("PCR indexes must be between 0 and 23.")
    return values


def auth_callback(_path: str, _description: str, user_data: str | None = None) -> str:
    if not user_data:
        raise AppError("TPM requested an auth value, but no auth value was provided.")
    return user_data
