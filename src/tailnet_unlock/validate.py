"""Narrow untrusted, parsed input (TOML, JSON) from `object` to concrete types.

Every function takes the value and a `where` string naming its place in the input, and raises the
given error type with a message that names that place.
"""

from collections.abc import Callable, Iterable

type ErrorType = Callable[[str], Exception]


def as_table(value: object, where: str, error: ErrorType) -> dict[str, object]:
    if not isinstance(value, dict):
        raise error(f"{where}: expected a table")
    table: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise error(f"{where}: keys must be strings")
        table[key] = item
    return table


def only_keys(
    table: dict[str, object], allowed: Iterable[str], where: str, error: ErrorType
) -> None:
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        raise error(f"{where}: unknown key(s): {', '.join(unknown)}")


def get_str(
    table: dict[str, object], key: str, default: str | None, where: str, error: ErrorType
) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise error(f"{where}.{key}: expected a string")
    return value


def get_opt_str(table: dict[str, object], key: str, where: str, error: ErrorType) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise error(f"{where}.{key}: expected a string")
    return value


def get_int(
    table: dict[str, object],
    key: str,
    default: int | None,
    where: str,
    error: ErrorType,
    low: int,
    high: int,
) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise error(f"{where}.{key}: expected an integer")
    if not low <= value <= high:
        raise error(f"{where}.{key}: must be between {low} and {high}")
    return value


def get_bool(
    table: dict[str, object], key: str, default: bool, where: str, error: ErrorType
) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise error(f"{where}.{key}: expected true or false")
    return value


def get_str_list(
    table: dict[str, object], key: str, default: tuple[str, ...], where: str, error: ErrorType
) -> tuple[str, ...]:
    value = table.get(key, list(default))
    if not isinstance(value, list):
        raise error(f"{where}.{key}: expected a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise error(f"{where}.{key}: expected a list of strings")
        items.append(item)
    return tuple(items)


def one_of[T: str](value: str, choices: tuple[T, ...], where: str, error: ErrorType) -> T:
    for choice in choices:
        if value == choice:
            return choice
    raise error(f"{where}: must be one of {', '.join(choices)}")
