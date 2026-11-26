"""Walk every string in a parsed-JSON structure, so no field escapes inspection."""

from typing import Any, Callable, Iterator


def _is_media(s: str) -> bool:
    # Inline base64 media (data:image/png;base64,...) is not prompt text, and redacting it would corrupt the file.
    return s.startswith("data:")


def iter_strings(obj: Any) -> Iterator[str]:
    """Yield every string key and value, at any depth."""
    if isinstance(obj, str):
        if not _is_media(obj):
            yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_strings(k)
            yield from iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v)


def map_strings(obj: Any, fn: Callable[[str], str]) -> Any:
    """Return a copy of obj with fn applied to every string value (keys are kept)."""
    if isinstance(obj, str):
        return obj if _is_media(obj) else fn(obj)
    if isinstance(obj, dict):
        return {k: map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [map_strings(v, fn) for v in obj]
    return obj
