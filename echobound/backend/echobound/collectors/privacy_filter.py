"""
Privacy Filter — applied at the collector layer, before any metadata leaves
the host. Hashes, masks, tokenizes or drops sensitive fields; raw file/
process content is never collected in the first place (only metadata is
gathered upstream), and this filter is the last line of defense on the
metadata itself.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable

from ..config import settings

SENSITIVE_FIELD_ACTIONS = {
    "command_line_args": "mask",
    "env_vars": "drop",
    "file_content": "drop",
    "auth_token": "hash",
    "password": "drop",
    "session_cookie": "hash",
    "email": "tokenize",
}


def _hash(value: str) -> str:
    return "h_" + hashlib.sha256((settings.privacy_hash_salt + str(value)).encode()).hexdigest()[:24]


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


_token_map: Dict[str, str] = {}
_token_counter = [0]


def _tokenize(value: str) -> str:
    if value not in _token_map:
        _token_counter[0] += 1
        _token_map[value] = f"tok_{_token_counter[0]:08d}"
    return _token_map[value]


class PrivacyFilter:
    def __init__(self, extra_rules: Dict[str, str] | None = None):
        self.rules = {**SENSITIVE_FIELD_ACTIONS, **(extra_rules or {})}

    def apply(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(payload)
        for field_name, action in self.rules.items():
            if field_name not in out:
                continue
            if action == "drop":
                out.pop(field_name, None)
            elif action == "hash":
                out[field_name] = _hash(str(out[field_name]))
            elif action == "mask":
                out[field_name] = _mask(str(out[field_name]))
            elif action == "tokenize":
                out[field_name] = _tokenize(str(out[field_name]))
        if not settings.collect_raw_payloads:
            out.pop("raw", None)
        return out

    def apply_many(self, payloads: Iterable[Dict[str, Any]]):
        return [self.apply(p) for p in payloads]
