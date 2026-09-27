"""
Local Model Abstraction Layer.

Provides a single interface (`generate`) that can be backed by:
 - "none": a deterministic, template-based summarizer (default, zero external
   calls, zero privacy risk) — always available, used for CI/tests and any
   environment without a local model configured.
 - "local_http": any OpenAI/Ollama-style local HTTP completion endpoint the
   user points at their own on-box model.

No private data is ever sent anywhere unless the user explicitly configures
`ECHOBOUND_LOCAL_AI_ENDPOINT` AND sets `local_ai_allow_external=True` for a
non-loopback endpoint. The default posture sends nothing off-host.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..config import settings


class LocalModelAbstraction:
    def __init__(self, endpoint: Optional[str] = None, allow_external: Optional[bool] = None):
        self.endpoint = endpoint if endpoint is not None else settings.local_ai_endpoint
        self.allow_external = settings.local_ai_allow_external if allow_external is None else allow_external

    def _endpoint_is_local(self) -> bool:
        if not self.endpoint:
            return True
        host = urlparse(self.endpoint).hostname or ""
        return host in ("localhost", "127.0.0.1", "::1")

    def available(self) -> bool:
        return settings.local_ai_enabled

    def generate(self, prompt: str, max_tokens: int = 400) -> str:
        if not self.available():
            return "[Local AI disabled] " + self._deterministic_fallback(prompt)

        if self.endpoint and (self._endpoint_is_local() or self.allow_external):
            try:
                return self._call_http_endpoint(prompt, max_tokens)
            except Exception as exc:  # network errors, malformed responses, etc.
                return f"[Local AI endpoint unreachable: {exc}] " + self._deterministic_fallback(prompt)

        return self._deterministic_fallback(prompt)

    def _call_http_endpoint(self, prompt: str, max_tokens: int) -> str:
        body = json.dumps({"prompt": prompt, "max_tokens": max_tokens}).encode()
        req = urllib.request.Request(
            self.endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("text") or data.get("response") or json.dumps(data)

    @staticmethod
    def _deterministic_fallback(prompt: str) -> str:
        """A template-based explanation used whenever no local model is
        configured. It never invents facts — it just formats the evidence
        that was already assembled by the investigator/tools layer, which is
        embedded directly inside `prompt`."""
        return (
            "Deterministic summary (no local model configured):\n" + prompt[-1500:]
        )
