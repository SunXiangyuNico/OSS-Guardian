#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OpenAI-compatible provider wrapper.
"""

from typing import Dict, List, Optional, Union


class OpenAIProvider:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: int = 30,
        max_retries: int = 2,
        timeout_connect: Optional[float] = None,
        timeout_read: Optional[float] = None,
        timeout_write: Optional[float] = None
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.timeout_connect = timeout_connect
        self.timeout_read = timeout_read
        self.timeout_write = timeout_write

    def _build_timeout(self) -> Union[float, "httpx.Timeout"]:
        if self.timeout_connect is None and self.timeout_read is None and self.timeout_write is None:
            return float(self.timeout)
        try:
            import httpx
        except Exception:
            return float(self.timeout)
        return httpx.Timeout(
            float(self.timeout),
            connect=self.timeout_connect,
            read=self.timeout_read,
            write=self.timeout_write
        )

    def chat(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None) -> str:
        try:
            from openai import OpenAI
        except Exception as exc:
            raise RuntimeError(f"OpenAI SDK not available: {exc}") from exc

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self._build_timeout(),
            max_retries=self.max_retries
        )
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        response = client.chat.completions.create(**payload)
        if not response or not getattr(response, "choices", None):
            return ""
        choice = response.choices[0]
        message = getattr(choice, "message", None)
        if not message:
            return ""
        return getattr(message, "content", "") or ""
