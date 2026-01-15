#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simple file-based cache for agent requests.
"""

import json
import os
import time
from typing import Any, Optional


def _cache_path(cache_dir: str, cache_key: str) -> str:
    return os.path.join(cache_dir, f"{cache_key}.json")


def load_cache(cache_dir: str, cache_key: str, ttl_seconds: int) -> Optional[Any]:
    if not cache_dir or not cache_key:
        return None
    path = _cache_path(cache_dir, cache_key)
    if not os.path.exists(path):
        return None
    if ttl_seconds > 0:
        mtime = os.path.getmtime(path)
        if (time.time() - mtime) > ttl_seconds:
            return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_cache(cache_dir: str, cache_key: str, payload: Any) -> None:
    if not cache_dir or not cache_key:
        return
    os.makedirs(cache_dir, exist_ok=True)
    path = _cache_path(cache_dir, cache_key)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        return
