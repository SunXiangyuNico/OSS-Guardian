#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Merge AI threats into existing threat list.
"""

from typing import Any, Dict, List


def merge_threats(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged = list(existing or [])
    seen = set()

    for threat in merged:
        key = (
            threat.get("threat_type"),
            threat.get("source_file"),
            tuple(threat.get("line_numbers") or [])
        )
        seen.add(key)

    for threat in incoming or []:
        key = (
            threat.get("threat_type"),
            threat.get("source_file"),
            tuple(threat.get("line_numbers") or [])
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(threat)

    return merged
