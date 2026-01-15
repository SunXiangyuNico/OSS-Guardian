#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Backward-compatible report generator shim.
"""

from .report_renderer import (
    generate_json_report,
    generate_html_report,
    generate_markdown_report,
    save_report
)

__all__ = [
    'generate_json_report',
    'generate_html_report',
    'generate_markdown_report',
    'save_report'
]
