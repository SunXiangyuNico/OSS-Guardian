#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CVE 匹配器（增强版）
根据官方 OSV 数据库（在线）匹配依赖项，并使用本地 JSON 作为后备。
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional

# 官方 OSV API 端点
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def match_cve(dependencies: List[Dict[str, Any]],
              cve_db_path: Optional[str] = None,
              language: str = 'python') -> List[Dict[str, Any]]:
    """
    根据漏洞数据库匹配依赖项。
    优先使用在线 OSV API，如果网络失败则回退到本地 JSON。

    参数:
        dependencies: 依赖项字典列表（必须包含 'name' 和 'version'）
        cve_db_path: 本地后备 CVE 数据库路径
        language: 项目语言（'python'、'java'、'go'）用于确定生态系统

    返回:
        List[Dict]: 匹配的 CVE 列表
    """
    matches = []

    # 1. 尝试在线查询 (OSV API)
    try:
        print("[INFO] Querying official OSV database...")
        online_matches = _query_osv_api(dependencies, language)
        if online_matches:
            return online_matches
    except Exception as e:
        print(f"[WARN] Online CVE check failed: {e}. Switching to local database.")


import concurrent.futures
import requests


# ... (保持原有的导入和 match_cve 函数不变，只替换下面的 _query_osv_api)

def _query_osv_api(dependencies: List[Dict[str, Any]], language: str) -> List[Dict[str, Any]]:
    """
    从 OSV.dev API 批量查询漏洞（并发优化版）。
    """
    ecosystem_map = {
        'python': 'PyPI', 'java': 'Maven', 'go': 'Go',
        'javascript': 'npm', 'typescript': 'npm'
    }
    ecosystem = ecosystem_map.get(language.lower(), 'PyPI')

    payload = {"queries": []}
    valid_deps = []

    # 1. 构建批量查询 Payload
    for dep in dependencies:
        name = dep.get('name')
        version = dep.get('version')
        if name and version and version != 'unknown':
            payload["queries"].append({
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version
            })
            valid_deps.append(dep)

    if not payload["queries"]:
        return []

    # 2. 发送批量索引请求 (Batch Query)
    try:
        response = requests.post(OSV_QUERY_BATCH_URL, json=payload, timeout=10)
        response.raise_for_status()
        results = response.json().get("results", [])
    except Exception as e:
        print(f"[ERROR] OSV API request failed: {e}")
        return []

    # 3. 收集所有需要查询详情的唯一 ID (去重)
    # 我们先不急着生成 matches，而是先弄清楚有哪些 ID 需要查
    vuln_ids_to_fetch = set()
    for res in results:
        vulns = res.get("vulns", [])
        for vuln in vulns:
            if vuln.get("id"):
                vuln_ids_to_fetch.add(vuln.get("id"))

    # 4. 并发获取漏洞详情 (Detail Query)
    # 这是一个辅助函数，用于在线程中运行
    def fetch_vuln_detail(vid):
        try:
            r = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", timeout=10)
            if r.status_code == 200:
                return vid, r.json()
        except Exception:
            pass
        return vid, None

    vuln_details_map = {}

    # 使用线程池并发查询，max_workers=20 表示同时发20个请求
    if vuln_ids_to_fetch:
        print(f"[INFO] Fetching details for {len(vuln_ids_to_fetch)} vulnerabilities...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            # 提交所有任务
            future_to_vid = {executor.submit(fetch_vuln_detail, vid): vid for vid in vuln_ids_to_fetch}

            # 获取结果
            for future in concurrent.futures.as_completed(future_to_vid):
                vid, detail = future.result()
                if detail:
                    vuln_details_map[vid] = detail

    # 5. 组装最终结果
    matches = []

    # 再次遍历原始依赖和结果，利用刚才并发抓取的详情表来构建 Match 对象
    for dep, res in zip(valid_deps, results):
        vulns = res.get("vulns", [])
        for vuln in vulns:
            vuln_id = vuln.get("id")
            # 从缓存字典里拿详情，不再发起网络请求
            vuln_detail = vuln_details_map.get(vuln_id)

            if not vuln_detail:
                continue

            # 提取 CVE ID
            cve_id = vuln_detail.get("id")
            if "aliases" in vuln_detail:
                for alias in vuln_detail["aliases"]:
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break

            # 提取严重程度
            severity = "medium"
            if "database_specific" in vuln_detail:
                db_severity = vuln_detail["database_specific"].get("severity")
                if db_severity:
                    severity = db_severity.lower()

            matches.append({
                'dependency': dep,
                'cve_id': cve_id,
                'description': vuln_detail.get("summary") or vuln_detail.get("details", "")[:200],
                'severity': severity,
                'fixed_version': "See report",
                'source': 'OSV-Live',
                'reference_url': f"https://osv.dev/vulnerability/{vuln_detail.get('id')}"
            })

    # 筛选只保留 high 和 critical 的漏洞
    matches = _filter_high_severity_only(matches)

    return matches


def _filter_high_severity_only(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    筛选漏洞列表，只保留严重程度为 high 或 critical 的漏洞。
    没有 severity 字段的漏洞将被排除。

    Args:
        matches: 原始漏洞匹配列表

    Returns:
        List[Dict]: 筛选后的漏洞列表（只包含 high 和 critical）
    """
    filtered = []

    for match in matches:
        # 检查是否存在 severity 字段
        severity = match.get('severity')

        # 如果没有 severity 字段，直接跳过
        if not severity:
            continue

        # 只保留 high 和 critical（不区分大小写）
        severity_lower = severity.lower()
        if severity_lower in ['high', 'critical']:
            filtered.append(match)

    return filtered
