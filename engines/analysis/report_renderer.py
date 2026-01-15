#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Report Renderer
Generates JSON/HTML/Markdown reports with separated static and dynamic sections.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List


def _count(items: Any) -> int:
    if isinstance(items, list):
        return len(items)
    return 0


def _md_escape(value: Any) -> str:
    if value is None:
        return ''
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def _format_file_label(file_path: str, display_name: str = None) -> str:
    if display_name:
        return display_name
    if file_path:
        return os.path.basename(file_path)
    return ''


def _build_static_summary(static_data: Dict[str, Any]) -> Dict[str, Any]:
    if not static_data:
        static_data = {}
    return {
        'pattern_matches': _count(static_data.get('pattern_matches', [])),
        'taint_flows': _count(static_data.get('taint_flows', [])),
        'cfg_structures': _count(static_data.get('cfg_structures', [])),
        'cve_matches': _count(static_data.get('cve_matches', [])),
        'syntax_valid': static_data.get('syntax_valid', True)
    }


def _build_dynamic_summary(dynamic_data: Dict[str, Any]) -> Dict[str, Any]:
    if not dynamic_data:
        dynamic_data = {}
    return {
        'syscalls': _count(dynamic_data.get('syscalls', [])),
        'network_activities': _count(dynamic_data.get('network_activities', [])),
        'file_activities': _count(dynamic_data.get('file_activities', [])),
        'memory_findings': _count(dynamic_data.get('memory_findings', [])),
        'fuzz_results': _count(dynamic_data.get('fuzz_results', []))
    }


def _static_summary_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    if not result:
        return _build_static_summary({})
    static_results = result.get('static_results', {}) or {}
    if static_results:
        return _build_static_summary(static_results)
    aggregated = result.get('aggregated_results', {}) or {}
    return _build_static_summary(aggregated.get('static', {}))


def _dynamic_summary_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    if not result:
        return _build_dynamic_summary({})
    dynamic_results = result.get('dynamic_results', {}) or {}
    if dynamic_results:
        return _build_dynamic_summary(dynamic_results)
    aggregated = result.get('aggregated_results', {}) or {}
    return _build_dynamic_summary(aggregated.get('dynamic', {}))


def _static_summary_from_aggregated(aggregated: Dict[str, Any]) -> Dict[str, Any]:
    aggregated = aggregated or {}
    return _build_static_summary(aggregated.get('static', {}))


def _dynamic_summary_from_aggregated(aggregated: Dict[str, Any]) -> Dict[str, Any]:
    aggregated = aggregated or {}
    return _build_dynamic_summary(aggregated.get('dynamic', {}))


def build_single_report_data(file_path: str, results: Dict[str, Any]) -> Dict[str, Any]:
    """Build report data for a single file analysis."""
    return {
        'file_path': file_path,
        'static_results': results.get('static_results', {}),
        'dynamic_results': results.get('dynamic_results', {}),
        'aggregated_results': results.get('aggregated_results', {}),
        'threats': results.get('threats', []),
        'risk_assessment': results.get('risk_assessment', {})
    }


def build_batch_report_data(
    batch_results: Dict[str, Any],
    file_name_map: Dict[str, str] = None
) -> Dict[str, Any]:
    """Build report data for batch analysis."""
    file_results = []
    for fr in batch_results.get('file_results', []):
        result = fr.get('result', {}) if fr.get('success') else {}
        static_results = result.get('static_results', {}) if fr.get('success') else {}
        file_path = fr.get('file_path')
        display_name = file_name_map.get(file_path) if file_name_map else None
        file_results.append({
            'file_path': file_path,
            'display_name': display_name,
            'risk_score': result.get('risk_assessment', {}).get('risk_score', 0) if fr.get('success') else 0,
            'threat_count': len(result.get('threats', [])) if fr.get('success') else 0,
            'static_summary': _static_summary_from_result(result),
            'dynamic_summary': _dynamic_summary_from_result(result),
            'cve_matches': static_results.get('cve_matches', []) or []
        })

    return {
        'analysis_type': 'batch',
        'summary': batch_results.get('summary', {}),
        'overall_risk': batch_results.get('overall_risk', {}),
        'aggregated_threats': batch_results.get('aggregated_threats', []),
        'ai_threats': batch_results.get('ai_threats', []),
        'ai_summary': batch_results.get('ai_summary', {}),
        'file_results': file_results
    }


def generate_json_report(analysis_results: Dict[str, Any]) -> str:
    """
    Generate JSON format report with separated static/dynamic summaries.
    """
    report_sections: Dict[str, Any] = {}
    analysis_type = analysis_results.get('analysis_type')

    if analysis_type == 'batch':
        file_results = analysis_results.get('file_results', [])
        static_by_file: List[Dict[str, Any]] = []
        dynamic_by_file: List[Dict[str, Any]] = []
        for fr in file_results:
            result = fr.get('result', {}) if fr.get('success') else {}
            static_summary = fr.get('static_summary') or _static_summary_from_result(result)
            dynamic_summary = fr.get('dynamic_summary') or _dynamic_summary_from_result(result)
            static_by_file.append({
                'file_path': fr.get('file_path'),
                **static_summary
            })
            dynamic_by_file.append({
                'file_path': fr.get('file_path'),
                **dynamic_summary
            })
        report_sections['static_summary_by_file'] = static_by_file
        report_sections['dynamic_summary_by_file'] = dynamic_by_file
    else:
        aggregated = analysis_results.get('aggregated_results', {}) or {}
        static_source = analysis_results.get('static_results') or aggregated.get('static', {})
        dynamic_source = analysis_results.get('dynamic_results') or aggregated.get('dynamic', {})
        report_sections['static_summary'] = _build_static_summary(static_source)
        report_sections['dynamic_summary'] = _build_dynamic_summary(dynamic_source)

    report_data = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'tool': 'OSS-Guardian',
            'version': '1.0'
        },
        'analysis_results': analysis_results,
        'report_sections': report_sections
    }

    return json.dumps(report_data, indent=2, ensure_ascii=False)


def generate_html_report(analysis_results: Dict[str, Any]) -> str:
    """
    生成 HTML 格式报告（中文版）
    """
    if analysis_results.get('analysis_type') == 'batch':
        summary = analysis_results.get('summary', {})
        overall_risk = analysis_results.get('overall_risk', {})
        file_results = analysis_results.get('file_results', [])
        threats = analysis_results.get('aggregated_threats', [])
        ai_threats = analysis_results.get('ai_threats', [])
        ai_summary = analysis_results.get('ai_summary', {})
        avg_score = overall_risk.get('average_risk_score', 0)
        avg_level = overall_risk.get('average_risk_level', overall_risk.get('risk_level', 'low'))

        level_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        avg_level_cn = level_cn.get(avg_level, avg_level)

        static_rows = []
        dynamic_rows = []
        display_name_map = {
            fr.get('file_path'): fr.get('display_name')
            for fr in file_results
            if fr.get('display_name')
        }
        for fr in file_results:
            result = fr.get('result', {}) if fr.get('success') else {}
            static_summary = fr.get('static_summary') or _static_summary_from_result(result)
            dynamic_summary = fr.get('dynamic_summary') or _dynamic_summary_from_result(result)
            file_label = _format_file_label(fr.get('file_path'), fr.get('display_name'))
            static_rows.append(
                f"<tr><td>{file_label}</td>"
                f"<td>{static_summary.get('pattern_matches', 0)}</td>"
                f"<td>{static_summary.get('taint_flows', 0)}</td>"
                f"<td>{static_summary.get('cfg_structures', 0)}</td>"
                f"<td>{static_summary.get('cve_matches', 0)}</td>"
                f"<td>{'通过' if static_summary.get('syntax_valid', True) else '失败'}</td></tr>"
            )
            dynamic_rows.append(
                f"<tr><td>{file_label}</td>"
                f"<td>{dynamic_summary.get('syscalls', 0)}</td>"
                f"<td>{dynamic_summary.get('network_activities', 0)}</td>"
                f"<td>{dynamic_summary.get('file_activities', 0)}</td>"
                f"<td>{dynamic_summary.get('memory_findings', 0)}</td>"
                f"<td>{dynamic_summary.get('fuzz_results', 0)}</td></tr>"
            )

        severity_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        threat_rows = []
        for threat in threats:
            line_numbers = threat.get('line_numbers', [])
            line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
            source_file = threat.get('source_file', '')
            file_label = _format_file_label(source_file, display_name_map.get(source_file))
            threat_rows.append(
                f"<tr><td>{file_label}</td>"
                f"<td>{threat.get('threat_type','未知')}</td>"
                f"<td>{severity_cn.get(threat.get('severity','medium'), threat.get('severity','medium'))}</td>"
                f"<td>{line_str}</td></tr>"
            )

        cve_rows = []
        for fr in file_results:
            for match in fr.get('cve_matches', []) or []:
                file_label = _format_file_label(fr.get('file_path'), fr.get('display_name'))
                cve_rows.append(
                    "<tr>"
                    f"<td>{file_label}</td>"
                    f"<td>{match.get('cve_id','N/A')}</td>"
                    f"<td>{match.get('description','')}</td>"
                    f"<td>{match.get('severity','unknown')}</td>"
                    f"<td>{match.get('fixed_version','')}</td>"
                    f"<td>{match.get('source','')}</td>"
                    f"<td><a href=\"{match.get('reference_url','')}\">{match.get('reference_url','')}</a></td>"
                    "</tr>"
                )

        cve_table = ""
        if cve_rows:
            cve_table = (
                "<h2>CVE 匹配详情</h2>"
                "<table><thead><tr>"
                "<th>文件</th><th>CVE ID</th><th>描述</th><th>严重程度</th>"
                "<th>修复版本</th><th>来源</th><th>参考链接</th>"
                "</tr></thead>"
                f"<tbody>{''.join(cve_rows)}</tbody></table>"
            )

        threat_table = ""
        if threat_rows:
            threat_table = (
                "<table><thead><tr><th>文件</th><th>威胁类型</th><th>严重程度</th><th>行号</th></tr></thead>"
                f"<tbody>{''.join(threat_rows)}</tbody></table>"
            )
        else:
            threat_table = "<p>未发现威胁。</p>"


        ai_threats = analysis_results.get('ai_threats', []) or []
        ai_summary = analysis_results.get('ai_summary', {}) or {}
        ai_rows = []
        for threat in ai_threats:
            line_numbers = threat.get('line_numbers', [])
            line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
            source_file = threat.get('source_file', '')
            file_label = _format_file_label(source_file, display_name_map.get(source_file))
            confidence = threat.get('confidence', 0.0)
            ai_rows.append(
                f"<tr><td>{file_label}</td>"
                f"<td>{threat.get('threat_type','Unknown')}</td>"
                f"<td>{severity_cn.get(threat.get('severity','medium'), threat.get('severity','medium'))}</td>"
                f"<td>{line_str}</td>"
                f"<td>{confidence:.2f}</td></tr>"
            )
        ai_table = ""
        if ai_rows:
            ai_table = (
                "<h2>AI Findings</h2>"
                "<table><thead><tr><th>File</th><th>Type</th><th>Severity</th><th>Lines</th><th>Confidence</th></tr></thead>"
                f"<tbody>{''.join(ai_rows)}</tbody></table>"
            )
        elif ai_summary.get('skipped'):
            ai_table = f"<h2>AI Findings</h2><p>AI skipped: {ai_summary.get('reason','unknown')}</p>"
        elif ai_summary.get('error'):
            ai_table = f"<h2>AI Findings</h2><p>AI error: {ai_summary.get('error')}</p>"

        return f"""<!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OSS-Guardian 批量分析报告</title>
        <style>
            body {{ font-family: "Microsoft YaHei", "SimHei", Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 18px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background: #f4f4f4; }}
        </style>
    </head>
    <body>
        <h1>OSS-Guardian 批量分析报告</h1>
        <h2>汇总</h2>
        <ul>
            <li>总文件数: {summary.get('total_files', 0)}</li>
            <li>成功: {summary.get('successful', 0)}</li>
            <li>失败: {summary.get('failed', 0)}</li>
            <li>威胁总数: {summary.get('total_threats', 0)}</li>
            <li>平均风险分数: {avg_score:.2f}/100</li>
            <li>平均风险等级: {avg_level_cn}</li>
        </ul>
        <h2>静态分析汇总</h2>
        <table>
            <thead>
                <tr>
                    <th>文件</th>
                    <th>模式匹配</th>
                    <th>污点流</th>
                    <th>CFG</th>
                    <th>CVE</th>
                    <th>语法检查</th>
                </tr>
            </thead>
            <tbody>
                {''.join(static_rows)}
            </tbody>
        </table>
        {cve_table}
        <h2>动态分析汇总</h2>
        <table>
            <thead>
                <tr>
                    <th>文件</th>
                    <th>系统调用</th>
                    <th>网络活动</th>
                    <th>文件活动</th>
                    <th>内存分析</th>
                    <th>模糊测试</th>
                </tr>
            </thead>
            <tbody>
                {''.join(dynamic_rows)}
            </tbody>
        </table>
        <h2>按文件汇总的威胁</h2>
        {threat_table}
        {ai_table}
    </body>
    </html>"""

    threats = analysis_results.get('threats', [])
    risk_assessment = analysis_results.get('risk_assessment', {})
    aggregated = analysis_results.get('aggregated_results', {}) or {}
    static_source = analysis_results.get('static_results') or aggregated.get('static', {})
    dynamic_source = analysis_results.get('dynamic_results') or aggregated.get('dynamic', {})
    static_summary = _build_static_summary(static_source)
    dynamic_summary = _build_dynamic_summary(dynamic_source)
    dynamic = dynamic_source or {}

    cve_rows = []
    for match in static_source.get('cve_matches', []) or []:
        cve_rows.append(
            "<tr>"
            f"<td>{match.get('cve_id','N/A')}</td>"
            f"<td>{match.get('description','')}</td>"
            f"<td>{match.get('severity','unknown')}</td>"
            f"<td>{match.get('fixed_version','')}</td>"
            f"<td>{match.get('source','')}</td>"
            f"<td><a href=\"{match.get('reference_url','')}\">{match.get('reference_url','')}</a></td>"
            "</tr>"
        )
    cve_table = ""
    if cve_rows:
        cve_table = (
            "<h2>CVE 匹配详情</h2>"
            "<table><thead><tr>"
            "<th>CVE ID</th><th>描述</th><th>严重程度</th>"
            "<th>修复版本</th><th>来源</th><th>参考链接</th>"
            "</tr></thead>"
            f"<tbody>{''.join(cve_rows)}</tbody></table>"
        )

    risk_score = risk_assessment.get('risk_score', 0)
    risk_level = risk_assessment.get('risk_level', 'low')
    threat_count = risk_assessment.get('threat_count', 0)

    risk_level_cn = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重'
    }

    risk_color = {
        'critical': '#E74C3C',
        'high': '#E67E22',
        'medium': '#F39C12',
        'low': '#27AE60'
    }.get(risk_level, '#6c757d')

    severity_cn = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    }

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSS-Guardian 安全分析报告</title>
    <style>
        body {{
            font-family: "Microsoft YaHei", "SimHei", Arial, sans-serif;
            margin: 20px;
            background-color: #F0F4F8;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(74, 144, 164, 0.15);
        }}
        h1 {{
            color: #2C3E50;
            border-bottom: 3px solid #4A90A4;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495E;
            margin-top: 30px;
        }}
        .risk-score {{
            text-align: center;
            padding: 30px;
            margin: 20px 0;
            background: linear-gradient(135deg, #4A90A4 0%, #6B9BD1 100%);
            color: white;
            border-radius: 8px;
            font-size: 48px;
            font-weight: bold;
            box-shadow: 0 4px 6px rgba(74, 144, 164, 0.2);
        }}
        .risk-level {{
            font-size: 24px;
            margin-top: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background-color: #F8FBFC;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4A90A4;
            box-shadow: 0 2px 4px rgba(74, 144, 164, 0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #2C3E50;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #4A90A4;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border: 1px solid #B8D4E3;
            border-radius: 6px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #B8D4E3;
        }}
        th {{
            background-color: #4A90A4;
            color: white;
        }}
        tr:hover {{
            background-color: #F0F4F8;
        }}
        .severity-critical {{
            color: #E74C3C;
            font-weight: bold;
            background-color: #FDE8E8;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-high {{
            color: #E67E22;
            font-weight: bold;
            background-color: #FDF0E8;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-medium {{
            color: #F39C12;
            background-color: #FEF5E7;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .severity-low {{
            color: #27AE60;
            background-color: #E8F8F0;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        .evidence {{
            background-color: #F8FBFC;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: "Consolas", "Monaco", monospace;
            font-size: 12px;
            border-left: 3px solid #6B9BD1;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 12px;
            margin-top: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>OSS-Guardian 安全分析报告</h1>
        
        <div class="risk-score">
            风险分数：{risk_score}/100
            <div class="risk-level">风险等级：{risk_level_cn.get(risk_level, risk_level.upper())}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>威胁总数</h3>
                <div class="value">{threat_count}</div>
            </div>
            <div class="summary-card">
                <h3>严重</h3>
                <div class="value" style="color: #E74C3C;">{risk_assessment.get('breakdown', {}).get('critical', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>高危</h3>
                <div class="value" style="color: #E67E22;">{risk_assessment.get('breakdown', {}).get('high', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>中危</h3>
                <div class="value" style="color: #F39C12;">{risk_assessment.get('breakdown', {}).get('medium', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>低危</h3>
                <div class="value" style="color: #27AE60;">{risk_assessment.get('breakdown', {}).get('low', 0)}</div>
            </div>
        </div>
        
        <h2>已识别的威胁</h2>
        <table>
            <thead>
                <tr>
                    <th>威胁类型</th>
                    <th>严重程度</th>
                    <th>描述</th>
                    <th>行号</th>
                </tr>
            </thead>
            <tbody>
"""

    for threat in threats:
        threat_type = threat.get('threat_type', '未知')
        severity = threat.get('severity', 'medium')
        description = threat.get('description', '')
        line_numbers = threat.get('line_numbers', [])
        line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
        severity_text = severity_cn.get(severity, severity.upper())

        severity_class = f'severity-{severity}'

        html += f"""
                <tr>
                    <td><strong>{threat_type}</strong></td>
                    <td class="{severity_class}">{severity_text}</td>
                    <td>{description}</td>
                    <td>{line_str}</td>
                </tr>
"""

    html += """
            </tbody>
        </table>

        <h2>静态分析结果</h2>
        <table>
            <thead>
                <tr>
                    <th>指标</th>
                    <th>数量</th>
                </tr>
            </thead>
            <tbody>
"""
    html += f"""
                <tr><td>模式匹配</td><td>{static_summary.get('pattern_matches', 0)}</td></tr>
                <tr><td>污点流</td><td>{static_summary.get('taint_flows', 0)}</td></tr>
                <tr><td>CFG 结构</td><td>{static_summary.get('cfg_structures', 0)}</td></tr>
                <tr><td>CVE 匹配</td><td>{static_summary.get('cve_matches', 0)}</td></tr>
                <tr><td>语法检查</td><td>{'通过' if static_summary.get('syntax_valid', True) else '失败'}</td></tr>
"""
    html += f"""
            </tbody>
        </table>

        {cve_table}
        <h2>动态分析结果</h2>
        <table>
            <thead>
                <tr>
                    <th>指标</th>
                    <th>数量</th>
                </tr>
            </thead>
            <tbody>
"""
    html += f"""
                <tr><td>系统调用</td><td>{dynamic_summary.get('syscalls', 0)}</td></tr>
                <tr><td>网络活动</td><td>{dynamic_summary.get('network_activities', 0)}</td></tr>
                <tr><td>文件活动</td><td>{dynamic_summary.get('file_activities', 0)}</td></tr>
                <tr><td>内存分析</td><td>{dynamic_summary.get('memory_findings', 0)}</td></tr>
                <tr><td>模糊测试</td><td>{dynamic_summary.get('fuzz_results', 0)}</td></tr>
"""
    html += """
            </tbody>
        </table>
"""

    if dynamic.get('network_activities'):
        html += "<h3>网络活动详情</h3><ul>"
        for activity in dynamic['network_activities']:
            activity_type = activity.get('type', 'unknown')
            activity_type_cn = '连接' if activity_type == 'connect' else '绑定' if activity_type == 'bind' else activity_type
            html += f"<li>{activity_type_cn}: {activity.get('target', 'N/A')}</li>"
        html += "</ul>"

    html += """
        <h2>详细证据</h2>
"""

    for i, threat in enumerate(threats, 1):
        threat_type = threat.get('threat_type', '未知')
        evidence = threat.get('evidence', [])

        html += f"""
        <h3>{i}. {threat_type}</h3>
        <div class="evidence">
"""
        for ev in evidence[:5]:
            html += f"<div>{json.dumps(ev, indent=2, ensure_ascii=False)}</div><br>"
        html += """
        </div>
"""

    html += f"""
        <div class="timestamp">
            报告生成时间：{datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""

    return html


def generate_markdown_report(analysis_results: Dict[str, Any]) -> str:
    """
    生成 Markdown 格式报告（中文版）
    """
    if analysis_results.get('analysis_type') == 'batch':
        summary = analysis_results.get('summary', {})
        overall_risk = analysis_results.get('overall_risk', {})
        file_results = analysis_results.get('file_results', [])
        threats = analysis_results.get('aggregated_threats', [])
        avg_score = overall_risk.get('average_risk_score', 0)
        avg_level = overall_risk.get('average_risk_level', overall_risk.get('risk_level', 'low'))

        level_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }
        avg_level_cn = level_cn.get(avg_level, avg_level)

        md = "# OSS-Guardian 批量分析报告\n\n"
        md += "## 汇总\n\n"
        md += f"- 总文件数: {summary.get('total_files', 0)}\n"
        md += f"- 成功: {summary.get('successful', 0)}\n"
        md += f"- 失败: {summary.get('failed', 0)}\n"
        md += f"- 威胁总数: {summary.get('total_threats', 0)}\n"
        md += f"- 平均风险分数: {avg_score:.2f}/100\n"
        md += f"- 平均风险等级: {avg_level_cn}\n\n"

        md += "## 静态分析汇总\n\n"
        display_name_map = {
            fr.get('file_path'): fr.get('display_name')
            for fr in file_results
            if fr.get('display_name')
        }
        md += "| 文件 | 模式匹配 | 污点流 | CFG | CVE | 语法检查 |\n"
        md += "|---|---:|---:|---:|---:|---|\n"
        for fr in file_results:
            result = fr.get('result', {}) if fr.get('success') else {}
            static_summary = fr.get('static_summary') or _static_summary_from_result(result)
            file_label = _format_file_label(fr.get('file_path'), fr.get('display_name'))
            md += (
                f"| {file_label} | {static_summary.get('pattern_matches', 0)} "
                f"| {static_summary.get('taint_flows', 0)} | {static_summary.get('cfg_structures', 0)} "
                f"| {static_summary.get('cve_matches', 0)} | "
                f"{'通过' if static_summary.get('syntax_valid', True) else '失败'} |\n"
            )

        cve_rows = []
        for fr in file_results:
            for match in fr.get('cve_matches', []) or []:
                url = match.get('reference_url', '')
                url_md = f"[{url}]({url})" if url else ''
                file_label = _format_file_label(fr.get('file_path'), fr.get('display_name'))
                cve_rows.append(
                    f"| {_md_escape(file_label)} | {_md_escape(match.get('cve_id','N/A'))} | "
                    f"{_md_escape(match.get('description',''))} | {_md_escape(match.get('severity','unknown'))} | "
                    f"{_md_escape(match.get('fixed_version',''))} | {_md_escape(match.get('source',''))} | {url_md} |\n"
                )

        if cve_rows:
            md += "\n## CVE 匹配详情\n"
            md += "| 文件 | CVE ID | 描述 | 严重程度 | 修复版本 | 来源 | 参考链接 |\n"
            md += "|---|---|---|---|---|---|---|\n"
            md += ''.join(cve_rows)

        md += "\n## 动态分析汇总\n\n"
        md += "| 文件 | 系统调用 | 网络活动 | 文件活动 | 内存分析 | 模糊测试 |\n"
        md += "|---|---:|---:|---:|---:|---:|\n"
        for fr in file_results:
            result = fr.get('result', {}) if fr.get('success') else {}
            dynamic_summary = fr.get('dynamic_summary') or _dynamic_summary_from_result(result)
            file_label = _format_file_label(fr.get('file_path'), fr.get('display_name'))
            md += (
                f"| {file_label} | {dynamic_summary.get('syscalls', 0)} "
                f"| {dynamic_summary.get('network_activities', 0)} | {dynamic_summary.get('file_activities', 0)} "
                f"| {dynamic_summary.get('memory_findings', 0)} | {dynamic_summary.get('fuzz_results', 0)} |\n"
            )

        md += "\n## 按文件汇总的威胁\n\n"
        if threats:
            by_file = {}
            for threat in threats:
                src = threat.get('source_file', 'unknown')
                by_file.setdefault(src, []).append(threat)
            for src, items in by_file.items():
                md += f"### {_format_file_label(src, display_name_map.get(src))}\n"
                for t in items:
                    severity = t.get('severity', 'medium')
                    severity_text = level_cn.get(severity, severity)
                    line_numbers = t.get('line_numbers', [])
                    line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
                    md += f"- {t.get('threat_type','unknown')} ({severity_text}) 行号: {line_str}\n"
                md += "\n"
        else:
            md += "未发现威胁。\n"

        md += """
        ## AI Findings

        """
        if ai_threats:
            md += "| File | Type | Severity | Lines | Confidence |\n"
            md += "|---|---|---|---|---:|\n"
            for threat in ai_threats:
                line_numbers = threat.get('line_numbers', [])
                line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'
                source_file = threat.get('source_file', '')
                file_label = _format_file_label(source_file, display_name_map.get(source_file))
                severity = threat.get('severity', 'medium')
                confidence = threat.get('confidence', 0.0)
                md += (
                    f"| {file_label} | {threat.get('threat_type','Unknown')} | "
                    f"{level_cn.get(severity, severity)} | {line_str} | {confidence:.2f} |\n"
                )
        elif ai_summary.get('skipped'):
            md += f"AI skipped: {ai_summary.get('reason','unknown')}\n"
        elif ai_summary.get('error'):
            md += f"AI error: {ai_summary.get('error')}\n"
        else:
            md += "No AI findings.\n"

        return md

    file_path = analysis_results.get('file_path', '未知文件')
    threats = analysis_results.get('threats', [])
    risk_assessment = analysis_results.get('risk_assessment', {})
    aggregated = analysis_results.get('aggregated_results', {})

    risk_score = risk_assessment.get('risk_score', 0)
    risk_level = risk_assessment.get('risk_level', 'low')
    threat_count = risk_assessment.get('threat_count', 0)

    risk_level_cn = {
        'low': '低',
        'medium': '中',
        'high': '高',
        'critical': '严重'
    }

    severity_cn = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
    }

    breakdown = risk_assessment.get('breakdown', {})
    static_source = analysis_results.get('static_results') or aggregated.get('static', {})
    dynamic_source = analysis_results.get('dynamic_results') or aggregated.get('dynamic', {})
    static_summary = _build_static_summary(static_source)
    dynamic_summary = _build_dynamic_summary(dynamic_source)
    dynamic = dynamic_source or {}

    md = f"""# OSS-Guardian 安全分析报告

## 报告信息

- **分析文件：** {file_path}
- **生成时间：** {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}
- **工具版本：** OSS-Guardian v1.0

---

## 风险评估概览

### 风险分数

**{risk_score}/100** - 风险等级：**{risk_level_cn.get(risk_level, risk_level.upper())}**

### 威胁统计

| 严重程度 | 数量 |
|---------|------|
| 严重 | {breakdown.get('critical', 0)} |
| 高危 | {breakdown.get('high', 0)} |
| 中危 | {breakdown.get('medium', 0)} |
| 低危 | {breakdown.get('low', 0)} |
| **总计** | **{threat_count}** |

---

## 已识别的威胁

"""

    if threats:
        for i, threat in enumerate(threats, 1):
            threat_type = threat.get('threat_type', '未知')
            severity = threat.get('severity', 'medium')
            severity_text = severity_cn.get(severity, severity.upper())
            description = threat.get('description', '')
            line_numbers = threat.get('line_numbers', [])
            line_str = ', '.join(map(str, line_numbers)) if line_numbers else 'N/A'

            md += f"""### {i}. {threat_type}

- **严重程度：** {severity_text}
- **描述：** {description}
- **行号：** {line_str}

"""
            evidence = threat.get('evidence', [])
            if evidence:
                md += "**证据信息：**\n\n"
                for j, ev in enumerate(evidence[:3], 1):
                    md += f"{j}. ```json\n{json.dumps(ev, indent=2, ensure_ascii=False)}\n```\n\n"
    else:
        md += "**未检测到威胁！代码相对安全。**\n\n"

    md += """---

## 静态分析结果

"""
    md += f"- **模式匹配：** {static_summary.get('pattern_matches', 0)} 项\n"
    md += f"- **污点流：** {static_summary.get('taint_flows', 0)} 条\n"
    md += f"- **CFG 结构：** {static_summary.get('cfg_structures', 0)} 个\n"
    md += f"- **CVE 匹配：** {static_summary.get('cve_matches', 0)} 项\n"
    md += f"- **语法检查：** {'通过' if static_summary.get('syntax_valid', True) else '失败'}\n\n"

    cve_rows = []
    for match in static_source.get('cve_matches', []) or []:
        url = match.get('reference_url', '')
        url_md = f"[{url}]({url})" if url else ''
        cve_rows.append(
            f"| {_md_escape(match.get('cve_id','N/A'))} | {_md_escape(match.get('description',''))} | "
            f"{_md_escape(match.get('severity','unknown'))} | {_md_escape(match.get('fixed_version',''))} | "
            f"{_md_escape(match.get('source',''))} | {url_md} |\n"
        )

    if cve_rows:
        md += "\n### CVE 匹配详情\n"
        md += "| CVE ID | 描述 | 严重程度 | 修复版本 | 来源 | 参考链接 |\n"
        md += "|---|---|---|---|---|---|\n"
        md += ''.join(cve_rows)
        md += "\n"

    md += """---

## 动态分析结果

"""
    md += f"- **系统调用：** {dynamic_summary.get('syscalls', 0)} 条\n"
    md += f"- **网络活动：** {dynamic_summary.get('network_activities', 0)} 条\n"
    md += f"- **文件活动：** {dynamic_summary.get('file_activities', 0)} 条\n"
    md += f"- **内存分析：** {dynamic_summary.get('memory_findings', 0)} 条\n"
    md += f"- **模糊测试：** {dynamic_summary.get('fuzz_results', 0)} 条\n\n"

    if dynamic.get('network_activities'):
        md += "### 网络活动详情\n\n"
        for activity in dynamic['network_activities']:
            activity_type = activity.get('type', 'unknown')
            activity_type_cn = '连接' if activity_type == 'connect' else '绑定' if activity_type == 'bind' else activity_type
            md += f"- **{activity_type_cn}** 到 {activity.get('target', 'N/A')}\n"
        md += "\n"

    md += f"""---

## 报告说明

本报告由 OSS-Guardian 安全检测系统自动生成。

**风险等级说明：**
- **0-19 分（低）**：代码相对安全，只有少量低危问题
- **20-49 分（中）**：存在中等风险，建议审查
- **50-79 分（高）**：存在高风险，需要立即处理
- **80-100 分（严重）**：存在严重安全威胁，必须修复

---

*报告生成时间：{datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}*
"""

    return md


def save_report(
    report_content: str,
    file_path: str,
    format: str = 'json'
) -> str:
    """
    保存报告到文件
    """
    report_dir = os.path.dirname(file_path)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)

    if not file_path.endswith(f'.{format}'):
        file_path = f"{file_path}.{format}"

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return file_path
