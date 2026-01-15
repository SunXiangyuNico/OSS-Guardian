#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Main Controller
Orchestrates the complete security analysis workflow.
"""

import os
import yaml
from typing import Dict, Any, Optional

# Preprocessing imports
from engines.preprocessing.parser import read_file
from engines.preprocessing.ast_builder import build_ast
from engines.preprocessing.symbol_table import extract_symbols
from engines.preprocessing.ir_generator import generate as generate_ir
from engines.preprocessing.language_detector import detect_language, is_supported_language

# Go language imports
from engines.preprocessing.go_ast_builder import build_ast as build_go_ast
from engines.static.go_syntax_checker import check_syntax as check_go_syntax
from engines.static.go_taint_analysis import analyze as go_taint_analyze
from engines.static.go_cfg_analysis import analyze as go_cfg_analyze

# Java language imports
from engines.preprocessing.java_ast_builder import build_ast as build_java_ast
from engines.static.java_syntax_checker import check_syntax as check_java_syntax
from engines.static.java_taint_analysis import analyze as java_taint_analyze
from engines.static.java_cfg_analysis import analyze as java_cfg_analyze

# Static analysis imports
from engines.static.syntax_checker import check_syntax
from engines.static.pattern_matcher import (
    match_patterns,
    load_rules_from_yaml,
    filter_rules_by_language
)
from engines.static.taint_analysis import analyze as taint_analyze
from engines.static.cfg_analysis import analyze as cfg_analyze

# Dynamic analysis imports
from engines.dynamic.sandbox import run_in_sandbox, run_direct
from engines.dynamic.network_monitor import analyze_network_activity
from engines.dynamic.fuzzer import fuzz_execution
from engines.dynamic.file_monitor import analyze_file_activity
from engines.dynamic.memory_analyzer import analyze_memory
from engines.dynamic.go_dynamic_runner import run_go_dynamic
from engines.dynamic.java_dynamic_runner import run_java_dynamic

# Analysis imports
from engines.analysis.aggregator import aggregate_results
from engines.analysis.threat_identifier import identify_threats
from engines.analysis.risk_assessor import assess_risk, assess_risk_from_counts
from engines.analysis.report_renderer import (
    build_single_report_data,
    generate_json_report,
    generate_html_report,
    generate_markdown_report,
    save_report
)
from engines.analysis.ai_agent import run_agent_analysis

# Dependency checking imports
from engines.static.dependency_checker import check_dependencies
from engines.static.cve_matcher import match_cve


def load_config(config_dir: str = 'config') -> Dict[str, Any]:
    """
    Load configuration from YAML files.
    
    Args:
        config_dir: Directory containing config files
        
    Returns:
        dict: Configuration dictionary
    """
    config = {}
    
    # Load settings
    settings_path = os.path.join(config_dir, 'settings.yaml')
    if os.path.exists(settings_path):
        with open(settings_path, 'r', encoding='utf-8') as f:
            config['settings'] = yaml.safe_load(f)
    else:
        config['settings'] = {
            'timeout': 30,
            'log_path': 'data/logs/',
            'report_path': 'data/reports/',
            'enable_dynamic_analysis': True,
            'enable_static_analysis': True,
            'enable_sandbox': True,
            'dynamic_timeout': 2,
            'dynamic_log_mode': 'queue',
            'parallel_analysis': True,
            'parallel_workers': None
        }
    
    # Load rules
    rules_path = os.path.join(config_dir, 'rules.yaml')
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            config['rules'] = yaml.safe_load(f)
    else:
        config['rules'] = {'rules': []}

    # Load agent config
    agent_path = os.path.join(config_dir, 'agent.yaml')
    if os.path.exists(agent_path):
        with open(agent_path, 'r', encoding='utf-8') as f:
            agent_data = yaml.safe_load(f) or {}
            config['agent'] = agent_data.get('agent', {})
    else:
        config['agent'] = {
            'enabled': False,
            'provider': 'openai',
            'model': 'qwen-plus-latest',
            'api_key': '',
            'base_url': 'https://aihubmix.com/v1',
            'timeout': 60,
            'max_retries': 5,
            'timeout_connect': 10,
            'timeout_read': 60,
            'timeout_write': 20,
            'network_enabled': False,
            'evidence_required': True,
            'max_findings': 10,
            'max_candidates': 24,
            'max_candidates_per_call': 6,
            'max_snippets': 24,
            'max_snippet_lines': 6,
            'max_chars': 12000,
            'max_file_chars': 4000,
            'select_max_tokens': 256,
            'analyze_max_tokens': 2048,
            'max_execution_log_chars': 2000,
            'max_dynamic_targets': 3,
            'select_preview_lines': 120,
            'prompt_select_path': 'config/agent_prompt_select.txt',
            'prompt_select_inline': '',
            'prompt_analyze_path': 'config/agent_prompt.txt',
            'prompt_analyze_inline': '',
            'redaction': {
                'enabled': True,
                'patterns': []
            },
            'cache': {
                'enabled': True,
                'path': 'data/agent_cache',
                'ttl_seconds': 86400
            }
        }
    
    return config


def analyze_file(
    file_path: str,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Perform complete security analysis on a source code file.
    Supports Python, Go, and Java languages.
    
    Args:
        file_path: Path to target source file
        config: Optional configuration dictionary. If None, loads from config files.
        
    Returns:
        dict: Complete analysis results containing:
            - 'file_path': str
            - 'language': str - Detected language
            - 'static_results': dict
            - 'dynamic_results': dict
            - 'aggregated_results': dict
            - 'threats': list
            - 'risk_assessment': dict
            - 'reports': dict (JSON and HTML report paths)
    """
    if config is None:
        config = load_config()
    
    def is_effectively_empty(path: str) -> bool:
        """Return True if file has no code (only whitespace/comments)."""
        try:
            if os.path.getsize(path) == 0:
                return True
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith(('#', '//', '/*', '*', '*/')):
                        continue
                    return False
            return True
        except Exception:
            return False
    
    # Skip empty / comment-only files quickly
    if is_effectively_empty(file_path):
        print(f"[INFO] Skipping empty/comment-only file: {file_path}")
        return {
            'file_path': file_path,
            'language': 'unknown',
            'static_results': {},
            'dynamic_results': {},
            'aggregated_results': {},
            'threats': [],
            'risk_assessment': {},
            'reports': {},
            'skipped': True,
            'reason': 'empty or comment-only file'
        }
    
    settings = config.get('settings', {})
    rules_data = config.get('rules', {})
    
    enable_static = settings.get('enable_static_analysis', True)
    enable_dynamic = settings.get('enable_dynamic_analysis', True)
    enable_sandbox = settings.get('enable_sandbox', True)
    timeout = settings.get('timeout', 30)
    dynamic_timeout = min(settings.get('dynamic_timeout', 2), timeout)
    dynamic_log_mode = settings.get('dynamic_log_mode', 'queue')
    dynamic_sample_interval = settings.get('dynamic_sample_interval', 0.1)
    
    # Detect language (requirements.txt is treated as Python dependency-only input)
    dependency_only = os.path.basename(file_path).lower() == 'requirements.txt'
    if dependency_only:
        language = 'python'
    else:
        language = detect_language(file_path)
        if not is_supported_language(language):
            raise ValueError(f"Unsupported language: {language}. Supported languages: Python, Go, Java")
    
    results = {
        'file_path': file_path,
        'language': language,
        'static_results': {},
        'dynamic_results': {},
        'aggregated_results': {},
        'threats': [],
        'risk_assessment': {},
        'reports': {}
    }
    
    try:
        # Step 1: Preprocessing
        print(f"[INFO] Reading file: {file_path}")
        print(f"[INFO] Detected language: {language}")
        source_code = ""
        ast_tree = None
        symbols = {}
        ir = []
        syntax_result = {'valid': True, 'errors': []}
        if not dependency_only:
            source_code = read_file(file_path)
            
            # Language-specific preprocessing
            if language == 'python':
                print("[INFO] Building AST...")
                ast_tree = build_ast(source_code, filename=file_path)
                
                print("[INFO] Extracting symbols...")
                symbols = extract_symbols(ast_tree)
                
                print("[INFO] Generating IR...")
                ir = generate_ir(ast_tree)
            elif language == 'go':
                print("[INFO] Building Go AST...")
                ast_tree = build_go_ast(file_path)
                symbols = ast_tree.get('functions', []) + ast_tree.get('variables', [])
                ir = []  # Go IR generation can be added later
            elif language == 'java':
                print("[INFO] Building Java AST...")
                ast_tree = build_java_ast(file_path)
                symbols = ast_tree.get('classes', []) + ast_tree.get('methods', []) + ast_tree.get('variables', [])
                ir = []  # Java IR generation can be added later
            else:
                raise ValueError(f"Unsupported language: {language}")
        
        # Step 2: Static Analysis
        if enable_static:
            print("[INFO] Performing static analysis...")
            
            # Language-specific static analysis
            if language == 'python':
                if dependency_only:
                    dependencies = check_dependencies(file_path, language)
                    cve_matches = match_cve(dependencies, language=language) if dependencies else []
                    results['static_results'] = {
                        'pattern_matches': [],
                        'taint_flows': [],
                        'cfg_structures': [],
                        'syntax_valid': True,
                        'syntax_errors': [],
                        'symbols': {},
                        'ir': [],
                        'dependencies': dependencies,
                        'cve_matches': cve_matches
                    }
                else:
                    # Syntax check
                    syntax_result = check_syntax(source_code, filename=file_path)
                    
                    # Pattern matching
                    rules = load_rules_from_yaml(rules_data)
                    rules = filter_rules_by_language(rules, language)
                    pattern_matches = match_patterns(source_code, rules)
                    
                    # Taint analysis
                    taint_flows = taint_analyze(ast_tree)
                    
                    # CFG analysis
                    cfg_structures = cfg_analyze(ast_tree)
                    
                    # Dependency checking
                    dependencies = check_dependencies(file_path, language)
                    cve_matches = match_cve(dependencies, language=language) if dependencies else []
                    
                    results['static_results'] = {
                        'pattern_matches': pattern_matches,
                        'taint_flows': taint_flows,
                        'cfg_structures': cfg_structures,
                        'syntax_valid': syntax_result['valid'],
                        'syntax_errors': syntax_result.get('errors', []),
                        'symbols': symbols,
                        'ir': ir,
                        'dependencies': dependencies,
                        'cve_matches': cve_matches
                    }
            elif language == 'go':
                # Go syntax check
                syntax_result = check_go_syntax(file_path)
                
                # Pattern matching (use same rules, filter by language if needed)
                rules = load_rules_from_yaml(rules_data)
                go_rules = filter_rules_by_language(rules, language)
                pattern_matches = match_patterns(source_code, go_rules)
                
                # Go taint analysis
                taint_flows = go_taint_analyze(file_path)

                # Merge taint flows into pattern matches for threat identification
                pattern_matches.extend(taint_flows)
                
                # CFG analysis for Go (heuristic)
                cfg_structures = go_cfg_analyze(source_code)
                
                # Dependency checking
                dependencies = check_dependencies(file_path, language)
                cve_matches = match_cve(dependencies, language=language) if dependencies else []
                
                results['static_results'] = {
                    'pattern_matches': pattern_matches,
                    'taint_flows': taint_flows,
                    'cfg_structures': cfg_structures,
                    'syntax_valid': syntax_result['valid'],
                    'syntax_errors': syntax_result.get('errors', []),
                    'symbols': symbols,
                    'ir': ir,
                    'dependencies': dependencies,
                    'cve_matches': cve_matches
                }
            elif language == 'java':
                # Java syntax check
                syntax_result = check_java_syntax(file_path)
                
                # Pattern matching
                rules = load_rules_from_yaml(rules_data)
                java_rules = filter_rules_by_language(rules, language)
                pattern_matches = match_patterns(source_code, java_rules)
                
                # Java taint analysis
                taint_flows = java_taint_analyze(file_path)

                # Merge taint flows into pattern matches for threat identification
                pattern_matches.extend(taint_flows)
                
                # CFG analysis for Java (heuristic)
                cfg_structures = java_cfg_analyze(source_code)
                
                # Dependency checking
                dependencies = check_dependencies(file_path, language)
                cve_matches = match_cve(dependencies, language=language) if dependencies else []
                
                results['static_results'] = {
                    'pattern_matches': pattern_matches,
                    'taint_flows': taint_flows,
                    'cfg_structures': cfg_structures,
                    'syntax_valid': syntax_result['valid'],
                    'syntax_errors': syntax_result.get('errors', []),
                    'symbols': symbols,
                    'ir': ir,
                    'dependencies': dependencies,
                    'cve_matches': cve_matches
                }
        else:
            results['static_results'] = {
                'pattern_matches': [],
                'taint_flows': [],
                'cfg_structures': [],
                'syntax_valid': True,
                'symbols': {},
                'ir': []
            }
        
        # Step 3: Dynamic Analysis
        # Note: Dynamic analysis currently only supports Python
        # Go and Java dynamic analysis would require different approaches
        if enable_dynamic and not dependency_only:
            print("[INFO] Performing dynamic analysis...")

            if language == 'python':
                # Run with hook runner; isolation is optional
                sandbox_result = run_in_sandbox(
                    file_path=file_path,
                    args=[],
                    timeout=dynamic_timeout,
                    log_mode=dynamic_log_mode
                )

                # Analyze network activity
                network_activities = []
                log_entries = sandbox_result.get('log_entries', [])
                if log_entries:
                    network_activities = analyze_network_activity(log_entries)
                elif sandbox_result.get('log_file'):
                    network_activities = analyze_network_activity(sandbox_result['log_file'])

                # Analyze file activity and memory signals
                file_activities = []
                memory_findings = []
                if log_entries:
                    file_activities = analyze_file_activity(log_entries)
                    memory_findings = analyze_memory(log_source=log_entries)
                elif sandbox_result.get('log_file'):
                    file_activities = analyze_file_activity(sandbox_result['log_file'])
                    memory_findings = analyze_memory(log_source=sandbox_result['log_file'])

                # Fuzz testing
                fuzz_results = fuzz_execution(
                    file_path=file_path,
                    num_tests=3,
                    timeout=min(dynamic_timeout, 2),
                    use_sandbox=True,
                    log_mode=dynamic_log_mode
                )

                # Extract syscalls from log
                syscalls = []
                if sandbox_result.get('log_entries'):
                    for entry in sandbox_result['log_entries']:
                        if '[ALERT] SYSCALL:' in entry or '[ALERT] NETWORK:' in entry:
                            syscalls.append(entry.strip())

                results['dynamic_results'] = {
                    'syscalls': syscalls,
                    'network_activities': network_activities,
                    'file_activities': file_activities,
                    'memory_findings': memory_findings,
                    'fuzz_results': fuzz_results,
                    'execution_log': sandbox_result.get('log_file', ''),
                    'sandbox_result': sandbox_result
                }
                if not enable_sandbox:
                    results['dynamic_results']['note'] = 'Sandbox disabled; hooks enabled without isolation.'
            elif language == 'go':
                results['dynamic_results'] = run_go_dynamic(
                    file_path=file_path,
                    args=[],
                    timeout=dynamic_timeout,
                    sample_interval=dynamic_sample_interval
                )
            elif language == 'java':
                results['dynamic_results'] = run_java_dynamic(
                    file_path=file_path,
                    args=[],
                    timeout=dynamic_timeout,
                    sample_interval=dynamic_sample_interval,
                    dependency_dirs=settings.get('java_dependency_dirs'),
                    extra_classpath=settings.get('java_extra_classpath')
                )
            else:
                results['dynamic_results'] = {
                    'syscalls': [],
                    'network_activities': [],
                    'file_activities': [],
                    'memory_findings': [],
                    'fuzz_results': [],
                    'execution_log': '',
                    'note': f'Dynamic analysis not implemented for {language}'
                }
        else:
            results['dynamic_results'] = {
                'syscalls': [],
                'network_activities': [],
                'file_activities': [],
                'memory_findings': [],
                'fuzz_results': [],
                'execution_log': ''
            }
        
        # Step 4: Result Analysis
        print("[INFO] Aggregating results...")
        aggregated = aggregate_results(
            results['static_results'],
            results['dynamic_results']
        )
        results['aggregated_results'] = aggregated
        
        print("[INFO] Identifying threats...")
        threats = identify_threats(aggregated)
        results['threats'] = threats
        
        print("[INFO] Assessing risk...")
        risk_assessment = assess_risk(threats)
        results['risk_assessment'] = risk_assessment
        
        # Step 5: Generate Reports
        print("[INFO] Generating reports...")
        report_data = build_single_report_data(file_path, results)
        
        # Generate JSON report
        json_report = generate_json_report(report_data)
        report_dir = settings.get('report_path', 'data/reports/')
        os.makedirs(report_dir, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        json_path = os.path.join(report_dir, f"{base_name}_{timestamp}.json")
        json_path = save_report(json_report, json_path, 'json')
        results['reports']['json'] = json_path
        
        # Generate HTML report
        html_report = generate_html_report(report_data)
        html_path = os.path.join(report_dir, f"{base_name}_{timestamp}.html")
        html_path = save_report(html_report, html_path, 'html')
        results['reports']['html'] = html_path
        
        # Generate Markdown report
        markdown_report = generate_markdown_report(report_data)
        markdown_path = os.path.join(report_dir, f"{base_name}_{timestamp}.md")
        markdown_path = save_report(markdown_report, markdown_path, 'markdown')
        results['reports']['markdown'] = markdown_path
        
        print(f"[SUCCESS] Analysis complete. Risk score: {risk_assessment['risk_score']}/100")
        
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        results['error'] = str(e)
    
    return results




def analyze_multiple_files(
    file_paths: list,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Project-level analysis for ZIP inputs (AI-driven static + dynamic)."""
    if config is None:
        config = load_config()

    if not file_paths:
        return {
            'file_path': '',
            'language': 'unknown',
            'static_results': {},
            'dynamic_results': {},
            'aggregated_results': {},
            'threats': [],
            'risk_assessment': {},
            'reports': {},
            'error': 'no files provided'
        }

    try:
        common_root = os.path.commonpath(file_paths)
        project_label = os.path.basename(common_root) or common_root
    except Exception:
        project_label = 'zip_project'

    dependencies = []
    cve_matches = []
    languages = {}
    for path in file_paths:
        lang = detect_language(path)
        languages.setdefault(lang, []).append(path)
    for lang, paths in languages.items():
        if lang not in ('python', 'go', 'java'):
            continue
        try:
            deps = check_dependencies(paths[0], lang)
            if deps:
                dependencies.extend(deps)
                cve_matches.extend(match_cve(deps, language=lang) or [])
        except Exception:
            continue

    ai_threats, dynamic_results, _ = run_agent_analysis(file_paths, config)

    static_results = {
        'pattern_matches': [],
        'taint_flows': [],
        'cfg_structures': [],
        'syntax_valid': True,
        'syntax_errors': [],
        'symbols': {},
        'ir': [],
        'dependencies': dependencies,
        'cve_matches': cve_matches
    }

    aggregated_results = aggregate_results(static_results, dynamic_results)

    # Merge rule-based dynamic threats with AI findings for reporting.
    rule_threats = identify_threats(aggregated_results)

    def merge_threats(existing, incoming):
        merged = list(existing or [])
        seen = set()
        for threat in merged:
            key = (
                threat.get('threat_type'),
                threat.get('severity'),
                threat.get('description'),
                tuple(threat.get('line_numbers') or []),
                tuple(
                    (ev.get('file'), ev.get('line')) for ev in (threat.get('evidence') or [])
                    if isinstance(ev, dict)
                )
            )
            seen.add(key)
        for threat in incoming or []:
            key = (
                threat.get('threat_type'),
                threat.get('severity'),
                threat.get('description'),
                tuple(threat.get('line_numbers') or []),
                tuple(
                    (ev.get('file'), ev.get('line')) for ev in (threat.get('evidence') or [])
                    if isinstance(ev, dict)
                )
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(threat)
        return merged

    threats = merge_threats(rule_threats, ai_threats)

    summary = aggregated_results.get('summary', {}) or {}
    ai_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for threat in ai_threats or []:
        sev = (threat.get('severity') or 'medium').lower()
        if sev not in ai_breakdown:
            sev = 'medium'
        ai_breakdown[sev] += 1

    combined_breakdown = {
        'critical': int(summary.get('critical_count', 0)) + ai_breakdown['critical'],
        'high': int(summary.get('high_count', 0)) + ai_breakdown['high'],
        'medium': int(summary.get('medium_count', 0)) + ai_breakdown['medium'],
        'low': int(summary.get('low_count', 0)) + ai_breakdown['low']
    }
    risk_assessment = assess_risk_from_counts(combined_breakdown)

    results = {
        'file_path': project_label,
        'language': 'mixed' if len(languages) > 1 else next(iter(languages.keys()), 'unknown'),
        'static_results': static_results,
        'dynamic_results': dynamic_results,
        'aggregated_results': aggregated_results,
        'threats': threats,
        'risk_assessment': risk_assessment,
        'reports': {}
    }

    report_data = build_single_report_data(project_label, results)
    report_dir = config.get('settings', {}).get('report_path', 'data/reports/')
    os.makedirs(report_dir, exist_ok=True)
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(project_label) or "zip_project"

    json_report = generate_json_report(report_data)
    json_path = os.path.join(report_dir, f"{base_name}_{timestamp}.json")
    results['reports']['json'] = save_report(json_report, json_path, 'json')

    html_report = generate_html_report(report_data)
    html_path = os.path.join(report_dir, f"{base_name}_{timestamp}.html")
    results['reports']['html'] = save_report(html_report, html_path, 'html')

    markdown_report = generate_markdown_report(report_data)
    markdown_path = os.path.join(report_dir, f"{base_name}_{timestamp}.md")
    results['reports']['markdown'] = save_report(markdown_report, markdown_path, 'markdown')

    return results

if __name__ == '__main__':
    # Example usage
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        results = analyze_file(file_path)
        print(f"\nRisk Score: {results['risk_assessment']['risk_score']}/100")
        print(f"Threats Found: {len(results['threats'])}")
    else:
        print("Usage: python main_controller.py <file_path>")
