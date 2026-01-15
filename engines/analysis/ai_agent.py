#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Multi-file AI agent orchestration for cross-file analysis.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Tuple

from engines.agent.openai_provider import OpenAIProvider
from engines.analysis.cache_manager import load_cache, save_cache
from engines.preprocessing.language_detector import detect_language
from engines.dynamic.sandbox import run_in_sandbox
from engines.dynamic.network_monitor import analyze_network_activity
from engines.dynamic.file_monitor import analyze_file_activity
from engines.dynamic.memory_analyzer import analyze_memory
from engines.dynamic.fuzzer import fuzz_execution
from engines.dynamic.process_monitor import run_process_with_monitor


def _default_agent_config() -> Dict[str, Any]:
    return {
        "enabled": False,
        "provider": "openai",
        "model": "qwen-plus-latest",
        "api_key": "",
        "base_url": "https://aihubmix.com/v1",
        "timeout": 60,
        "max_retries": 5,
        "timeout_connect": 10,
        "timeout_read": 60,
        "timeout_write": 20,
        "network_enabled": False,
        "evidence_required": True,
        "max_findings": 10,
        "max_chars": 12000,
        "max_file_chars": 4000,
        "select_max_tokens": 256,
        "analyze_max_tokens": 2048,
        "max_execution_log_chars": 2000,
        "max_dynamic_targets": 3,
        "select_preview_lines": 120,
        "prompt_select_path": "config/agent_prompt_select.txt",
        "prompt_select_inline": "",
        "prompt_analyze_path": "config/agent_prompt.txt",
        "prompt_analyze_inline": "",
        "redaction": {
            "enabled": True,
            "patterns": []
        },
        "cache": {
            "enabled": True,
            "path": "data/agent_cache",
            "ttl_seconds": 86400
        }
    }


def _merge_agent_config(config: Dict[str, Any]) -> Dict[str, Any]:
    defaults = _default_agent_config()
    incoming = config.get("agent", {}) if isinstance(config, dict) else {}

    def merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(a)
        for key, value in b.items():
            if isinstance(value, dict) and isinstance(out.get(key), dict):
                out[key] = merge(out[key], value)
            else:
                out[key] = value
        return out

    return merge(defaults, incoming)


def _hash_payload(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _parse_json_response(content: str) -> Dict[str, Any]:
    if not content:
        return {}
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json", "", 1).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(cleaned[start:end + 1])
        except Exception:
            return {}
    return {}


def _load_prompt(prompt_path: str, prompt_inline: str) -> str:
    inline = (prompt_inline or "").strip()
    if inline:
        return inline
    path = (prompt_path or "").strip()
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""


def _build_messages(payload: Dict[str, Any], prompt_path: str, prompt_inline: str) -> List[Dict[str, str]]:
    system = _load_prompt(prompt_path, prompt_inline)
    if not system:
        system = (
            "You are a security analysis agent. "
            "Only use provided context snippets. "
            "Return JSON only with a top-level object containing a 'findings' array."
        )
    user = json.dumps(payload, ensure_ascii=False, indent=2)
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user}
    ]


def run_agent_analysis(
    file_paths: List[str],
    config: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    agent_cfg = _merge_agent_config(config or {})
    if not agent_cfg.get("enabled", False):
        return [], {}, {"skipped": True, "reason": "agent_disabled"}
    if not agent_cfg.get("network_enabled", False):
        return [], {}, {"skipped": True, "reason": "network_disabled"}

    api_key = agent_cfg.get("api_key") or os.getenv("AIHUBMIX_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return [], {}, {"skipped": True, "reason": "missing_api_key"}

    provider = OpenAIProvider(
        api_key=api_key,
        base_url=agent_cfg.get("base_url", ""),
        model=agent_cfg.get("model", ""),
        timeout=int(agent_cfg.get("timeout", 60)),
        max_retries=int(agent_cfg.get("max_retries", 5)),
        timeout_connect=agent_cfg.get("timeout_connect"),
        timeout_read=agent_cfg.get("timeout_read"),
        timeout_write=agent_cfg.get("timeout_write")
    )

    file_entries = _collect_files(file_paths)
    file_map = {entry["path"]: entry for entry in file_entries}
    language_groups: Dict[str, List[Dict[str, Any]]] = {}
    for entry in file_entries:
        lang = entry.get("language")
        if lang in ("python", "go", "java"):
            language_groups.setdefault(lang, []).append(entry)
    settings = (config or {}).get("settings", {})
    enable_dynamic = bool(settings.get("enable_dynamic_analysis", True))

    dynamic_summary: Dict[str, Any] = {
        "syscalls": [],
        "network_activities": [],
        "file_activities": [],
        "memory_findings": [],
        "fuzz_results": [],
        "execution_logs": []
    }

    max_targets = int(agent_cfg.get("max_dynamic_targets", 3))
    selected_targets: List[Dict[str, Any]] = []
    if enable_dynamic and language_groups and max_targets > 0:
        languages = [lang for lang in ("python", "go", "java") if lang in language_groups]
        selections: Dict[str, List[Dict[str, Any]]] = {}
        for lang in languages:
            selections[lang] = _select_dynamic_targets(
                provider=provider,
                agent_cfg=agent_cfg,
                file_entries=language_groups.get(lang, []),
                max_targets=max_targets,
                language=lang
            )

        for lang in languages:
            if len(selected_targets) >= max_targets:
                break
            if selections.get(lang):
                selected_targets.append(selections[lang][0])

        for lang in languages:
            for entry in selections.get(lang, [])[1:]:
                if len(selected_targets) >= max_targets:
                    break
                if entry not in selected_targets:
                    selected_targets.append(entry)

        if selected_targets:
            dynamic_summary = _run_dynamic_targets(selected_targets, config, agent_cfg)

    payload = _build_project_payload(
        file_entries=file_entries,
        dynamic_summary=dynamic_summary,
        agent_cfg=agent_cfg
    )

    cache_cfg = agent_cfg.get("cache", {}) or {}
    cache_enabled = bool(cache_cfg.get("enabled", False))
    cache_path = cache_cfg.get("path", "data/agent_cache")
    cache_ttl = int(cache_cfg.get("ttl_seconds", 0))

    cache_key = _hash_payload(payload)
    cached = load_cache(cache_path, cache_key, cache_ttl) if cache_enabled else None
    error_reason = ""
    if cached is not None:
        response_data = cached
    else:
        messages = _build_messages(
            payload,
            agent_cfg.get("prompt_analyze_path", ""),
            agent_cfg.get("prompt_analyze_inline", "")
        )
        analyze_max_tokens = agent_cfg.get("analyze_max_tokens")
        try:
            content = provider.chat(messages, max_tokens=analyze_max_tokens)
            response_data = _parse_json_response(content)
            if cache_enabled:
                save_cache(cache_path, cache_key, response_data)
        except Exception as exc:
            response_data = {}
            error_reason = str(exc)

    raw_findings = []
    if isinstance(response_data, dict):
        raw_findings = response_data.get("findings", [])
    elif isinstance(response_data, list):
        raw_findings = response_data

    evidence_required = bool(agent_cfg.get("evidence_required", True))
    threats = _normalize_threats(raw_findings, file_map, evidence_required)
    meta = {
        "selected_dynamic_targets": [t.get("path") for t in selected_targets],
        "files_count": len(file_entries)
    }
    if error_reason:
        meta["analysis_error"] = error_reason
    return threats, dynamic_summary, meta


def _collect_files(file_paths: List[str]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in file_paths:
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(path, "r", encoding="latin-1") as f:
                content = f.read()
        language = detect_language(path)
        entries.append({
            "path": path,
            "language": language,
            "content": content,
            "lines": content.splitlines()
        })
    return entries


def _has_entrypoint(language: str, content: str) -> bool:
    if language == "python":
        return "__name__" in content
    if language == "go":
        return "package main" in content and "func main" in content
    if language == "java":
        return re.search(r"\bstatic\s+void\s+main\s*\(", content) is not None
    return False


def _extract_key_snippets(language: str, lines: List[str], max_snippets: int = 8) -> List[str]:
    patterns = []
    if language == "python":
        patterns = [r"__name__", r"def main", r"if __name__"]
    elif language == "go":
        patterns = [r"package main", r"func main", r"import\\s*\\("]
    elif language == "java":
        patterns = [r"package\\s+", r"import\\s+", r"class\\s+", r"static\\s+void\\s+main"]

    snippets: List[str] = []
    if not patterns:
        return snippets

    for line in lines:
        if len(snippets) >= max_snippets:
            break
        for pat in patterns:
            if re.search(pat, line):
                snippet = line.strip()
                if snippet:
                    snippets.append(snippet[:200])
                break
    return snippets


def _select_dynamic_targets(
    provider: OpenAIProvider,
    agent_cfg: Dict[str, Any],
    file_entries: List[Dict[str, Any]],
    max_targets: int,
    language: str
) -> List[Dict[str, Any]]:
    if not file_entries or max_targets <= 0:
        return []

    preview_lines = int(agent_cfg.get("select_preview_lines", 120))
    files_payload = []
    for entry in file_entries:
        lines = entry.get("lines", [])
        preview = "\n".join(lines[:preview_lines])
        has_entry = _has_entrypoint(language, entry.get("content", ""))
        key_snippets = _extract_key_snippets(language, lines)
        files_payload.append({
            "path": entry.get("path"),
            "language": entry.get("language"),
            "line_count": len(lines),
            "has_entrypoint": has_entry,
            "preview": preview,
            "key_snippets": key_snippets
        })

    payload = {
        "task": "select_dynamic_targets",
        "constraints": {
            "max_targets": max_targets,
            "language": language
        },
        "files": files_payload
    }

    messages = _build_messages(
        payload,
        agent_cfg.get("prompt_select_path", ""),
        agent_cfg.get("prompt_select_inline", "")
    )
    select_max_tokens = agent_cfg.get("select_max_tokens")
    try:
        content = provider.chat(messages, max_tokens=select_max_tokens)
        response = _parse_json_response(content)
    except Exception:
        response = {}
    run_targets = response.get("run_targets", []) if isinstance(response, dict) else []
    if not isinstance(run_targets, list):
        run_targets = []

    candidates = []
    target_set = set(run_targets)
    for entry in file_entries:
        if entry.get("path") in target_set:
            candidates.append(entry)

    if candidates:
        return candidates[:max_targets]

    fallback = []
    for entry in file_entries:
        if _has_entrypoint(language, entry.get("content", "")):
            fallback.append(entry)
    if not fallback:
        fallback = file_entries[:max_targets]
    return fallback[:max_targets]


def _truncate_text(value: str, max_chars: int) -> str:
    if not value:
        return ""
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    return value[:max_chars] + " [truncated]"


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _run_command(command: List[str], cwd: str, timeout: int) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            cwd=cwd or None
        )
        return {
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "return_code": -1,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"Execution timed out after {timeout} seconds",
            "timed_out": True
        }


def _find_project_root(start_dir: str, markers: List[str]) -> str:
    current = os.path.abspath(start_dir)
    while True:
        for marker in markers:
            if os.path.exists(os.path.join(current, marker)):
                return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return os.path.abspath(start_dir)


def _find_java_project_root(file_path: str) -> str:
    start_dir = os.path.abspath(os.path.dirname(file_path))
    markers = ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew", "mvnw"]
    return _find_project_root(start_dir, markers)


def _collect_java_sources(project_root: str) -> Tuple[List[str], str]:
    source_root = ""
    candidates = [
        os.path.join(project_root, "src", "main", "java"),
        os.path.join(project_root, "src")
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            source_root = candidate
            break
    if not source_root:
        source_root = project_root

    java_files: List[str] = []
    for root, _, files in os.walk(source_root):
        for name in files:
            if name.lower().endswith(".java"):
                java_files.append(os.path.join(root, name))

    if not java_files and source_root != project_root:
        for root, _, files in os.walk(project_root):
            for name in files:
                if name.lower().endswith(".java"):
                    java_files.append(os.path.join(root, name))
    return java_files, source_root


def _collect_java_classpath(
    project_root: str,
    dependency_dirs: List[str],
    extra_classpath: Any
) -> str:
    jar_paths: List[str] = []
    for rel_dir in dependency_dirs:
        if not rel_dir:
            continue
        dir_path = os.path.join(project_root, rel_dir)
        if not os.path.isdir(dir_path):
            continue
        for root, _, files in os.walk(dir_path):
            for name in files:
                if name.lower().endswith(".jar"):
                    jar_paths.append(os.path.join(root, name))

    extra_entries: List[str] = []
    if isinstance(extra_classpath, str):
        for part in extra_classpath.split(os.pathsep):
            part = part.strip()
            if part:
                extra_entries.append(part)
    elif isinstance(extra_classpath, list):
        for item in extra_classpath:
            if item:
                extra_entries.append(str(item))

    entries: List[str] = []
    seen = set()
    for path in jar_paths + extra_entries:
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        entries.append(path)
    return os.pathsep.join(entries)


def _format_javac_arg(value: str) -> str:
    if not value:
        return ""
    if any(ch.isspace() for ch in value) or "(" in value or ")" in value:
        return f"\"{value}\""
    return value


def _write_javac_argfile(
    out_dir: str,
    classpath: str,
    java_files: List[str]
) -> str:
    arg_lines: List[str] = [
        "-encoding",
        "UTF-8",
        "-d",
        _format_javac_arg(out_dir)
    ]
    if classpath:
        arg_lines.extend(["-cp", _format_javac_arg(classpath)])
    for path in java_files:
        arg_lines.append(_format_javac_arg(path))

    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
        suffix=".args",
        prefix="oss_guardian_javac_"
    )
    try:
        handle.write("\n".join(arg_lines))
    finally:
        handle.close()
    return handle.name


def _maybe_prepare_java_dependencies(
    project_root: str,
    settings: Dict[str, Any],
    timeout: int
) -> Dict[str, Any]:
    mode = str(settings.get("java_dependency_mode", "off")).lower()
    if mode in ("false", "0", "none"):
        mode = "off"
    if mode not in ("offline", "online", "off"):
        mode = "off"
    pom_path = os.path.join(project_root, "pom.xml")
    if mode == "off":
        return {"status": "skipped", "reason": "dependency_mode_off"}
    if not os.path.exists(pom_path):
        return {"status": "skipped", "reason": "pom_not_found"}
    if not _command_exists("mvn"):
        return {"status": "skipped", "reason": "maven_not_found"}

    cmd = ["mvn"]
    if mode == "offline":
        cmd.append("-o")
    cmd += ["-q", "-DskipTests", "dependency:copy-dependencies", "-DoutputDirectory=target/dependency"]
    result = _run_command(cmd, project_root, timeout)
    result["command"] = " ".join(cmd)
    result["cwd"] = project_root
    if result.get("return_code", -1) == 0:
        result["status"] = "dependencies_copied"
    else:
        result["status"] = "dependency_failed"
        if not result.get("stderr"):
            result["stderr"] = result.get("stdout", "")
    return result


def _detect_java_main_class(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return ""
    if re.search(r"\bstatic\s+void\s+main\s*\(", content) is None:
        return ""
    package_match = re.search(r"^\s*package\s+([A-Za-z0-9_\.]+)\s*;", content, re.MULTILINE)
    class_name = os.path.splitext(os.path.basename(file_path))[0]
    if package_match:
        return f"{package_match.group(1)}.{class_name}"
    return class_name


def _run_go_target(file_path: str, timeout: int) -> Dict[str, Any]:
    if not _command_exists("go"):
        return {"status": "skipped", "reason": "go_not_found"}
    file_path = os.path.abspath(file_path)
    work_dir = os.path.abspath(os.path.dirname(file_path))
    command = ["go", "run", "."]
    result = run_process_with_monitor(command, work_dir, timeout)
    result["command"] = " ".join(command)
    result["cwd"] = work_dir
    result["status"] = "ran"
    return result


def _run_java_target(file_path: str, timeout: int, settings: Dict[str, Any]) -> Dict[str, Any]:
    if not _command_exists("javac") or not _command_exists("java"):
        return {"status": "skipped", "reason": "java_not_found"}
    file_path = os.path.abspath(file_path)
    project_root = _find_java_project_root(file_path)
    work_dir = project_root
    main_class = _detect_java_main_class(file_path)
    if not main_class:
        return {"status": "skipped", "reason": "no_main_class"}

    java_files, _source_root = _collect_java_sources(project_root)
    if not java_files:
        java_files = [file_path]

    dep_timeout = max(timeout, 30)
    compile_timeout = max(timeout, 10)
    dep_result = _maybe_prepare_java_dependencies(project_root, settings, dep_timeout)
    dep_error = ""
    if dep_result.get("status") == "dependency_failed":
        dep_error = _truncate_text(
            dep_result.get("stderr") or dep_result.get("stdout") or "dependency_copy_failed",
            2000
        )

    dependency_dirs = settings.get(
        "java_dependency_dirs",
        ["lib", "libs", "target/dependency", "build/libs", "build/deps"]
    )
    if isinstance(dependency_dirs, str):
        dependency_dirs = [item.strip() for item in dependency_dirs.split(",") if item.strip()]
    classpath = _collect_java_classpath(project_root, dependency_dirs, settings.get("java_extra_classpath"))

    out_dir = tempfile.mkdtemp(prefix="oss_guardian_java_")
    arg_file = ""
    try:
        arg_file = _write_javac_argfile(out_dir, classpath, java_files)
        compile_cmd = ["javac", f"@{arg_file}"]
        compile_result = _run_command(compile_cmd, work_dir, compile_timeout)
        if compile_result.get("return_code", -1) != 0:
            compile_result["command"] = " ".join(compile_cmd)
            compile_result["cwd"] = work_dir
            compile_result["status"] = "compile_failed"
            reason = compile_result.get("stderr") or compile_result.get("stdout") or ""
            if dep_error:
                reason = f"{reason}\ndependency_resolution_failed: {dep_error}" if reason else dep_error
            if reason:
                compile_result["reason"] = reason
            return compile_result

        run_classpath = out_dir if not classpath else f"{out_dir}{os.pathsep}{classpath}"
        run_cmd = ["java", "-cp", run_classpath, main_class]
        run_result = run_process_with_monitor(run_cmd, work_dir, timeout)
        run_result["command"] = " ".join(run_cmd)
        run_result["cwd"] = work_dir
        run_result["status"] = "ran"
        return run_result
    finally:
        if arg_file:
            try:
                os.remove(arg_file)
            except Exception:
                pass
        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except Exception:
            pass


def _run_dynamic_targets(
    file_entries: List[Dict[str, Any]],
    config: Dict[str, Any],
    agent_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    settings = (config or {}).get("settings", {})
    dynamic_timeout = int(settings.get("dynamic_timeout", 2))
    dynamic_log_mode = settings.get("dynamic_log_mode", "queue")
    max_log_chars = int(agent_cfg.get("max_execution_log_chars", 2000))

    syscalls: List[str] = []
    network_activities: List[Any] = []
    file_activities: List[Any] = []
    memory_findings: List[Any] = []
    fuzz_results: List[Any] = []
    execution_logs: List[Dict[str, Any]] = []

    def append_execution_log(file_path: str, language: str, result: Dict[str, Any]) -> None:
        execution_logs.append({
            "source_file": file_path,
            "language": language,
            "command": result.get("command", ""),
            "cwd": result.get("cwd", ""),
            "status": result.get("status", "ran"),
            "reason": result.get("reason", ""),
            "return_code": result.get("return_code", -1),
            "timed_out": result.get("timed_out", False),
            "stdout": _truncate_text(result.get("stdout", ""), max_log_chars),
            "stderr": _truncate_text(result.get("stderr", ""), max_log_chars),
            "log_file": result.get("log_file", "")
        })

    for entry in file_entries:
        file_path = entry.get("path")
        language = entry.get("language", "")
        if not file_path:
            continue

        if language == "python":
            sandbox_result = run_in_sandbox(
                file_path=file_path,
                args=[],
                timeout=dynamic_timeout,
                log_mode=dynamic_log_mode
            )

            log_entries = sandbox_result.get("log_entries", [])
            if log_entries:
                net = analyze_network_activity(log_entries)
                file_act = analyze_file_activity(log_entries)
                mem = analyze_memory(log_source=log_entries)
            elif sandbox_result.get("log_file"):
                net = analyze_network_activity(sandbox_result.get("log_file"))
                file_act = analyze_file_activity(sandbox_result.get("log_file"))
                mem = analyze_memory(log_source=sandbox_result.get("log_file"))
            else:
                net = []
                file_act = []
                mem = []

            for item in net:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                network_activities.append(item)
            for item in file_act:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                file_activities.append(item)
            for item in mem:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                memory_findings.append(item)

            fuzz = fuzz_execution(
                file_path=file_path,
                num_tests=3,
                timeout=min(dynamic_timeout, 2),
                use_sandbox=True,
                log_mode=dynamic_log_mode
            )
            for item in fuzz:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                fuzz_results.append(item)

            if sandbox_result.get("log_entries"):
                for log_entry in sandbox_result.get("log_entries"):
                    if '[ALERT] SYSCALL:' in log_entry or '[ALERT] NETWORK:' in log_entry:
                        syscalls.append(f"{file_path}: {log_entry.strip()}")

            sandbox_result["command"] = f"python {os.path.basename(file_path)}"
            sandbox_result["cwd"] = os.path.dirname(file_path)
            sandbox_result.setdefault("status", "ran")
            append_execution_log(file_path, language, sandbox_result)
            continue

        if language == "go":
            go_result = _run_go_target(file_path, dynamic_timeout)
            for entry in go_result.get("syscalls", []) or []:
                syscalls.append(f"{file_path}: {entry}")
            for item in go_result.get("network_activities", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                network_activities.append(item)
            for item in go_result.get("file_activities", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                file_activities.append(item)
            for item in go_result.get("memory_findings", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                memory_findings.append(item)
            if go_result.get("monitor_error"):
                go_result["reason"] = go_result.get("monitor_error")
            append_execution_log(file_path, language, go_result)
            continue

        if language == "java":
            java_result = _run_java_target(file_path, dynamic_timeout, settings)
            for entry in java_result.get("syscalls", []) or []:
                syscalls.append(f"{file_path}: {entry}")
            for item in java_result.get("network_activities", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                network_activities.append(item)
            for item in java_result.get("file_activities", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                file_activities.append(item)
            for item in java_result.get("memory_findings", []) or []:
                if isinstance(item, dict):
                    item.setdefault("source_file", file_path)
                memory_findings.append(item)
            if java_result.get("monitor_error"):
                java_result["reason"] = java_result.get("monitor_error")
            append_execution_log(file_path, language, java_result)
            continue

    return {
        "syscalls": syscalls,
        "network_activities": network_activities,
        "file_activities": file_activities,
        "memory_findings": memory_findings,
        "fuzz_results": fuzz_results,
        "execution_log": "",
        "execution_logs": execution_logs
    }


def _build_project_payload(
    file_entries: List[Dict[str, Any]],
    dynamic_summary: Dict[str, Any],
    agent_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    max_chars = int(agent_cfg.get("max_chars", 12000))
    max_file_chars = int(agent_cfg.get("max_file_chars", 4000))

    files_payload = []
    total_chars = 0
    for entry in file_entries:
        content = entry.get("content", "")
        truncated = False
        if max_file_chars and len(content) > max_file_chars:
            content = content[:max_file_chars]
            truncated = True
        payload_entry = {
            "path": entry.get("path"),
            "language": entry.get("language"),
            "content": content,
            "truncated": truncated
        }
        serialized = json.dumps(payload_entry, ensure_ascii=False)
        if max_chars and (total_chars + len(serialized)) > max_chars:
            continue
        files_payload.append(payload_entry)
        total_chars += len(serialized)

    return {
        "task": "analyze_project",
        "project": {
            "files_count": len(file_entries)
        },
        "files": files_payload,
        "dynamic_summary": dynamic_summary,
        "constraints": {
            "evidence_required": bool(agent_cfg.get("evidence_required", True)),
            "max_findings": int(agent_cfg.get("max_findings", 10)),
            "output_language": "zh-CN"
        }
    }


def _normalize_threats(
    raw_findings: List[Dict[str, Any]],
    file_map: Dict[str, Dict[str, Any]],
    evidence_required: bool
) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        threat_type = (item.get("threat_type") or "Unknown").strip()
        severity = (item.get("severity") or "medium").lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        description = (item.get("description") or "").strip()

        line_numbers = []
        for val in item.get("line_numbers", []) or []:
            try:
                line_numbers.append(int(val))
            except Exception:
                continue

        evidence = item.get("evidence", []) or []
        cleaned_evidence = []
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            file_path = ev.get("file")
            line = ev.get("line")
            snippet = ev.get("snippet", "")
            if file_path not in file_map:
                continue
            try:
                line = int(line)
            except Exception:
                continue
            lines = file_map[file_path].get("lines", [])
            if line <= 0 or line > len(lines):
                continue
            if not snippet:
                snippet = lines[line - 1].strip()
            cleaned_evidence.append({
                "file": file_path,
                "line": line,
                "snippet": snippet
            })
            if line not in line_numbers:
                line_numbers.append(line)

        if evidence_required and not cleaned_evidence:
            continue

        if not line_numbers:
            continue

        normalized.append({
            "threat_type": threat_type,
            "severity": severity,
            "description": description,
            "line_numbers": sorted(set(line_numbers)),
            "evidence": cleaned_evidence
        })

    return normalized
