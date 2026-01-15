# OSS-Guardian 使用说明（Windows）

本文档说明单文件与 ZIP 多文件（AI）分析流程、报告解读与关键配置。当前功能以 Windows 10/11 为目标环境。

## 目录

- [环境要求](#环境要求)
- [安装与启动](#安装与启动)
- [单文件分析](#单文件分析)
- [ZIP 多文件分析（AI）](#zip-多文件分析ai)
- [报告说明](#报告说明)
- [配置说明](#配置说明)
- [常见问题](#常见问题)

## 环境要求

- Windows 10/11
- Python 3.8+
- Go（单文件/ZIP 动态分析）
- JDK（单文件/ZIP 动态分析）
- Maven（Java 依赖项目动态分析）

> 动态分析会执行被测代码，建议在隔离环境中运行。

## 安装与启动

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动 Web UI

```bash
streamlit run app.py
```

浏览器访问：

```
http://localhost:8501
```

## 单文件分析

### 支持输入

- `.py` / `.go` / `.java`
- `requirements.txt`（仅依赖/CVE 检测，不执行动态分析）

### 运行逻辑

1) 预处理：解析源码、AST、符号、IR（Python）。  
2) 静态分析：语法检查 + 规则匹配 + 污点分析 + CFG + 依赖/CVE。  
3) 动态分析：  
   - Python：hook runner（可选沙箱）  
   - Go：`go build` + 运行二进制，psutil 采样  
   - Java：`javac` + `java` 运行，psutil 采样（依赖项目需 classpath）  
4) 聚合 -> 威胁识别 -> 风险评分 -> 报告输出。  

## ZIP 多文件分析（AI）

### 使用流程

1) 上传 ZIP 文件。  
2) 选择语言过滤（可选）并勾选需要分析的文件。  
3) 点击分析，自动进入 AI 多文件流程。  

### AI 多文件逻辑

- AI 选择动态执行目标（最多 `max_dynamic_targets`）。  
- 执行动态并采样：
  - Python：hook + 可选沙箱  
  - Go：`go run .` + psutil 进程监控  
  - Java：`javac/java` + psutil 进程监控  
- 组合源码内容与动态摘要发给模型，模型输出严格 threat 结构。  
- AI 结果与规则威胁合并后统一生成报告（无独立 AI 区块）。  

### Java 依赖项目说明

`java-rootkit-master.zip` 等项目需要 Maven 拉依赖，否则会编译失败：

1) 确保 Maven 可用：`mvn -v`  
2) 配置 `config/settings.yaml`：
   - `java_dependency_mode: online`  
3) 重新分析 ZIP。  

若环境禁止 HTTP 仓库，可先手动执行：

```bash
mvn -q -DskipTests -Dmaven.wagon.http.allowInsecureProtocol=true dependency:copy-dependencies -DoutputDirectory=target/dependency
```

或将依赖 jar 放入 ZIP 的 `lib/` 目录。

## 报告说明

### 输出位置

- 默认：`data/reports/`
- 格式：JSON / HTML / Markdown

### 关键字段

- `threats`：统一威胁结构（含 `evidence`）
- `dynamic_results.execution_log`：单文件动态日志路径
- `dynamic_results.execution_logs`：ZIP 动态执行日志摘要
- `aggregated_results.static.cve_data`：CVE 匹配结果

## 配置说明

### settings.yaml

- `enable_static_analysis` / `enable_dynamic_analysis`
- `enable_sandbox`
- `timeout` / `dynamic_timeout` / `dynamic_log_mode` / `dynamic_sample_interval`
- `java_dependency_mode`：`off` | `offline` | `online`
- `java_dependency_dirs` / `java_extra_classpath`

### agent.yaml

- `enabled` / `model` / `api_key` / `base_url`
- `network_enabled`（必须开启才能调用模型）
- `max_dynamic_targets` / `select_max_tokens` / `analyze_max_tokens`
- `cache.path` / `cache.ttl_seconds`
- `prompt_select_path` / `prompt_analyze_path`

### Prompt

- `config/agent_prompt_select.txt`：动态目标选择  
- `config/agent_prompt.txt`：多文件静态/动态综合分析  

## 常见问题

### 1) 单文件 Go/Java 动态分析为 0

请确认 Go/JDK 已安装；编译/运行失败会写入 `dynamic_results.execution_log`。

### 2) Java 动态分析编译失败

多为依赖缺失。设置 `java_dependency_mode: online` 并确保 Maven 可用，或提供 jar 依赖。

### 3) Go 动态分析失败

请确认 Go 已安装，且项目根目录有 `go.mod` 或可直接 `go build`。

### 4) AI 没有返回结果

确认 `config/agent.yaml` 中 `enabled` 与 `network_enabled` 已开启，API Key 正确，且网络可达。
