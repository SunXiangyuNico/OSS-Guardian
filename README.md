# OSS-Guardian

OSS-Guardian 是面向 Python / Go / Java 的开源代码安全分析工具。单文件走传统静态 + 动态链路；ZIP 多文件走 AI Agent 跨文件关联分析，AI 输出与单文件报告结构严格一致。

## 核心能力

- 单文件静态：语法检查、规则匹配、污点分析、CFG、依赖与 CVE 匹配
- 单文件动态：
  - Python：hook + 可选沙箱
  - Go：go build/run + psutil 进程采样
  - Java：javac/java + psutil 进程采样（依赖项目需可用 classpath）
- ZIP 多文件（AI）：AI 负责跨文件静态 + 动态分析与风险归纳
  - 动态目标由模型挑选（`config/agent_prompt_select.txt`）
  - Python 使用 hook runner；Go/Java 使用进程监控（psutil）采样
- 报告输出：JSON / HTML / Markdown（威胁列表统一结构）
- Windows 原生运行

## 支持矩阵

| 场景 | Python | Go | Java |
|---|---|---|---|
| 单文件静态 | ✅ | ✅ | ✅ |
| 单文件动态 | ✅（hook+可选沙箱） | ✅（go build/run + psutil） | ✅（javac/java + psutil，需依赖） |
| ZIP AI 静态 | ✅ | ✅ | ✅ |
| ZIP AI 动态 | ✅（hook） | ⚠（go run + psutil） | ⚠（javac/java + psutil，需依赖） |
| 依赖/CVE | ✅ | ✅ | ✅ |

> ⚠ Go/Java 动态需要对应运行时与依赖可用；失败原因会写入动态日志或 `execution_logs`。

## 分析流程

### 单文件
1. 预处理：解析源码、AST、符号表、IR（Python），Go/Java 走轻量解析。  
2. 静态：语法检查 + 规则匹配 + 污点分析 + CFG + 依赖/CVE。  
3. 动态：
   - Python：hook runner（可选沙箱）采集 syscalls/network/file/memory + fuzz  
   - Go：`go build` + 运行目标进程，psutil 采样网络/文件/内存/子进程  
   - Java：`javac` + `java` 运行目标进程，psutil 采样网络/文件/内存/子进程  
4. 聚合与威胁识别：`aggregator` -> `threat_identifier` -> `risk_assessor`。  
5. 生成报告：`report_renderer` 输出 JSON/HTML/Markdown。  

### ZIP 多文件（AI）
1. 解压与语言识别（`app.py`）。  
2. 依赖/CVE 保留（`check_dependencies` + `cve_matcher`）。  
3. AI 选择动态目标文件（`ai_agent._select_dynamic_targets`）。  
4. 执行动态：Python 用 hook；Go/Java 用 psutil 进程监控。  
5. 构建 AI 载荷：文件内容 + 动态摘要（`execution_logs` 等）。  
6. AI 输出 findings -> 映射为 threat 结构并与规则威胁合并。  
7. `report_renderer` 统一生成报告。  

## 快速开始（Windows）

1) 安装依赖

```bash
pip install -r requirements.txt
```

2) 启动 UI

```bash
streamlit run app.py
```

3) 访问：`http://localhost:8501`

## 命令行

```bash
python main_controller.py <file_path>
```

> 仅支持单文件分析，ZIP 走 Web UI。

## 配置说明

- `config/settings.yaml`
  - `enable_static_analysis` / `enable_dynamic_analysis` / `enable_sandbox`
  - `timeout` / `dynamic_timeout` / `dynamic_log_mode` / `dynamic_sample_interval`
  - `java_dependency_mode`: `off` | `offline` | `online`
  - `java_dependency_dirs` / `java_extra_classpath`
- `config/agent.yaml`
  - `model` / `api_key` / `base_url` / `timeout` / `max_retries`
  - `network_enabled` / `evidence_required`
  - `cache.path` / `cache.ttl_seconds`
  - `prompt_select_path` / `prompt_analyze_path`
- `config/rules.yaml`：静态规则
- `config/agent_prompt_select.txt` / `config/agent_prompt.txt`：AI Prompt

## 项目结构

```
OSS-Guardian/
├─ app.py                         # Streamlit UI（上传/展示/下载）
├─ main_controller.py             # 单文件与 ZIP 入口，报告生成
├─ config/
│  ├─ settings.yaml               # 系统配置
│  ├─ agent.yaml                  # AI 配置
│  ├─ rules.yaml                  # 静态规则
│  ├─ agent_prompt*.txt           # AI Prompt
├─ engines/
│  ├─ preprocessing/              # 解析/AST/语言识别
│  ├─ static/                     # 语法/规则/污点/CFG/依赖/CVE
│  ├─ dynamic/                    # Python hook/sandbox + Go/Java 动态执行
│  ├─ analysis/                   # 聚合、AI、风险评估、报告渲染
│  └─ agent/                      # OpenAI-compatible Provider
├─ data/
│  ├─ uploads/                    # 上传与解压文件
│  ├─ reports/                    # 输出报告
│  └─ agent_cache/                # AI 缓存
└─ docs/examples/                 # 可复现样例 ZIP
```

`engines/analysis/context_builder.py`, `candidate_builder.py`, `project_indexer.py`, `evidence_validator.py`, `threat_merger.py` 当前未在主流程中调用，用于后续跨文件索引/证据校验的预留实现。

## 安全提示

动态分析会执行被测代码，建议在隔离环境或虚拟机中运行。
