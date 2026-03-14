from __future__ import annotations

import ast
import html
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND_FILE = ROOT / "police_claw_v3.py"
FRONTEND_FILE = ROOT / "Police_Claw_v3_Dashboard.jsx"
OUTPUT_FILE = ROOT / "index.html"


BACKEND_DESCRIPTIONS = {
    "Collector": "采集进程、网络连接、打开文件、环境变量和 DNS，作为扫描上下文的唯一入口。",
    "TrafficMonitor": "从连接数据中提取外连数量、云端端点、模型 API 端点和 DNS 异常。",
    "FSMonitor": "按敏感路径分区检测文件访问，聚焦钱包、SSH、Cookie、证书和备份。",
    "ModelMonitor": "识别模型相关进程、Embedding/Fine-tune 行为和 Prompt 文件。",
    "SignalEngine": "把采集结果映射成 42 项安全信号，是规则层的核心。",
    "RiskEngine": "为每个检查项计算风险分、状态和置信度，并叠加安全域权重。",
    "ReportWriter": "把最终结果落成 JSON 和 DOCX 报告，并输出分域汇总。",
    "main": "串起 6 个阶段，负责控制台输出、统计汇总和报告写入。",
}

FRONTEND_DESCRIPTIONS = {
    "simulate": "生成前端演示数据，不依赖 Python 扫描结果。",
    "Bar": "渲染风险分条形图，负责颜色和分数动画。",
    "DomainCard": "按安全域展开显示检查项、状态、风险分和证据数量。",
    "PoliceClaw": "页面入口组件，驱动扫描状态、阶段文案和结果汇总展示。",
    "startScan": "组件内部的扫描状态机，按阶段推进进度条并在完成后注入模拟结果。",
}

PIPELINE_STEPS = [
    "CLI / main()",
    "Collector",
    "TrafficMonitor",
    "FSMonitor",
    "ModelMonitor",
    "SignalEngine",
    "RiskEngine",
    "ReportWriter",
]

SNIPPET_SPECS = [
    {
        "title": "主流程编排",
        "subtitle": "Python 扫描的控制入口，能直接看出阶段顺序。",
        "file": BACKEND_FILE,
        "start": 833,
        "end": 879,
    },
    {
        "title": "Signal Engine 规则层",
        "subtitle": "42 项信号在这里落地，是整个引擎的决策中心。",
        "file": BACKEND_FILE,
        "start": 469,
        "end": 581,
    },
    {
        "title": "前端扫描状态机",
        "subtitle": "React 页面通过 `startScan()` 模拟进度和结果切换。",
        "file": FRONTEND_FILE,
        "start": 174,
        "end": 203,
    },
]


@dataclass
class ModuleInfo:
    name: str
    kind: str
    file_name: str
    line: int
    description: str
    methods: list[str]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    return read_text(path).splitlines()


def count_literal_items(tree: ast.AST, name: str) -> int:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return len(ast.literal_eval(node.value))
    raise ValueError(f"Unable to resolve literal count for {name}")


def parse_python_modules(source: str) -> tuple[list[ModuleInfo], int, int]:
    tree = ast.parse(source)
    domain_count = count_literal_items(tree, "DOMAINS")
    check_count = count_literal_items(tree, "CHECK_ITEMS")
    modules: list[ModuleInfo] = []

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = [
                child.name
                for child in node.body
                if isinstance(child, ast.FunctionDef)
            ]
            modules.append(
                ModuleInfo(
                    name=node.name,
                    kind="class",
                    file_name=BACKEND_FILE.name,
                    line=node.lineno,
                    description=BACKEND_DESCRIPTIONS.get(node.name, ""),
                    methods=methods,
                )
            )
        elif isinstance(node, ast.FunctionDef):
            modules.append(
                ModuleInfo(
                    name=node.name,
                    kind="function",
                    file_name=BACKEND_FILE.name,
                    line=node.lineno,
                    description=BACKEND_DESCRIPTIONS.get(node.name, ""),
                    methods=[],
                )
            )

    return modules, domain_count, check_count


def count_js_array_entries(lines: list[str], const_name: str) -> int:
    count = 0
    in_block = False
    opener = f"const {const_name} = ["
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(opener):
            in_block = True
            continue
        if in_block and stripped == "];":
            break
        if in_block and stripped.startswith("{ id:"):
            count += 1
    return count


def parse_jsx_modules(source: str) -> tuple[list[ModuleInfo], int, int]:
    modules: list[ModuleInfo] = []
    lines = source.splitlines()
    pattern = re.compile(r"^(\s*)(?:export default )?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

    for index, line in enumerate(lines, start=1):
        match = pattern.match(line)
        if not match:
            continue
        indent = match.group(1)
        name = match.group(2)
        kind = "function"
        if name == "PoliceClaw":
            kind = "component"
        elif indent:
            kind = "handler"
        modules.append(
            ModuleInfo(
                name=name,
                kind=kind,
                file_name=FRONTEND_FILE.name,
                line=index,
                description=FRONTEND_DESCRIPTIONS.get(name, ""),
                methods=[],
            )
        )

    return (
        modules,
        count_js_array_entries(lines, "DOMAINS"),
        count_js_array_entries(lines, "CHECKS"),
    )


def slice_with_numbers(path: Path, start: int, end: int) -> str:
    lines = read_lines(path)
    end = min(end, len(lines))
    snippet = []
    for number in range(start, end + 1):
        snippet.append(f"{number:>4} | {lines[number - 1]}")
    return "\n".join(snippet)


def module_card(module: ModuleInfo, accent: str) -> str:
    methods_html = ""
    if module.methods:
        methods = "".join(f"<li>{html.escape(name)}()</li>" for name in module.methods)
        methods_html = (
            '<div class="module-list">'
            '<div class="eyebrow">Methods</div>'
            f"<ul>{methods}</ul>"
            "</div>"
        )

    return f"""
    <details class="module-card" open>
      <summary>
        <div class="module-head">
          <div>
            <span class="chip {accent}">{html.escape(module.kind)}</span>
            <h3>{html.escape(module.name)}</h3>
          </div>
          <div class="module-line">{html.escape(module.file_name)} : {module.line}</div>
        </div>
      </summary>
      <p>{html.escape(module.description)}</p>
      {methods_html}
    </details>
    """


def snippet_card(title: str, subtitle: str, file_name: str, body: str) -> str:
    return f"""
    <article class="snippet-card">
      <div class="snippet-meta">
        <span class="eyebrow">{html.escape(file_name)}</span>
        <h3>{html.escape(title)}</h3>
        <p>{html.escape(subtitle)}</p>
      </div>
      <pre><code>{html.escape(body)}</code></pre>
    </article>
    """


def render_site() -> str:
    backend_source = read_text(BACKEND_FILE)
    frontend_source = read_text(FRONTEND_FILE)
    backend_lines = backend_source.splitlines()
    frontend_lines = frontend_source.splitlines()

    backend_modules, backend_domains, backend_checks = parse_python_modules(backend_source)
    frontend_modules, frontend_domains, frontend_checks = parse_jsx_modules(frontend_source)

    backend_cards = "".join(module_card(module, "chip-teal") for module in backend_modules)
    frontend_cards = "".join(module_card(module, "chip-amber") for module in frontend_modules)

    snippet_cards = "".join(
        snippet_card(
            spec["title"],
            spec["subtitle"],
            spec["file"].name,
            slice_with_numbers(spec["file"], spec["start"], spec["end"]),
        )
        for spec in SNIPPET_SPECS
    )

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    backend_loc = len(backend_lines)
    frontend_loc = len(frontend_lines)

    pipeline_html = f"""
    <section class="panel">
      <div class="section-head">
        <span class="eyebrow">Execution Flow</span>
        <h2>核心调用链</h2>
        <p>真实执行链只存在于 Python。React 页面对这条链路做了 UI 复刻，但当前仍是本地模拟。</p>
      </div>

      <div class="flow-shell">
        <div class="flow-row">
          <div class="flow-node flow-node-strong">{html.escape(PIPELINE_STEPS[0])}</div>
          <div class="flow-arrow">→</div>
          <div class="flow-node flow-node-strong">{html.escape(PIPELINE_STEPS[1])}</div>
        </div>

        <div class="flow-branches">
          <div class="flow-branch-line"></div>
          <div class="flow-node">{html.escape(PIPELINE_STEPS[2])}</div>
          <div class="flow-node">{html.escape(PIPELINE_STEPS[3])}</div>
          <div class="flow-node">{html.escape(PIPELINE_STEPS[4])}</div>
        </div>

        <div class="flow-row">
          <div class="flow-node flow-node-wide">{html.escape(PIPELINE_STEPS[5])}</div>
          <div class="flow-arrow">→</div>
          <div class="flow-node">{html.escape(PIPELINE_STEPS[6])}</div>
          <div class="flow-arrow">→</div>
          <div class="flow-node">{html.escape(PIPELINE_STEPS[7])}</div>
        </div>
      </div>
    </section>
    """

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Xpoliceclaw Architecture</title>
  <link rel="icon" href="data:,">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --paper: #f7f3ea;
      --canvas: linear-gradient(135deg, #f7f3ea 0%, #eef5f1 45%, #f9efe5 100%);
      --panel: rgba(255, 252, 247, 0.88);
      --ink: #182026;
      --muted: #56616b;
      --line: rgba(24, 32, 38, 0.12);
      --teal: #0f766e;
      --teal-soft: rgba(15, 118, 110, 0.12);
      --amber: #b45309;
      --amber-soft: rgba(180, 83, 9, 0.12);
      --navy: #1d3557;
      --rose: #c2410c;
      --shadow: 0 18px 60px rgba(25, 35, 43, 0.12);
      --radius: 24px;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      font-family: "Space Grotesk", "Segoe UI Variable", "PingFang SC", sans-serif;
      color: var(--ink);
      background: var(--canvas);
      min-height: 100vh;
    }}

    .page {{
      width: min(1200px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 48px;
    }}

    .hero {{
      position: relative;
      overflow: hidden;
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.18), transparent 34%),
        radial-gradient(circle at top right, rgba(180, 83, 9, 0.14), transparent 32%),
        rgba(255, 252, 247, 0.8);
      border: 1px solid var(--line);
      border-radius: calc(var(--radius) + 6px);
      box-shadow: var(--shadow);
      padding: 28px;
      animation: rise 0.55s ease both;
    }}

    .hero-grid {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 20px;
      align-items: end;
    }}

    .eyebrow {{
      font-size: 12px;
      letter-spacing: 0.2em;
      text-transform: uppercase;
      color: var(--muted);
    }}

    h1, h2, h3, p {{
      margin: 0;
    }}

    h1 {{
      margin-top: 12px;
      font-size: clamp(2.2rem, 4vw, 4.2rem);
      line-height: 0.95;
      letter-spacing: -0.04em;
      max-width: 10ch;
    }}

    .hero p {{
      margin-top: 12px;
      max-width: 62ch;
      color: var(--muted);
      line-height: 1.7;
    }}

    .hero-kicker {{
      display: inline-flex;
      gap: 10px;
      align-items: center;
      padding: 8px 14px;
      background: rgba(29, 53, 87, 0.08);
      color: var(--navy);
      border-radius: 999px;
      font-size: 13px;
      margin-bottom: 8px;
    }}

    .project-note {{
      display: grid;
      gap: 12px;
    }}

    .note-card {{
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 18px;
    }}

    .note-card strong {{
      display: block;
      font-size: 15px;
      margin-bottom: 8px;
    }}

    .note-card p {{
      margin: 0;
      font-size: 14px;
    }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}

    .stat-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px 18px;
      box-shadow: 0 12px 30px rgba(25, 35, 43, 0.05);
      animation: rise 0.55s ease both;
    }}

    .stat-card:nth-child(2) {{ animation-delay: 0.06s; }}
    .stat-card:nth-child(3) {{ animation-delay: 0.12s; }}
    .stat-card:nth-child(4) {{ animation-delay: 0.18s; }}

    .stat-card strong {{
      display: block;
      font-size: 2rem;
      line-height: 1;
      margin-bottom: 6px;
    }}

    .stat-card span {{
      display: block;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}

    .grid-two {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-top: 18px;
    }}

    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 24px;
      box-shadow: var(--shadow);
      animation: rise 0.65s ease both;
    }}

    .section-head {{
      display: grid;
      gap: 8px;
      margin-bottom: 18px;
    }}

    .section-head h2 {{
      font-size: clamp(1.5rem, 2vw, 2.1rem);
      letter-spacing: -0.04em;
    }}

    .section-head p {{
      color: var(--muted);
      line-height: 1.7;
      max-width: 70ch;
    }}

    .flow-shell {{
      display: grid;
      gap: 18px;
      padding: 12px 0 4px;
    }}

    .flow-row {{
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
    }}

    .flow-branches {{
      position: relative;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      padding-top: 18px;
    }}

    .flow-branch-line {{
      position: absolute;
      top: 0;
      left: 16.66%;
      right: 16.66%;
      height: 18px;
      border-top: 1px solid rgba(24, 32, 38, 0.26);
      border-left: 1px solid rgba(24, 32, 38, 0.26);
      border-right: 1px solid rgba(24, 32, 38, 0.26);
      border-radius: 16px 16px 0 0;
      pointer-events: none;
    }}

    .flow-node {{
      padding: 14px 18px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.72);
      box-shadow: 0 8px 22px rgba(25, 35, 43, 0.05);
      min-width: 120px;
      text-align: center;
      font-size: 15px;
    }}

    .flow-node-strong {{
      background: linear-gradient(180deg, rgba(29, 53, 87, 0.1), rgba(29, 53, 87, 0.03));
      border-color: rgba(29, 53, 87, 0.18);
      font-weight: 700;
    }}

    .flow-node-wide {{
      min-width: 220px;
      font-weight: 700;
    }}

    .flow-arrow {{
      font-size: 22px;
      color: var(--muted);
      line-height: 1;
    }}

    .module-stack {{
      display: grid;
      gap: 12px;
    }}

    .module-card {{
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.74);
      overflow: hidden;
    }}

    .module-card summary {{
      list-style: none;
      cursor: pointer;
      padding: 18px;
    }}

    .module-card summary::-webkit-details-marker {{
      display: none;
    }}

    .module-head {{
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 12px;
    }}

    .module-head h3 {{
      margin-top: 10px;
      font-size: 1.3rem;
      letter-spacing: -0.03em;
    }}

    .module-line {{
      color: var(--muted);
      font-size: 13px;
      font-family: "IBM Plex Mono", monospace;
      white-space: nowrap;
      padding-top: 2px;
    }}

    .module-card p {{
      padding: 0 18px 18px;
      color: var(--muted);
      line-height: 1.7;
    }}

    .chip {{
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.16em;
    }}

    .chip-teal {{
      color: var(--teal);
      background: var(--teal-soft);
    }}

    .chip-amber {{
      color: var(--amber);
      background: var(--amber-soft);
    }}

    .module-list {{
      border-top: 1px solid var(--line);
      padding: 14px 18px 18px;
    }}

    .module-list ul {{
      margin: 10px 0 0;
      padding-left: 18px;
      color: var(--muted);
      display: grid;
      gap: 6px;
    }}

    .callout-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 18px;
    }}

    .callout {{
      border-radius: 18px;
      padding: 18px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.72);
    }}

    .callout strong {{
      display: block;
      margin-bottom: 10px;
      font-size: 1rem;
    }}

    .callout p {{
      color: var(--muted);
      line-height: 1.7;
    }}

    .snippet-grid {{
      display: grid;
      gap: 18px;
      margin-top: 18px;
    }}

    .snippet-card {{
      display: grid;
      gap: 14px;
      border-radius: 22px;
      border: 1px solid var(--line);
      padding: 20px;
      background: rgba(255, 255, 255, 0.72);
    }}

    .snippet-card h3 {{
      font-size: 1.2rem;
      letter-spacing: -0.03em;
      margin-top: 6px;
    }}

    .snippet-card p {{
      color: var(--muted);
      line-height: 1.7;
      margin-top: 8px;
    }}

    pre {{
      margin: 0;
      overflow: auto;
      padding: 18px;
      border-radius: 18px;
      background: #1d2430;
      color: #ecf3fb;
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-family: "IBM Plex Mono", monospace;
      font-size: 12px;
      line-height: 1.75;
    }}

    .footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 13px;
      text-align: center;
    }}

    @keyframes rise {{
      from {{
        opacity: 0;
        transform: translateY(18px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}

    @media (max-width: 980px) {{
      .hero-grid,
      .grid-two,
      .callout-grid {{
        grid-template-columns: 1fr;
      }}

      .stats {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
    }}

    @media (max-width: 720px) {{
      .page {{
        width: min(100vw - 20px, 100%);
        padding-top: 14px;
      }}

      .hero,
      .panel {{
        padding: 18px;
      }}

      .stats {{
        grid-template-columns: 1fr;
      }}

      .flow-branches {{
        grid-template-columns: 1fr;
        padding-top: 0;
      }}

      .flow-branch-line {{
        display: none;
      }}

      .module-head {{
        flex-direction: column;
      }}

      .module-line {{
        white-space: normal;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="hero-grid">
        <div>
          <div class="hero-kicker">Xpoliceclaw / Source-Driven Architecture View</div>
          <span class="eyebrow">Generated From Real Files</span>
          <h1>Police Claw 的源码架构站点</h1>
          <p>
            这个页面直接从仓库里的 <code>{html.escape(BACKEND_FILE.name)}</code> 和
            <code>{html.escape(FRONTEND_FILE.name)}</code> 提取结构信息，展示真实的后端执行链、
            React 组件结构，以及几个最关键的代码片段。
          </p>
        </div>

        <div class="project-note">
          <div class="note-card">
            <strong>后端是真正的扫描引擎</strong>
            <p>Python 文件包含 Collector、Monitor、Signal、Risk、Report 全链路，可独立生成 JSON 和 DOCX 报告。</p>
          </div>
          <div class="note-card">
            <strong>前端当前是展示层</strong>
            <p>React 文件通过 <code>simulate()</code> 和 <code>startScan()</code> 模拟结果，没有直接调用 Python 输出。</p>
          </div>
        </div>
      </div>
    </section>

    <section class="stats">
      <article class="stat-card">
        <strong>{backend_checks}</strong>
        <span>后端检查项数量，来自 <code>CHECK_ITEMS</code>。</span>
      </article>
      <article class="stat-card">
        <strong>{backend_domains}</strong>
        <span>安全域数量，Python 与 React 都复用了同一套概念。</span>
      </article>
      <article class="stat-card">
        <strong>{backend_loc}</strong>
        <span>{html.escape(BACKEND_FILE.name)} 的代码行数。</span>
      </article>
      <article class="stat-card">
        <strong>{frontend_loc}</strong>
        <span>{html.escape(FRONTEND_FILE.name)} 的代码行数。</span>
      </article>
    </section>

    {pipeline_html}

    <section class="grid-two">
      <article class="panel">
        <div class="section-head">
          <span class="eyebrow">Backend</span>
          <h2>Python 引擎模块</h2>
          <p>
            共提取到 {len(backend_modules)} 个顶层定义。
            其中类 {sum(1 for item in backend_modules if item.kind == "class")} 个，入口函数 1 个。
          </p>
        </div>
        <div class="module-stack">
          {backend_cards}
        </div>
      </article>

      <article class="panel">
        <div class="section-head">
          <span class="eyebrow">Frontend</span>
          <h2>React 展示层模块</h2>
          <p>
            共提取到 {len(frontend_modules)} 个函数/组件定义。
            同时识别到 {frontend_domains} 个前端安全域配置和 {frontend_checks} 个前端检查项配置。
          </p>
        </div>
        <div class="module-stack">
          {frontend_cards}
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="section-head">
        <span class="eyebrow">Architecture Notes</span>
        <h2>当前系统边界</h2>
        <p>页面除了画结构，也把现在真正存在的架构边界讲清楚，避免把演示层误判成生产链路。</p>
      </div>

      <div class="callout-grid">
        <article class="callout">
          <strong>真实执行链</strong>
          <p>命令行进入 <code>main()</code> 后，按 6 个阶段执行采集、分析、信号识别、评分和报告生成。风险结论以 Python 结果为准。</p>
        </article>
        <article class="callout">
          <strong>当前断点</strong>
          <p>React 页面没有读取 <code>Police_Claw_v3_Report.json</code>，所以页面里的风险结果属于本地模拟，不是扫描实况。</p>
        </article>
      </div>
    </section>

    <section class="panel">
      <div class="section-head">
        <span class="eyebrow">Code Highlights</span>
        <h2>关键代码片段</h2>
        <p>下面的内容不是手写摘要，而是从源码按行截取的真实片段，方便你快速核对调用链。</p>
      </div>
      <div class="snippet-grid">
        {snippet_cards}
      </div>
    </section>

    <p class="footer">
      Generated at {generated_at} · Files: {html.escape(BACKEND_FILE.name)}, {html.escape(FRONTEND_FILE.name)}
    </p>
  </main>
</body>
</html>
"""


def main() -> None:
    OUTPUT_FILE.write_text(render_site(), encoding="utf-8")
    print(f"Generated {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
