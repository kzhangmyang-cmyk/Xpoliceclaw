const STAGES = [
  { key: "queued", zh: "排队中", en: "Queued" },
  { key: "collect", zh: "收集系统数据", en: "Collecting system data" },
  { key: "traffic", zh: "分析网络流量", en: "Analyzing network traffic" },
  { key: "fs", zh: "扫描文件系统痕迹", en: "Scanning filesystem footprint" },
  { key: "model", zh: "检查模型活动", en: "Inspecting model activity" },
  { key: "signal", zh: "评估风险信号", en: "Scoring detected signals" },
  { key: "report", zh: "生成报告", en: "Publishing reports" },
  { key: "completed", zh: "已完成", en: "Completed" },
];

const JOB_STATUS_LABELS = {
  queued: { zh: "排队中", en: "Queued" },
  running: { zh: "运行中", en: "Running" },
  completed: { zh: "已完成", en: "Completed" },
  failed: { zh: "失败", en: "Failed" },
};

const TASK_STATUS_LABELS = {
  pending: { zh: "待执行", en: "Pending" },
  running: { zh: "执行中", en: "Running" },
  success: { zh: "成功", en: "Success" },
  failed: { zh: "失败", en: "Failed" },
  partial: { zh: "部分完成", en: "Partial" },
};

const RISK_LEVEL_LABELS = {
  critical: { zh: "严重", en: "Critical" },
  high: { zh: "高", en: "High" },
  medium: { zh: "中", en: "Medium" },
  low: { zh: "低", en: "Low" },
};

const STEP_STATUS_LABELS = {
  pending: { zh: "待执行", en: "Pending" },
  running: { zh: "执行中", en: "Running" },
  completed: { zh: "已完成", en: "Completed" },
  failed: { zh: "失败", en: "Failed" },
  success: { zh: "成功", en: "Success" },
  unknown: { zh: "未知", en: "Unknown" },
};

const LOG_LEVEL_LABELS = {
  info: { zh: "信息", en: "Info" },
  warn: { zh: "警告", en: "Warn" },
  warning: { zh: "警告", en: "Warn" },
  error: { zh: "错误", en: "Error" },
};

const SUPPORT_LEVEL_LABELS = {
  full: { zh: "高优先级", en: "Urgent" },
  cleanup: { zh: "可清理", en: "Cleanup" },
  terminate_only: { zh: "仅遏制", en: "Contain" },
  blocked: { zh: "受限", en: "Blocked" },
};

const UNINSTALL_STEP_LABELS = {
  "Identifying target footprint": { zh: "识别目标足迹", en: "Identifying target footprint" },
  "Terminating active processes": { zh: "终止活动进程", en: "Terminating active processes" },
  "Removing persistence entries": { zh: "移除持久化项", en: "Removing persistence entries" },
  "Cleaning config and cache": { zh: "清理配置与缓存", en: "Cleaning config and cache" },
  "Removing core files": { zh: "移除核心文件", en: "Removing core files" },
  "Verifying leftovers": { zh: "验证残留", en: "Verifying leftovers" },
  "Finalizing removal record": { zh: "完成处置记录", en: "Finalizing removal record" },
};

const PLANNED_ACTION_LABELS = {
  "Terminate active processes": { zh: "终止活动进程", en: "Terminate active processes" },
  "Remove user persistence entries": { zh: "移除用户级持久化项", en: "Remove user persistence entries" },
  "Remove config footprint": { zh: "移除配置痕迹", en: "Remove config footprint" },
  "Remove cache footprint": { zh: "移除缓存痕迹", en: "Remove cache footprint" },
  "Remove explicit binary files": { zh: "移除明确识别出的程序文件", en: "Remove explicit binary files" },
  "Preserve binary path for manual review": { zh: "保留程序路径，待人工复核", en: "Preserve binary path for manual review" },
  "Contain runtime process only": { zh: "仅遏制运行中进程", en: "Contain runtime process only" },
  "Escalate to manual review": { zh: "升级为人工复核", en: "Escalate to manual review" },
};

const STARTUP_KIND_LABELS = {
  registry_run: { zh: "注册表启动项", en: "Registry Run entry" },
  scheduled_task: { zh: "计划任务", en: "Scheduled task" },
  launch_agent: { zh: "LaunchAgent", en: "LaunchAgent" },
  systemd_user_service: { zh: "用户级 systemd 服务", en: "User systemd service" },
  autostart_desktop: { zh: "自启动项", en: "Autostart entry" },
  startup: { zh: "启动项", en: "Startup entry" },
};

const RESULT_ITEM_TYPE_LABELS = {
  process: { zh: "进程", en: "Process" },
  startup: { zh: "启动项", en: "Startup entry" },
  config: { zh: "配置", en: "Config" },
  cache: { zh: "缓存", en: "Cache" },
  binary: { zh: "程序文件", en: "Binary" },
  path: { zh: "路径", en: "Path" },
  file: { zh: "文件", en: "File" },
  directory: { zh: "目录", en: "Directory" },
};

const TARGET_TYPE_LABELS = {
  process: { zh: "进程", en: "Process" },
  cli: { zh: "CLI 工具", en: "CLI tool" },
  cli_agent: { zh: "CLI 代理", en: "CLI agent" },
  tool: { zh: "工具", en: "Tool" },
  agent: { zh: "代理", en: "Agent" },
  python_agent: { zh: "Python 代理", en: "Python agent" },
  node_agent: { zh: "Node 代理", en: "Node agent" },
  script: { zh: "脚本", en: "Script" },
  binary: { zh: "程序", en: "Binary" },
  service: { zh: "服务", en: "Service" },
};

const BLOCK_REASON_LABELS = {
  insufficient_evidence: { zh: "证据不足", en: "Insufficient evidence" },
  path_too_broad: { zh: "路径范围过宽", en: "Path too broad" },
  user_data_overlap: { zh: "与用户数据重叠", en: "User data overlap" },
  binary_not_safe_to_remove: { zh: "程序路径不适合自动删除", en: "Binary not safe to remove" },
  process_only_detection: { zh: "仅发现进程迹象", en: "Process-only detection" },
};

const DOMAIN_TRANSLATIONS = {
  credential: { zh: "凭证与身份安全", en: "Credential & Identity Security" },
  transaction: { zh: "交易与金融安全", en: "Transaction & Financial Security" },
  behavior: { zh: "用户行为追踪", en: "User Behavior Tracking" },
  system: { zh: "系统权限与控制", en: "System Privilege & Control" },
  data: { zh: "数据采集与外泄", en: "Data Collection & Exfiltration" },
  model: { zh: "模型与 AI 上下文", en: "Model & AI Context" },
  audit: { zh: "审计与合规", en: "Audit & Compliance" },
};

const CHECK_TRANSLATIONS = {
  cred_password: {
    zhTitle: "抓取账户密码",
    enTitle: "Credential Password Access",
    zhDescription: "检测进程是否访问密码存储 / keychain / 浏览器密码数据库",
    enDescription: "Detect processes accessing password stores, keychains, or browser password databases.",
  },
  cred_ssh_keys: {
    zhTitle: "读取 SSH 密钥",
    enTitle: "SSH Key Access",
    zhDescription: "检测对 ~/.ssh/id_rsa、id_ed25519 等私钥文件的访问",
    enDescription: "Detect access to ~/.ssh/id_rsa, id_ed25519, and other private key files.",
  },
  cred_api_tokens: {
    zhTitle: "窃取 API Token",
    enTitle: "API Token Theft",
    zhDescription: "检测环境变量和配置文件中 API 密钥的暴露与读取",
    enDescription: "Detect exposure and reads of API keys in environment variables and config files.",
  },
  cred_cookies: {
    zhTitle: "抓取浏览器 Cookie",
    enTitle: "Browser Cookie Harvesting",
    zhDescription: "检测对 Chrome/Firefox/Safari cookie 数据库的访问",
    enDescription: "Detect access to Chrome, Firefox, or Safari cookie databases.",
  },
  cred_wallet: {
    zhTitle: "读取加密钱包",
    enTitle: "Crypto Wallet Access",
    zhDescription: "检测对 wallet.dat / MetaMask vault / 助记词文件的访问",
    enDescription: "Detect access to wallet.dat, MetaMask vaults, or seed phrase files.",
  },
  cred_2fa: {
    zhTitle: "窃取 2FA 凭证",
    enTitle: "2FA Secret Theft",
    zhDescription: "检测对 TOTP 种子、Authenticator 数据库的访问",
    enDescription: "Detect access to TOTP seeds or authenticator databases.",
  },
  cred_cert: {
    zhTitle: "读取证书与私钥",
    enTitle: "Certificate & Private Key Access",
    zhDescription: "检测对 .pem / .p12 / .pfx / TLS 私钥文件的访问",
    enDescription: "Detect access to .pem, .p12, .pfx, and TLS private key files.",
  },
  txn_unauthorized: {
    zhTitle: "未授权进行交易",
    enTitle: "Unauthorized Transactions",
    zhDescription: "监控未授权的金融交易进程或到交易所的网络连接",
    enDescription: "Monitor unauthorized financial transaction processes or exchange-bound network connections.",
  },
  txn_crypto: {
    zhTitle: "加密货币自动交易",
    enTitle: "Automated Crypto Trading",
    zhDescription: "检测与 DEX / CEX API 的未授权交互",
    enDescription: "Detect unauthorized interaction with DEX or CEX APIs.",
  },
  txn_payment: {
    zhTitle: "篡改支付信息",
    enTitle: "Payment Tampering",
    zhDescription: "检测对支付网关请求的劫持或中间人行为",
    enDescription: "Detect hijacking or man-in-the-middle behavior against payment gateway requests.",
  },
  txn_mining: {
    zhTitle: "挖矿行为",
    enTitle: "Cryptomining Activity",
    zhDescription: "检测 xmrig / cpuminer 等挖矿进程及矿池连接",
    enDescription: "Detect xmrig, cpuminer, and other mining processes or pool connections.",
  },
  beh_search: {
    zhTitle: "抓取搜索行为",
    enTitle: "Search History Harvesting",
    zhDescription: "检测浏览器历史 / 搜索日志 / 自动补全数据的异常读取",
    enDescription: "Detect unusual reads of browser history, search logs, or autocomplete data.",
  },
  beh_code: {
    zhTitle: "追踪代码编写",
    enTitle: "Code Activity Tracking",
    zhDescription: "监控 .git / IDE 工作区 / 代码仓库的异常扫描",
    enDescription: "Monitor unusual scanning of .git, IDE workspaces, or source repositories.",
  },
  beh_debug: {
    zhTitle: "追踪调试行为",
    enTitle: "Debug Behavior Tracking",
    zhDescription: "检测 gdb / lldb / strace / pdb 等调试工具的异常调用",
    enDescription: "Detect unusual calls to gdb, lldb, strace, pdb, and other debugging tools.",
  },
  beh_keylog: {
    zhTitle: "键盘记录",
    enTitle: "Keystroke Logging",
    zhDescription: "检测键盘输入捕获进程 / 输入法监控 / IME 注入",
    enDescription: "Detect keyboard capture processes, input method monitoring, or IME injection.",
  },
  beh_screen: {
    zhTitle: "屏幕截图与录制",
    enTitle: "Screen Capture & Recording",
    zhDescription: "检测屏幕捕获 / 截图进程 / 远程桌面未授权共享",
    enDescription: "Detect screen capture, screenshot processes, or unauthorized remote desktop sharing.",
  },
  beh_clipboard: {
    zhTitle: "剪贴板监控",
    enTitle: "Clipboard Monitoring",
    zhDescription: "检测剪贴板内容持续读取或劫持，尤其是加密地址替换",
    enDescription: "Detect continuous clipboard reads or hijacking, especially crypto address replacement.",
  },
  beh_operation_log: {
    zhTitle: "操作记录抓取",
    enTitle: "Operation Log Harvesting",
    zhDescription: "检测用户操作轨迹的异常采集与外传",
    enDescription: "Detect unusual collection and exfiltration of user activity trails.",
  },
  sys_root: {
    zhTitle: "root/SYSTEM 权限运行",
    enTitle: "root/SYSTEM Privilege Execution",
    zhDescription: "检查 AI 进程是否以最高权限运行",
    enDescription: "Check whether AI processes are running with the highest privileges.",
  },
  sys_persistence: {
    zhTitle: "持久化驻留",
    enTitle: "Persistence Registration",
    zhDescription: "检测 crontab / 启动项 / systemd service 的异常注册",
    enDescription: "Detect unusual crontab, startup item, or systemd service registration.",
  },
  sys_process_inject: {
    zhTitle: "进程注入",
    enTitle: "Process Injection",
    zhDescription: "检测 DLL 注入 / ptrace attach / LD_PRELOAD 劫持",
    enDescription: "Detect DLL injection, ptrace attach, or LD_PRELOAD hijacking.",
  },
  sys_driver: {
    zhTitle: "内核模块/驱动加载",
    enTitle: "Kernel Module / Driver Loading",
    zhDescription: "检测未授权的内核模块或驱动程序加载",
    enDescription: "Detect unauthorized kernel module or driver loading.",
  },
  sys_firewall: {
    zhTitle: "防火墙规则篡改",
    enTitle: "Firewall Rule Tampering",
    zhDescription: "检测 iptables / Windows Firewall 规则的异常修改",
    enDescription: "Detect abnormal changes to iptables or Windows Firewall rules.",
  },
  sys_dns: {
    zhTitle: "DNS 劫持",
    enTitle: "DNS Hijacking",
    zhDescription: "检测 DNS 配置篡改 / hosts 文件修改 / 异常 DNS 服务器",
    enDescription: "Detect DNS configuration tampering, hosts file edits, or suspicious DNS servers.",
  },
  data_file_read: {
    zhTitle: "读取私人文件",
    enTitle: "Private File Access",
    zhDescription: "检测对 Documents / Photos / Downloads 的异常批量访问",
    enDescription: "Detect unusual bulk access to Documents, Photos, or Downloads.",
  },
  data_file_content: {
    zhTitle: "抓取文件内容",
    enTitle: "File Content Extraction",
    zhDescription: "检测文件索引 / OCR / 文本提取 / PDF 解析进程",
    enDescription: "Detect file indexing, OCR, text extraction, or PDF parsing processes.",
  },
  data_cloud_upload: {
    zhTitle: "上传云端文件",
    enTitle: "Cloud Upload Activity",
    zhDescription: "监控云同步进程和 rclone / s3 cp / gsutil 等上传命令",
    enDescription: "Monitor cloud sync processes and upload commands such as rclone, s3 cp, or gsutil.",
  },
  data_idle_exfil: {
    zhTitle: "待机偷跑数据",
    enTitle: "Idle-Time Data Exfiltration",
    zhDescription: "检测休眠进程的隐蔽网络外传行为",
    enDescription: "Detect stealthy outbound transfer behavior from background or idle processes.",
  },
  data_stream: {
    zhTitle: "平台可见全部数据流",
    enTitle: "Platform-Wide Data Streams",
    zhDescription: "监控大规模外传连接 / 遥测 / 分析进程",
    enDescription: "Monitor large outbound streams, telemetry, or analytics processes.",
  },
  data_dns_tunnel: {
    zhTitle: "DNS 隧道外泄",
    enTitle: "DNS Tunnel Exfiltration",
    zhDescription: "检测通过 DNS TXT/CNAME 记录进行的数据编码外传",
    enDescription: "Detect encoded exfiltration through DNS TXT or CNAME records.",
  },
  data_steganography: {
    zhTitle: "隐写术数据外泄",
    enTitle: "Steganographic Exfiltration",
    zhDescription: "检测图片 / 音频文件中嵌入隐藏数据的外传行为",
    enDescription: "Detect exfiltration by embedding hidden data in image or audio files.",
  },
  data_usb: {
    zhTitle: "USB/外接设备数据拷贝",
    enTitle: "USB / External Device Copy",
    zhDescription: "检测向 USB 设备或外接存储的异常大规模数据传输",
    enDescription: "Detect unusual large-scale transfers to USB devices or external storage.",
  },
  data_backup_exfil: {
    zhTitle: "备份文件外泄",
    enTitle: "Backup Data Exfiltration",
    zhDescription: "检测对系统备份 / Time Machine / 快照文件的异常访问",
    enDescription: "Detect unusual access to system backups, Time Machine archives, or snapshot files.",
  },
  model_context: {
    zhTitle: "数据进入模型上下文",
    enTitle: "Sensitive Data in Model Context",
    zhDescription: "检测 LLM / RAG 管道是否将敏感数据纳入推理上下文",
    enDescription: "Detect whether LLM or RAG pipelines place sensitive data into inference context.",
  },
  model_prompt: {
    zhTitle: "Prompt 抓取",
    enTitle: "Prompt Harvesting",
    zhDescription: "检测 Prompt 缓存 / system prompt / 对话历史的异常读取",
    enDescription: "Detect unusual reads of prompt caches, system prompts, or chat history.",
  },
  model_finetune: {
    zhTitle: "用户数据用于微调",
    enTitle: "User Data Used for Fine-Tuning",
    zhDescription: "检测本地数据是否被用于模型 fine-tune / LoRA 训练",
    enDescription: "Detect whether local data is being used for model fine-tuning or LoRA training.",
  },
  model_embedding: {
    zhTitle: "敏感数据向量化",
    enTitle: "Sensitive Data Vectorization",
    zhDescription: "检测私人文档被 embedding 化存入向量数据库",
    enDescription: "Detect private documents being embedded and stored in a vector database.",
  },
  model_api_leak: {
    zhTitle: "模型 API 调用泄露数据",
    enTitle: "Sensitive Data in Model API Calls",
    zhDescription: "检测向外部模型 API 发送的请求中是否包含敏感信息",
    enDescription: "Detect whether outbound model API requests contain sensitive information.",
  },
  audit_system: {
    zhTitle: "安全审计体系",
    enTitle: "Security Audit Coverage",
    zhDescription: "验证 auditd / SIEM / 安全日志系统是否正常运行",
    enDescription: "Validate whether auditd, SIEM, or security logging systems are operating correctly.",
  },
  audit_log_tamper: {
    zhTitle: "审计日志篡改",
    enTitle: "Audit Log Tampering",
    zhDescription: "检测安全日志的异常删除 / 截断 / 权限变更",
    enDescription: "Detect unusual deletion, truncation, or permission changes on security logs.",
  },
  audit_compliance: {
    zhTitle: "合规性缺失",
    enTitle: "Compliance Gap",
    zhDescription: "检查 GDPR / CCPA / 个人信息保护法等合规措施是否到位",
    enDescription: "Check whether GDPR, CCPA, PIPL, and similar compliance controls are in place.",
  },
  audit_leak_risk: {
    zhTitle: "综合数据泄露风险",
    enTitle: "Composite Data Leakage Risk",
    zhDescription: "多类目同时触发时的复合风险评估",
    enDescription: "Evaluate compound leakage risk when multiple categories trigger at the same time.",
  },
};

const LANGUAGE_STORAGE_KEY = "policeClawLocale";
const SUPPORTED_LANGUAGES = new Set(["zh", "en"]);
const STATIC_TRANSLATIONS = {
  zh: {
    "brand.subtitle": "企业安全控制台",
    "topbar.kicker": "企业安全控制台",
    "topbar.subtitle": "面向 AI agents、skills、scripts 与本地执行风险的安全工作台",
    "topbar.stateLabel": "当前状态",
    "topbar.lastScanLabel": "最近扫描",
    "topbar.modeDemo": "演示数据",
    "language.label": "语言",
    "topbar.download": "下载 Windows 客户端",
    "topbar.architecture": "查看架构",
    "nav.eyebrow": "导航",
    "nav.title": "控制台",
    "nav.dashboard": "Dashboard",
    "nav.findings": "Findings",
    "nav.targets": "Targets",
    "nav.history": "History",
    "nav.scopeEyebrow": "边界",
    "nav.scopeBody": "聚焦 AI agents、skills、scripts 与本地执行风险，不扩展为通用系统防护界面。",
    "hero.eyebrow": "处置工作台",
    "hero.title": "在一个工作台里完成检测、解释、卸载和复核。",
    "hero.description": "工作台保留了原始扫描与证据分析流程，并补上了真实卸载链路：识别可处置目标、查看处置范围、发起后台卸载，并在同一页完成残留复核。",
    "hero.download": "下载 Windows 客户端",
    "hero.downloadMeta": "桌面客户端发布后，会在这里显示下载入口。",
    "hero.highlight.scan.tag": "扫描",
    "hero.highlight.scan.title": "真实 Flask 后台任务",
    "hero.highlight.response.tag": "处置",
    "hero.highlight.response.title": "证据联动的卸载流程",
    "hero.highlight.audit.tag": "审计",
    "hero.highlight.audit.title": "JSON、DOCX、任务日志与残留",
    "section.summary.eyebrow": "管理摘要",
    "section.summary.title": "执行概览",
    "summary.meta.host": "主机",
    "summary.meta.system": "系统",
    "summary.meta.scanId": "扫描 ID",
    "summary.meta.finishedAt": "完成时间",
    "recommendation.eyebrow": "下一步动作",
    "recommendation.title": "Recommended Remediation",
    "recommendation.targets.title": "高风险目标",
    "progress.eyebrow": "扫描生命周期",
    "progress.title": "执行进度",
    "domains.eyebrow": "安全域概览",
    "domains.title": "安全域",
    "findings.eyebrow": "发现项",
    "findings.title": "发现工作台",
    "findings.searchPlaceholder": "搜索检查项、域、描述或 ID",
    "findings.head.check": "发现项 / 目标",
    "findings.head.domain": "类型 / 安全域",
    "findings.head.status": "状态",
    "findings.head.risk": "风险",
    "findings.head.confidence": "置信度",
    "findings.head.evidence": "证据",
    "findings.head.action": "操作",
    "ops.eyebrow": "操作",
    "ops.title": "操作中心",
    "ops.currentState": "当前状态",
    "ops.scanLabel": "扫描",
    "ops.timeLabel": "时间",
    "ops.removableTargets": "可处置目标",
    "ops.lastUninstall": "最近卸载",
    "download.eyebrow": "下载",
    "download.title": "Windows 客户端",
    "download.channel": "发布通道",
    "runtime.eyebrow": "运行时",
    "runtime.title": "运行时上下文",
    "about.eyebrow": "说明",
    "about.title": "安全说明",
    "history.scan.eyebrow": "扫描历史",
    "history.scan.title": "最近扫描",
    "uninstall.progress.eyebrow": "卸载进度",
    "uninstall.progress.title": "处置编排器",
    "evidence.eyebrow": "证据检查器",
    "evidence.title": "证据检查器",
    "result.eyebrow": "处置结果",
    "result.title": "残留复核",
    "history.uninstall.eyebrow": "卸载历史",
    "history.uninstall.title": "最近处置",
    "modal.eyebrow": "卸载确认",
    "modal.title": "确认处置范围",
    "modal.target": "目标",
    "modal.safety": "安全提醒",
    "modal.safetyTitle": "卸载可能会影响此工具继续运行。",
    "modal.safetyBody": "如果执行器为了保护路径而保留部分内容，可能仍需要人工复核残留。",
    "modal.scope": "计划范围",
    "modal.mode": "模式",
    "modal.toggle.startup": "清理启动项和持久化项",
    "modal.toggle.cache": "清理缓存目录",
    "modal.toggle.config": "清理配置目录",
    "modal.toggle.binary": "删除明确识别出的程序文件",
    "modal.confirm": "输入 UNINSTALL CONFIRMED 后继续",
    "modal.confirmPlaceholder": "UNINSTALL CONFIRMED",
    "modal.cancel": "取消",
    "modal.submit": "确认卸载",
  },
  en: {
    "brand.subtitle": "Enterprise Security Console",
    "topbar.kicker": "Enterprise Security Console",
    "topbar.subtitle": "Local security workbench for AI agents, risky skills, scripts, and local execution risks",
    "topbar.stateLabel": "System State",
    "topbar.lastScanLabel": "Last Scan",
    "topbar.modeDemo": "Demo Data",
    "language.label": "Language",
    "topbar.download": "Download Windows Client",
    "topbar.architecture": "View Architecture",
    "nav.eyebrow": "Navigation",
    "nav.title": "Control Surface",
    "nav.dashboard": "Dashboard",
    "nav.findings": "Findings",
    "nav.targets": "Targets",
    "nav.history": "History",
    "nav.scopeEyebrow": "Scope",
    "nav.scopeBody": "Focused on AI agents, skills, scripts, and local execution risks rather than general system protection.",
    "hero.eyebrow": "Operational Reporting",
    "hero.title": "Detect, explain, remove, and verify in one workbench.",
    "hero.description": "The workbench keeps the original scan and evidence workflow, and adds a real uninstall track: identify removable targets, inspect scope, launch a background uninstall, and review residuals without leaving the report page.",
    "hero.download": "Download Windows Client",
    "hero.downloadMeta": "Desktop client downloads appear here when a release package is available.",
    "hero.highlight.scan.tag": "Scan",
    "hero.highlight.scan.title": "Real Flask background jobs",
    "hero.highlight.response.tag": "Response",
    "hero.highlight.response.title": "Evidence-linked uninstall flow",
    "hero.highlight.audit.tag": "Audit",
    "hero.highlight.audit.title": "JSON, DOCX, task logs, leftovers",
    "section.summary.eyebrow": "Executive Summary",
    "section.summary.title": "Executive Summary",
    "summary.meta.host": "Host",
    "summary.meta.system": "System",
    "summary.meta.scanId": "Scan ID",
    "summary.meta.finishedAt": "Finished At",
    "recommendation.eyebrow": "Next Moves",
    "recommendation.title": "Recommended Remediation",
    "recommendation.targets.title": "High-Risk Targets",
    "progress.eyebrow": "Scan Lifecycle",
    "progress.title": "Execution Progress",
    "domains.eyebrow": "Domain Portfolio",
    "domains.title": "Security Domains",
    "findings.eyebrow": "Findings",
    "findings.title": "Finding Workbench",
    "findings.searchPlaceholder": "Search checks, domains, descriptions, or IDs",
    "findings.head.check": "Finding / Target",
    "findings.head.domain": "Type / Domain",
    "findings.head.status": "Status",
    "findings.head.risk": "Risk",
    "findings.head.confidence": "Confidence",
    "findings.head.evidence": "Evidence",
    "findings.head.action": "Action",
    "ops.eyebrow": "Operations",
    "ops.title": "Operations Center",
    "ops.currentState": "Current State",
    "ops.scanLabel": "Scan",
    "ops.timeLabel": "Time",
    "ops.removableTargets": "Removable Targets",
    "ops.lastUninstall": "Last Uninstall",
    "download.eyebrow": "Download",
    "download.title": "Windows Client",
    "download.channel": "Release Channel",
    "runtime.eyebrow": "Runtime",
    "runtime.title": "Runtime Context",
    "about.eyebrow": "About",
    "about.title": "Safety Notes",
    "history.scan.eyebrow": "Scan History",
    "history.scan.title": "Recent Scans",
    "uninstall.progress.eyebrow": "Uninstall Progress",
    "uninstall.progress.title": "Removal Orchestrator",
    "evidence.eyebrow": "Evidence Inspector",
    "evidence.title": "Evidence Inspector",
    "result.eyebrow": "Removal Result",
    "result.title": "Residual Review",
    "history.uninstall.eyebrow": "Uninstall History",
    "history.uninstall.title": "Recent Removals",
    "modal.eyebrow": "Uninstall Confirmation",
    "modal.title": "Review scope and confirm",
    "modal.target": "Target",
    "modal.safety": "Safety Notes",
    "modal.safetyTitle": "Uninstall may disable this tool.",
    "modal.safetyBody": "Some leftovers may require manual review if the runner preserves protected paths.",
    "modal.scope": "Planned Scope",
    "modal.mode": "Mode",
    "modal.toggle.startup": "Remove startup and persistence entries",
    "modal.toggle.cache": "Remove cache footprint",
    "modal.toggle.config": "Remove config footprint",
    "modal.toggle.binary": "Remove explicit binary files",
    "modal.confirm": "Type UNINSTALL CONFIRMED to continue",
    "modal.confirmPlaceholder": "UNINSTALL CONFIRMED",
    "modal.cancel": "Cancel",
    "modal.submit": "Confirm Uninstall",
  },
};

const CLIENT_BOOTSTRAP = window.POLICE_CLAW_BOOTSTRAP || {};
const API_HEADER_NAME = CLIENT_BOOTSTRAP.apiHeaderName || "X-PoliceClaw-Token";
const API_TOKEN = CLIENT_BOOTSTRAP.apiToken || "";
const PUBLIC_SITE_MODE = Boolean(CLIENT_BOOTSTRAP.publicSiteMode);
const DOWNLOAD_ASSET = CLIENT_BOOTSTRAP.download || {};
const APP_VERSION = CLIENT_BOOTSTRAP.appVersion || "0.0.0";
const PUBLIC_SITE_URL = CLIENT_BOOTSTRAP.publicSiteUrl || "https://xpoliceclaw.com";
const RELEASE_URL = CLIENT_BOOTSTRAP.releaseUrl || "";
const PUBLIC_DOWNLOAD_URL = CLIENT_BOOTSTRAP.publicDownloadUrl || "";
const UPDATE_MANIFEST_URL = CLIENT_BOOTSTRAP.updateManifestUrl || `${PUBLIC_SITE_URL}/download/windows/latest/manifest.json`;
const UNINSTALL_CONFIRMATION_TEXT = "UNINSTALL CONFIRMED";
const HIGH_RISK_THRESHOLD = 70;
const TASK_ACTIVE_STATUSES = new Set(["pending", "running"]);
const TASK_TERMINAL_STATUSES = new Set(["success", "failed", "partial"]);
const MANUAL_REVIEW_BLOCK_CODES = new Set(["path_too_broad", "user_data_overlap", "binary_not_safe_to_remove"]);
const CONSOLE_SECTION_IDS = ["dashboardSection", "findingsSection", "targetsSection", "historySection"];
const state = {
  language: resolvePreferredLanguage(),
  jobs: [],
  currentJob: null,
  selectedCheckId: null,
  pollTimer: null,
  uninstallTargets: [],
  uninstallTask: null,
  uninstallHistory: [],
  uninstallSourceJobId: null,
  uninstallSourceScanId: null,
  removedTargetIds: new Set(),
  uninstallModalState: buildModalState(),
  uninstallResult: null,
  uninstallPollTimer: null,
  uninstallPollingTaskId: null,
  uninstallPollInFlight: false,
  releaseInfo: null,
  releaseStatus: "checking",
  eventsBound: false,
  notice: null,
  filters: {
    search: "",
    domain: "all",
    status: "all",
    sort: "risk",
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  bootstrap();
});

function resolvePreferredLanguage() {
  const stored = (() => {
    try {
      return window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    } catch (error) {
      return "";
    }
  })();
  const raw = String(stored || navigator.language || "zh").toLowerCase();
  return raw.startsWith("en") ? "en" : "zh";
}

function tr(zh, en = zh) {
  return state.language === "en" ? en : zh;
}

function getLanguageLocale() {
  return state.language === "en" ? "en-US" : "zh-CN";
}

function getJobStatusLabel(status) {
  const entry = JOB_STATUS_LABELS[status];
  return entry ? tr(entry.zh, entry.en) : safeText(status, tr("未知", "Unknown"));
}

function getRiskLevelLabel(level) {
  const entry = RISK_LEVEL_LABELS[String(level || "").toLowerCase()];
  return entry ? tr(entry.zh, entry.en) : safeText(level, tr("未知", "Unknown"));
}

function getTaskStatusLabel(status) {
  const entry = TASK_STATUS_LABELS[status];
  return entry ? tr(entry.zh, entry.en) : safeText(status, tr("未知", "Unknown"));
}

function getStepStatusLabel(status) {
  const entry = STEP_STATUS_LABELS[status];
  return entry ? tr(entry.zh, entry.en) : safeText(status, tr("未知", "Unknown"));
}

function getLogLevelLabel(level) {
  const entry = LOG_LEVEL_LABELS[String(level || "").toLowerCase()];
  return entry ? tr(entry.zh, entry.en) : safeText(level, tr("信息", "Info"));
}

function getSupportLevelLabel(level) {
  const entry = SUPPORT_LEVEL_LABELS[level];
  return entry ? tr(entry.zh, entry.en) : safeText(level, tr("受限", "Blocked"));
}

function getBlockedReasonLabel(code) {
  const entry = BLOCK_REASON_LABELS[code];
  return entry ? tr(entry.zh, entry.en) : "";
}

function getUninstallStepLabel(label) {
  const entry = UNINSTALL_STEP_LABELS[label];
  return entry ? tr(entry.zh, entry.en) : safeText(label, tr("待执行步骤", "Pending step"));
}

function getPlannedActionLabel(action) {
  const entry = PLANNED_ACTION_LABELS[action];
  return entry ? tr(entry.zh, entry.en) : safeText(action, tr("待处理动作", "Pending action"));
}

function getStartupKindLabel(kind) {
  const entry = STARTUP_KIND_LABELS[kind];
  return entry ? tr(entry.zh, entry.en) : safeText(kind, tr("启动项", "Startup entry"));
}

function getResultItemTypeLabel(type) {
  const entry = RESULT_ITEM_TYPE_LABELS[type];
  return entry ? tr(entry.zh, entry.en) : safeText(type, tr("条目", "Item"));
}

function getTargetTypeLabel(type) {
  const raw = String(type || "").trim();
  const normalized = raw.toLowerCase().replace(/[_-]+/g, " ");
  if (normalized === "local tool" || normalized === "localtool") {
    return tr("本地工具", "Local Tool");
  }
  if (normalized === "unknown") {
    return tr("未知目标", "Unknown target");
  }
  const entry = TARGET_TYPE_LABELS[type];
  if (entry) {
    return tr(entry.zh, entry.en);
  }
  return safeText(humanizeSlug(raw), tr("目标", "Target"));
}

function getTargetName(target) {
  return safeText(target?.display_name || target?.name, tr("未命名目标", "Unnamed target"));
}

function basenameFromPath(value) {
  if (!value) {
    return "";
  }
  const bits = String(value).split(/[\\/]/).filter(Boolean);
  return bits[bits.length - 1] || String(value);
}

function buildBlockedReasonDetail(code) {
  if (code === "path_too_broad") {
    return tr("识别出的路径范围过宽，自动删除会突破安全边界。", "The inferred path is too broad and would exceed the safe removal boundary.");
  }
  if (code === "user_data_overlap") {
    return tr("目标路径与用户数据重叠，执行器默认保留给人工复核。", "The target path overlaps user data, so the runner preserves it for manual review.");
  }
  if (code === "binary_not_safe_to_remove") {
    return tr("程序文件路径不够精确，不能直接自动删除。", "The binary path is not precise enough for automatic removal.");
  }
  if (code === "process_only_detection") {
    return tr("当前只识别到运行中的进程证据，无法安全扩展到文件删除。", "Only runtime process evidence was identified, so file removal is not safe.");
  }
  if (code === "insufficient_evidence") {
    return tr("当前证据不足以把足迹缩小到安全可删范围。", "The current evidence is not precise enough to reduce the footprint to a safely removable scope.");
  }
  return tr("这个目标需要人工复核后再决定是否执行文件删除。", "This target needs human review before any file removal is attempted.");
}

function buildTargetSummaryText(target) {
  if (!target) {
    return tr("尚未选择目标。", "No target selected.");
  }
  const parts = [
    tr(`命中 ${target.matched_findings_count || 0} 条发现`, `${target.matched_findings_count || 0} matched finding(s)`),
    tr(`置信度 ${formatPercent(target.confidence || 0)}`, `${formatPercent(target.confidence || 0)} confidence`),
  ];
  if (target.primary_executable) {
    parts.push(tr(`主程序 ${basenameFromPath(target.primary_executable)}`, `Primary executable ${basenameFromPath(target.primary_executable)}`));
  } else if (target.primary_workdir) {
    parts.push(tr(`工作目录 ${basenameFromPath(target.primary_workdir)}`, `Workdir ${basenameFromPath(target.primary_workdir)}`));
  }
  if (target.startup_entries?.length) {
    parts.push(tr(`${target.startup_entries.length} 个持久化项`, `${target.startup_entries.length} persistence item(s)`));
  }
  if (target.path_warnings?.length) {
    parts.push(tr("部分路径受安全规则保护", "Some paths are protected by safety rules"));
  }
  if (target.support_level === "terminate_only") {
    parts.push(tr("当前仅支持遏制运行进程", "Runtime-only containment"));
  } else if (!target.uninstall_supported && target.blocked_reason_code) {
    parts.push(getBlockedReasonLabel(target.blocked_reason_code));
  }
  return parts.filter(Boolean).join(tr("，", " · "));
}

function buildTargetReasonText(target) {
  if (!target) {
    return tr("请选择一个目标查看处置范围。", "Select a target to review scope.");
  }
  if (target.support_level === "full") {
    return tr("程序路径、工作目录和用户级清理范围都能稳定收敛到同一目标，可在安全校验后执行完整卸载。", "Executable path, workdir, and user-scoped cleanup paths all converge on the same target, so a full uninstall can run after safety validation.");
  }
  if (target.support_level === "cleanup") {
    return tr("持久化、配置和缓存范围明确，但程序文件默认保留给人工复核。", "Persistence, config, and cache paths are clear, but the binary path remains under manual review.");
  }
  if (target.support_level === "terminate_only") {
    return tr("当前证据足以终止活动进程，但文件范围仍然过宽，只适合先做遏制。", "Current evidence is strong enough to stop the active process, but the file scope is still too broad for deletion.");
  }
  return buildBlockedReasonDetail(target.blocked_reason_code);
}

function buildTargetActionHint(target) {
  if (!target) {
    return tr("尚未选择目标。", "No target selected.");
  }
  if (!target.uninstall_supported) {
    return buildBlockedReasonDetail(target.blocked_reason_code);
  }
  if (target.support_level === "cleanup") {
    return tr("会清理持久化、配置和缓存，程序文件默认保留。", "The runner will clean persistence, config, and cache, while preserving the binary path.");
  }
  if (target.support_level === "terminate_only") {
    return tr("当前只会终止进程，不会自动删除文件。", "Only process containment is allowed right now; files stay untouched.");
  }
  return tr("所有文件动作在执行前都会再次经过后端路径安全校验。", "Every file action is revalidated by the backend before execution.");
}

function translateManualStep(text) {
  const value = String(text || "").trim();
  if (!value) {
    return "";
  }
  if (value === "Confirm the linked process is stopped, then rerun a scan before removing anything else.") {
    return tr("先确认关联进程已经停止，再重新执行一次扫描，然后再处理其他残留。", value);
  }
  if (value === "Review remaining user-level persistence items and remove only entries that still point to the target.") {
    return tr("检查剩余的用户级持久化项，只移除仍然明确指向该目标的条目。", value);
  }
  if (value === "Inspect preserved or leftover paths and remove only target-specific files inside the approved footprint.") {
    return tr("检查已保留或残留的路径，只删除已批准范围内明确属于目标的文件。", value);
  }
  if (value === "Keep binary removal manual because the identified path overlaps a protected or user-data-heavy location.") {
    return tr("程序文件删除必须保留为人工操作，因为当前识别路径与受保护位置或高密度用户数据区域重叠。", value);
  }
  if (value === "Contain the target by stopping its process and keep file cleanup under manual review.") {
    return tr("先通过停止进程遏制目标，文件清理继续保持人工复核。", value);
  }
  return value;
}

function translateAuditText(text) {
  const value = String(text || "").trim();
  if (!value) {
    return "";
  }
  if (state.language === "en") {
    return value;
  }
  const exact = new Map([
    ["Manual review is required.", "需要人工复核。"],
    ["No actionable footprint remained after safety validation.", "经过安全校验后，没有剩余可执行的处置足迹。"],
    ["Path still exists after removal pass.", "处置执行后路径仍然存在。"],
    ["Persistence file still exists.", "持久化文件仍然存在。"],
    ["Process is still active.", "进程仍在运行。"],
    ["Removed HKCU Run entry.", "已移除 HKCU Run 启动项。"],
    ["Removed scheduled task.", "已移除计划任务。"],
    ["Config cleanup was disabled by request.", "已按请求跳过配置清理。"],
    ["Cache cleanup was disabled by request.", "已按请求跳过缓存清理。"],
    ["Binary removal was disabled by request.", "已按请求跳过程序文件删除。"],
    ["Binary removal was requested, but the path did not pass safety validation.", "已请求删除程序文件，但路径未通过安全校验。"],
    ["Skipped process that no longer matches the target.", "已跳过不再匹配目标身份的进程。"],
  ]);
  if (exact.has(value)) {
    return exact.get(value);
  }
  if (value.startsWith("Rejected ")) {
    return value
      .replace(/^Rejected /, "已拒绝 ")
      .replace(" path ", " 路径 ")
      .replace(/: /, "：");
  }
  if (value.startsWith("Persistence cleanup failed:")) {
    return value.replace("Persistence cleanup failed:", "持久化清理失败：");
  }
  if (value.startsWith("Process termination failed:")) {
    return value.replace("Process termination failed:", "进程终止失败：");
  }
  if (value.startsWith("Skipped ")) {
    return value.replace("Skipped ", "已跳过 ");
  }
  return value;
}

function translateLogMessage(text) {
  const value = String(text || "").trim();
  if (!value) {
    return "";
  }
  if (state.language === "en") {
    return value;
  }
  if (value.startsWith("Preparing uninstall plan for ")) {
    return value.replace("Preparing uninstall plan for ", "正在为以下目标生成卸载计划：").replace(/\.$/, "。");
  }
  if (/^Plan includes \d+ process\(es\), \d+ persistence item\(s\), and \d+ file path\(s\)\.$/.test(value)) {
    return value
      .replace(/^Plan includes /, "计划包含 ")
      .replace(" process(es), ", " 个进程、")
      .replace(" persistence item(s), and ", " 个持久化项，以及 ")
      .replace(" file path(s).", " 条文件路径。");
  }
  if (value === "No active processes were linked to the target.") {
    return "没有发现与目标关联的活动进程。";
  }
  if (value === "Startup and persistence cleanup was disabled by request.") {
    return "已按请求禁用启动项和持久化清理。";
  }
  if (value === "No user-level persistence entries were identified.") {
    return "没有识别到用户级持久化项。";
  }
  if (value === "No config or cache paths were planned for removal.") {
    return "本次计划中没有配置或缓存路径需要删除。";
  }
  if (value === "No explicit binary paths were approved for removal.") {
    return "没有明确获批的程序文件路径可供删除。";
  }
  if (value === "Verification completed with no remaining approved footprint.") {
    return "校验完成，未发现剩余已批准足迹。";
  }
  if (/^Verification found \d+ leftover item\(s\)\.$/.test(value)) {
    return value.replace(/^Verification found /, "校验发现 ").replace(" leftover item(s).", " 个残留项。");
  }
  if (/^Process \d+ was already gone\.$/.test(value)) {
    return value.replace(/^Process /, "进程 ").replace(" was already gone.", " 已经退出。");
  }
  if (/^Terminated process \d+\.$/.test(value)) {
    return value.replace(/^Terminated process /, "已终止进程 ").replace(/\.$/, "。");
  }
  if (/^Killed process \d+ after timeout\.$/.test(value)) {
    return value.replace(/^Killed process /, "进程 ").replace(" after timeout.", " 在超时后被强制结束。");
  }
  if (/^Failed to terminate process \d+: /.test(value)) {
    return value.replace(/^Failed to terminate process /, "终止进程 ").replace(/: /, " 失败：");
  }
  if (/^Persistence cleanup failed for /.test(value)) {
    return value.replace(/^Persistence cleanup failed for /, "持久化清理失败：").replace(/: /, "：");
  }
  if (/^Skipped .*: /.test(value)) {
    return value.replace(/^Skipped /, "已跳过 ").replace(/: /, "：");
  }
  if (/^Task failed unexpectedly: /.test(value)) {
    return value.replace(/^Task failed unexpectedly: /, "任务意外失败：");
  }
  return value;
}

function buildTaskSummaryText(task) {
  if (!task) {
    return tr("任务尚未开始。", "Task has not started.");
  }
  const currentStepText = task.current_step
    ? getUninstallStepLabel(task.current_step)
    : tr("任务已创建，等待执行。", "Task created, waiting for execution.");
  if (task.status === "success") {
    return tr("处置已完成，目标范围内没有需要继续人工处理的残留。", "Removal completed and no further manual follow-up is required for the approved scope.");
  }
  if (task.status === "partial") {
    return tr("处置已完成主体动作，但仍有保留项或残留项需要人工复核。", "Primary removal steps completed, but preserved or leftover items still require manual review.");
  }
  if (task.status === "failed") {
    return tr("处置任务失败，请查看日志和残留复核面板。", "Removal task failed. Review logs and the residual panel.");
  }
  return currentStepText;
}

function setLanguage(language) {
  const next = SUPPORTED_LANGUAGES.has(language) ? language : "zh";
  state.language = next;
  try {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, next);
  } catch (error) {
    // Ignore unavailable storage.
  }
  document.documentElement.lang = getLanguageLocale();
  applyStaticTranslations();
  ensureConsoleChrome();
  applyFilterSelectCopy();
  rerenderLanguageState();
}

function translateStaticKey(key) {
  const bucket = STATIC_TRANSLATIONS[state.language] || STATIC_TRANSLATIONS.zh;
  return bucket[key] || key;
}

function applyStaticTranslations() {
  const select = document.getElementById("languageSelect");
  if (select) {
    select.value = state.language;
  }
  if (!PUBLIC_SITE_MODE) {
    document.title = tr("Police Claw 安全报告工作台", "Police Claw Security Report Workbench");
  }
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = translateStaticKey(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", translateStaticKey(node.dataset.i18nPlaceholder));
  });
}

function ensureConsoleChrome() {
  ensureScopeBadgeHost();
  ensureTopbarFactsHost();
  ensureFindingsSummaryHost();
  ensureOperationSignalHost();
  ensurePanelSubcopy("#dashboardSection", tr(
    "用一眼可读的方式汇总当前风险态势、主机上下文与最近一次扫描结果。",
    "Summarize current posture, host context, and the latest completed scan in one pass.",
  ));
  ensurePanelSubcopy(".progress-panel", tr(
    "跟踪当前扫描阶段、阶段历史和最终报告生成进度。",
    "Track the current stage, stage history, and report generation progress for the active scan.",
  ));
  ensurePanelSubcopy("#domainPortfolio", tr(
    "按安全域查看风险分布，快速定位最值得先处理的本地执行面。",
    "Compare risk distribution across domains to find the most urgent local execution surface.",
  ));
  ensurePanelSubcopy(".runtime-panel-main", tr(
    "保留进程、连接、文件与模型信号，帮助解释报告与处置范围。",
    "Keep process, connection, file, and model signals visible so findings stay explainable.",
  ));
  ensurePanelSubcopy("#findingsSection", tr(
    "以表格方式浏览高风险代理、脚本、技能与本地执行迹象，并联动证据检查器。",
    "Review risky agents, scripts, skills, and local execution traces in a table-first workflow.",
  ));
  ensurePanelSubcopy("#targetsSection", tr(
    "优先列出处置价值最高且范围可解释的自动化或人工跟进动作。",
    "Queue the highest-value remediation moves first and leave explicit manual follow-up signals.",
  ));
  ensurePanelSubcopy("#operationsSection", tr(
    "集中查看当前扫描状态、最近处置结果与报告导出入口。",
    "Keep scan status, recent remediation outcome, and report exports in one operational rail.",
  ));
  ensurePanelSubcopy("#uninstallTaskMeta", tr(
    "持续显示后台处置任务的步骤、进度和日志输出。",
    "Follow each remediation task through background steps, timing, and logs.",
  ));
  ensurePanelSubcopy("#evidenceMeta", tr(
    "查看原始证据、推导目标与当前发现项的上下文说明。",
    "Inspect raw evidence, inferred targets, and the reasoning behind the selected finding.",
  ));
  ensurePanelSubcopy("#uninstallResultMeta", tr(
    "汇总已删除、保留与残留项，明确哪些步骤仍需人工复核。",
    "Review removed, preserved, and leftover items before closing the remediation loop.",
  ));
  ensurePanelSubcopy("#safetyNotesMeta", tr(
    "明确当前控制台的能力边界、保守处置原则与历史持久化范围。",
    "Reinforce capability scope, conservative deletion boundaries, and persisted history behavior.",
  ));
  ensurePanelSubcopy("#historyList", tr(
    "回看最近的扫描批次、状态与报告完成情况。",
    "Review recent scan batches, completion state, and the latest host snapshot.",
  ));
  ensurePanelSubcopy("#uninstallHistoryList", tr(
    "追踪最近的自动处置尝试、结果和人工跟进信号。",
    "Track the latest automated remediation attempts and remaining manual review work.",
  ));
  ensurePanelSubcopy("#downloadPanelMeta", tr(
    "本地客户端负责真实扫描与处置，网站只负责分发安装包。",
    "The local client performs real scan and remediation. The site only distributes installers.",
  ));
}

function ensureTopbarFactsHost() {
  const topbarCopy = document.querySelector(".topbar-copy");
  if (!topbarCopy || document.getElementById("consoleQuickStats")) {
    return;
  }
  const host = document.createElement("div");
  host.id = "consoleQuickStats";
  host.className = "topbar-facts";
  topbarCopy.appendChild(host);
}

function ensureScopeBadgeHost() {
  const subtitle = document.querySelector(".topbar-subtitle");
  if (!subtitle || document.getElementById("scopeBadgeHost")) {
    return;
  }
  const host = document.createElement("div");
  host.id = "scopeBadgeHost";
  host.className = "scope-badge";
  subtitle.insertAdjacentElement("afterend", host);
}

function ensureFindingsSummaryHost() {
  const findingsSection = document.getElementById("findingsSection");
  if (!findingsSection || document.getElementById("findingsSummaryChips")) {
    return;
  }
  const toolbar = findingsSection.querySelector(".findings-toolbar");
  if (!toolbar) {
    return;
  }
  const host = document.createElement("div");
  host.id = "findingsSummaryChips";
  host.className = "findings-summary";
  toolbar.insertAdjacentElement("afterend", host);
}

function ensureOperationSignalHost() {
  const section = document.getElementById("operationsSection");
  if (!section || document.getElementById("opsSignalStrip")) {
    return;
  }
  const statusCard = section.querySelector(".status-card");
  if (!statusCard) {
    return;
  }
  const host = document.createElement("div");
  host.id = "opsSignalStrip";
  host.className = "ops-signal-strip";
  statusCard.insertAdjacentElement("beforebegin", host);
}

function ensurePanelSubcopy(anchorSelector, text) {
  const anchor = document.querySelector(anchorSelector);
  const section = anchor?.matches("section") ? anchor : anchor?.closest("section");
  const container = section?.querySelector(".panel-head > div");
  if (!container) {
    return;
  }
  let node = container.querySelector(".panel-subcopy");
  if (!node) {
    node = document.createElement("p");
    node.className = "panel-subcopy";
    container.appendChild(node);
  }
  node.textContent = text;
}

function applyFilterSelectCopy() {
  const statusFilter = document.getElementById("statusFilter");
  const sortFilter = document.getElementById("sortFilter");
  const uninstallMode = document.getElementById("uninstallMode");
  const currentStatus = state.filters.status;
  const currentSort = state.filters.sort;
  const currentMode = uninstallMode ? uninstallMode.value : "standard";
  if (statusFilter) {
    statusFilter.innerHTML = [
      ["all", tr("全部状态", "All Status")],
      ["risk", tr("仅风险项", "Risk Only")],
      ["clear", tr("仅清洁项", "Clear Only")],
      ["evidence", tr("仅有证据", "With Evidence")],
    ].map(([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`).join("");
    statusFilter.value = currentStatus;
  }
  if (sortFilter) {
    sortFilter.innerHTML = [
      ["risk", tr("按风险排序", "Sort by Risk")],
      ["evidence", tr("按证据排序", "Sort by Evidence")],
      ["domain", tr("按安全域排序", "Sort by Domain")],
      ["name", tr("按名称排序", "Sort by Name")],
    ].map(([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`).join("");
    sortFilter.value = currentSort;
  }
  if (uninstallMode) {
    uninstallMode.innerHTML = [
      ["standard", tr("标准", "Standard")],
      ["deep", tr("深度", "Deep")],
    ].map(([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`).join("");
    uninstallMode.value = currentMode;
  }
}

function rerenderLanguageState() {
  if (PUBLIC_SITE_MODE) {
    renderPublicSiteMode();
    renderModal();
    return;
  }
  if (state.currentJob || state.jobs.length || state.uninstallHistory.length) {
    renderJob(state.currentJob);
    renderModal();
    return;
  }
  renderEmptyState();
}

function buildModalState() {
  return {
    open: false,
    targetId: null,
    mode: "standard",
    remove_startup: true,
    remove_cache: true,
    remove_config: true,
    remove_binary: false,
    confirmation_text: "",
    error: "",
  };
}

function bindEvents() {
  if (state.eventsBound) {
    return;
  }
  state.eventsBound = true;
  const languageSelect = document.getElementById("languageSelect");
  if (languageSelect) {
    languageSelect.addEventListener("change", (event) => setLanguage(event.target.value));
  }
  document.getElementById("startScanBtn").addEventListener("click", handlePrimaryAction);
  document.getElementById("historyList").addEventListener("click", onHistoryClick);
  document.getElementById("domainPortfolio").addEventListener("click", onDomainClick);
  document.getElementById("findingsTable").addEventListener("click", onFindingClick);
  document.getElementById("findingsSearch").addEventListener("input", onFilterChange);
  document.getElementById("domainFilter").addEventListener("change", onFilterChange);
  document.getElementById("statusFilter").addEventListener("change", onFilterChange);
  document.getElementById("sortFilter").addEventListener("change", onFilterChange);
  document.getElementById("uninstallTargetList").addEventListener("click", onTargetActionClick);
  document.getElementById("uninstallHistoryList").addEventListener("click", onUninstallHistoryClick);
  document.getElementById("uninstallCancelBtn").addEventListener("click", closeUninstallModal);
  document.getElementById("uninstallSubmitBtn").addEventListener("click", submitUninstall);
  document.getElementById("uninstallModal").addEventListener("click", onModalShellClick);
  document.getElementById("uninstallMode").addEventListener("change", onModalInputChange);
  document.getElementById("removeStartupToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeCacheToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeConfigToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeBinaryToggle").addEventListener("change", onModalInputChange);
  document.getElementById("confirmationText").addEventListener("input", onModalInputChange);
  document.querySelectorAll(".console-nav-link").forEach((link) => {
    link.addEventListener("click", onConsoleNavClick);
  });
  window.addEventListener("hashchange", () => setActiveConsoleNav(resolveConsoleNavSection()));
  bindConsoleNavigation();
}

function onConsoleNavClick(event) {
  const href = event.currentTarget.getAttribute("href") || "";
  if (!href.startsWith("#")) {
    return;
  }
  setActiveConsoleNav(href.slice(1));
}

function setActiveConsoleNav(sectionId) {
  document.querySelectorAll(".console-nav-link").forEach((link) => {
    const href = link.getAttribute("href") || "";
    const targetId = href.startsWith("#") ? href.slice(1) : "";
    link.classList.toggle("is-active", targetId === sectionId);
  });
}

function bindConsoleNavigation() {
  setActiveConsoleNav(resolveConsoleNavSection());
}

function resolveConsoleNavSection() {
  const hash = String(window.location.hash || "").replace(/^#/, "");
  return CONSOLE_SECTION_IDS.includes(hash) ? hash : "dashboardSection";
}

async function bootstrap() {
  document.documentElement.lang = getLanguageLocale();
  applyStaticTranslations();
  ensureConsoleChrome();
  applyFilterSelectCopy();
  renderEmptyState();
  renderGlobalNotice();
  loadReleaseInfo().catch(() => {});

  if (PUBLIC_SITE_MODE) {
    renderPublicSiteMode();
    renderModal();
    return;
  }

  const failures = [];
  await Promise.all([
    loadJobs().catch((error) => failures.push(tr(`扫描历史：${error.message}`, `Scan history: ${error.message}`))),
    loadUninstallHistory().catch((error) => failures.push(tr(`卸载历史：${error.message}`, `Uninstall history: ${error.message}`))),
  ]);

  if (failures.length) {
    setGlobalNotice("warn", tr("数据仅部分加载", "Partial data loaded"), failures.join(" "));
  }

  try {
    const activeJob = state.jobs.find((job) => ["queued", "running"].includes(job.status));
    if (activeJob) {
      await loadJob(activeJob.id);
      startPolling(activeJob.id);
    } else if (state.jobs[0]) {
      await loadJob(state.jobs[0].id);
    } else {
      renderEmptyState();
    }

    await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));

    const activeTask = getScopedUninstallHistory().find((task) => TASK_ACTIVE_STATUSES.has(task.status));
    if (activeTask) {
      await loadUninstallTask(activeTask.id);
      startUninstallPolling(activeTask.id);
    } else if (getScopedUninstallHistory()[0]) {
      state.uninstallTask = getScopedUninstallHistory()[0];
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      }
      renderUninstallPanel();
      renderUninstallResult();
    } else if (state.uninstallHistory[0]) {
      state.uninstallTask = state.uninstallHistory[0];
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      }
      renderUninstallPanel();
      renderUninstallResult();
    }

    renderModal();
    renderSafetyNotes(state.currentJob);
  } catch (error) {
    renderGlobalError(error.message);
  }
}

function handlePrimaryAction() {
  if (PUBLIC_SITE_MODE) {
    openDownloadAsset();
    return;
  }
  startScan();
}

async function startScan() {
  const button = document.getElementById("startScanBtn");
  button.disabled = true;

  try {
    clearGlobalNotice();
    const job = await requestJson("/api/scans", { method: "POST" }, tr("无法启动扫描。", "Unable to start a scan."));
    state.selectedCheckId = null;
    state.currentJob = job;
    renderJob(job);
    await loadJobs();
    await fetchUninstallTargets(getRequestedUninstallJobId(job));
    startPolling(job.id);
  } catch (error) {
    renderGlobalError(error.message);
  } finally {
    syncButtonState();
  }
}

async function loadJobs() {
  const payload = await requestJson("/api/scans", {}, tr("无法加载扫描历史。", "Unable to load scan history."));
  state.jobs = payload.items || [];
  renderHistory();
}

async function loadJob(jobId) {
  const job = await requestJson(`/api/scans/${jobId}`, {}, tr("无法加载所选扫描。", "Unable to load the selected scan."));
  state.currentJob = job;
  ensureSelectedCheck(job);
  renderJob(job);
}

async function fetchUninstallTargets(jobId = null) {
  const query = jobId ? `?job_id=${encodeURIComponent(jobId)}` : "";
  const payload = await requestJson(
    `/api/uninstall/targets${query}`,
    {},
    tr("无法加载卸载目标。", "Unable to load uninstall targets."),
  );
  state.uninstallTargets = payload.items || [];
  state.uninstallSourceJobId = payload.source_job_id || null;
  state.uninstallSourceScanId = payload.source_scan_id || null;
  refreshRemovedTargetIds();
  refreshUninstallViews();
}

async function loadUninstallTargets() {
  await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
}

async function loadUninstallHistory() {
  const payload = await requestJson("/api/uninstall/history", {}, tr("无法加载卸载历史。", "Unable to load uninstall history."));
  state.uninstallHistory = payload.items || [];
  if (state.uninstallTask) {
    const refreshed = state.uninstallHistory.find((task) => task.id === state.uninstallTask.id);
    if (refreshed) {
      state.uninstallTask = refreshed;
    }
  } else if (state.uninstallHistory[0]) {
    state.uninstallTask = state.uninstallHistory[0];
  }
  refreshRemovedTargetIds();
  refreshUninstallViews();
}

async function loadUninstallTask(taskId) {
  const task = await requestJson(`/api/uninstall/${taskId}`, {}, tr("无法加载卸载任务详情。", "Unable to load uninstall task details."));
  state.uninstallTask = task;
  renderUninstallPanel();
  syncOperationPanel(state.currentJob);
  if (isTerminalTask(task)) {
    await loadUninstallResult(task.id);
  }
}

async function loadUninstallResult(taskId) {
  const result = await requestJson(
    `/api/uninstall/${taskId}/result`,
    {},
    tr("无法加载卸载结果。", "Unable to load the uninstall result."),
  );
  state.uninstallResult = result;
  renderUninstallResult();
}

async function loadReleaseInfo() {
  state.releaseStatus = "checking";
  renderDownloadPanel();
  const isLoopbackDev = ["127.0.0.1", "localhost"].includes(window.location.hostname) && !CLIENT_BOOTSTRAP.desktopShell;
  if (isLoopbackDev && !PUBLIC_SITE_MODE) {
    state.releaseInfo = null;
    state.releaseStatus = hasDownloadAsset() ? "ready" : "unavailable";
    renderDownloadPanel();
    return;
  }
  try {
    const response = await fetch(UPDATE_MANIFEST_URL, {
      headers: {
        Accept: "application/json",
      },
    });
    const payload = await parseJson(response, tr("无法检查最新公开发布版本。", "Unable to check the latest public release."));
    state.releaseInfo = payload;
    state.releaseStatus = "ready";
  } catch (error) {
    state.releaseInfo = null;
    state.releaseStatus = "unavailable";
  }
  renderDownloadPanel();
  syncOperationPanel(state.currentJob);
}

function startPolling(jobId) {
  stopPolling();
  state.pollTimer = window.setInterval(async () => {
    try {
      await Promise.all([loadJob(jobId), loadJobs()]);
      if (!["queued", "running"].includes(state.currentJob?.status)) {
        stopPolling();
        await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
      }
    } catch (error) {
      stopPolling();
      renderGlobalError(error.message);
    }
  }, 1500);
}

function stopPolling() {
  if (!state.pollTimer) {
    return;
  }
  window.clearInterval(state.pollTimer);
  state.pollTimer = null;
}

function startUninstallPolling(taskId) {
  stopUninstallPolling();
  state.uninstallPollingTaskId = taskId;
  pollUninstallTask(taskId);
}

async function pollUninstallTask(taskId) {
  if (state.uninstallPollInFlight || state.uninstallPollingTaskId !== taskId) {
    return;
  }
  state.uninstallPollInFlight = true;
  try {
    await Promise.all([
      loadUninstallTask(taskId),
      loadUninstallHistory(),
      fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob)),
    ]);
    if (state.uninstallTask?.id !== taskId || isTerminalTask(state.uninstallTask)) {
      stopUninstallPolling();
      return;
    }
    state.uninstallPollTimer = window.setTimeout(() => {
      pollUninstallTask(taskId).catch((error) => renderGlobalError(error.message));
    }, 1200);
  } catch (error) {
    stopUninstallPolling();
    renderGlobalError(error.message);
  } finally {
    state.uninstallPollInFlight = false;
  }
}

function stopUninstallPolling() {
  if (!state.uninstallPollTimer) {
    state.uninstallPollingTaskId = null;
    state.uninstallPollInFlight = false;
    return;
  }
  window.clearTimeout(state.uninstallPollTimer);
  state.uninstallPollTimer = null;
  state.uninstallPollingTaskId = null;
  state.uninstallPollInFlight = false;
}

function renderJob(job) {
  renderConsoleHeader(job);
  syncButtonState();
  syncOperationPanel(job);
  renderExecutiveSummary(job);
  renderProgress(job);
  renderArtifacts(job);
  renderRuntime(job);
  renderSafetyNotes(job);
  renderHistory();
  renderDomainPortfolio(job);
  renderFindings(job);
  renderEvidencePanel(job);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
  renderDownloadPanel();
  decorateConsoleSurface(job);
}

function refreshUninstallViews() {
  syncOperationPanel(state.currentJob);
  renderExecutiveSummary(state.currentJob);
  renderFindings(state.currentJob);
  renderEvidencePanel(state.currentJob);
  renderSafetyNotes(state.currentJob);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
  renderDownloadPanel();
  renderModal();
  decorateConsoleSurface(state.currentJob);
}

function syncOperationPanel(job) {
  if (PUBLIC_SITE_MODE) {
    document.getElementById("jobStateText").textContent = hasDownloadAsset()
      ? tr("公开下载站", "Public download site")
      : tr("发布包不可用", "Release package unavailable");
    document.getElementById("jobMetaText").textContent = hasDownloadAsset()
      ? tr(`Windows 安装包 ${DOWNLOAD_ASSET.version || "--"} 已可直接下载。`, `Windows installer ${DOWNLOAD_ASSET.version || "--"} is ready for direct download.`)
      : tr("请先构建 Windows 发布包，网站才会开放直接下载。", "Build a Windows release package to enable direct website downloads.");
    document.getElementById("scanIdLabel").textContent = DOWNLOAD_ASSET.version || "--";
    document.getElementById("scanTimeLabel").textContent = hasDownloadAsset()
      ? formatFileSize(DOWNLOAD_ASSET.sizeBytes)
      : "--";
    document.getElementById("uninstallAvailableLabel").textContent = "--";
    document.getElementById("uninstallLastStatus").textContent = tr("仅本地", "Local Only");
    document.getElementById("uninstallLastMeta").textContent =
      tr("真实扫描与卸载只在安装后的 Windows 客户端中可用。", "Real scan and uninstall remain available after the Windows client is installed.");
    return;
  }

  const stageText = getStageLabel(job?.stage_key, job?.stage_label);
  const statusText = job?.status === "failed"
    ? tr("扫描失败", "Scan failed")
    : stageText || tr("等待扫描", "Waiting for a scan");
  const metaText = job?.report
    ? `${job.report.host || "--"} / ${job.report.os || "--"}`
    : job?.created_at
      ? tr(`任务创建于 ${formatDate(job.created_at)}`, `Job created at ${formatDate(job.created_at)}`)
      : tr("当前还没有活动中的扫描任务", "No active scan job yet");

  document.getElementById("jobStateText").textContent = statusText;
  document.getElementById("jobMetaText").textContent = metaText;
  document.getElementById("scanIdLabel").textContent = job?.scan_id || "--";
  document.getElementById("scanTimeLabel").textContent = job?.report?.timestamp || "--";

  const scopedTargets = getRenderableUninstallTargets(job);
  const directTargets = scopedTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  document.getElementById("uninstallAvailableLabel").textContent = String(directTargets.length);

  const scopedHistory = getScopedUninstallHistory(job);
  const lastTask = scopedHistory[0] || state.uninstallHistory[0];
  document.getElementById("uninstallLastStatus").textContent = lastTask
    ? getTaskStatusLabel(lastTask.status)
    : tr("无", "None");
  document.getElementById("uninstallLastMeta").textContent = lastTask
    ? `${lastTask.target_name} / ${formatDate(lastTask.updated_at)}${lastTask.status === "partial" ? tr(" / 需要人工复核", " / Manual review required") : ""}`
    : state.uninstallSourceScanId
      ? tr(`目标来源于扫描 ${state.uninstallSourceScanId}`, `Targets sourced from scan ${state.uninstallSourceScanId}`)
      : tr("还没有执行过卸载任务", "No uninstall task has run yet");
}

function renderConsoleHeader(job) {
  const stateBadge = document.getElementById("consoleStateBadge");
  const lastScan = document.getElementById("consoleLastScanText");
  const demoBadge = document.getElementById("consoleModeBadge");
  if (!stateBadge || !lastScan || !demoBadge) {
    return;
  }

  if (PUBLIC_SITE_MODE) {
    stateBadge.className = `console-status-badge ${hasDownloadAsset() ? "state-safe" : "state-review"}`;
    stateBadge.textContent = hasDownloadAsset()
      ? tr("站点交付", "Hosted Delivery")
      : tr("待发布", "Release Pending");
    lastScan.textContent = DOWNLOAD_ASSET.publishedAt ? formatDate(DOWNLOAD_ASSET.publishedAt) : (DOWNLOAD_ASSET.version || "--");
    demoBadge.className = "console-mode-badge is-hidden";
    demoBadge.textContent = tr("演示数据", "Demo Data");
    return;
  }

  const referenceJob = job || state.jobs.find((item) => item?.report) || state.jobs[0] || null;
  let label = tr("等待扫描", "Idle");
  let tone = "state-idle";
  let lastText = "--";

  if (referenceJob) {
    lastText = referenceJob.report?.timestamp || formatDate(referenceJob.updated_at || referenceJob.finished_at || referenceJob.created_at) || "--";
    if (["queued", "running"].includes(referenceJob.status)) {
      label = getStageLabel(referenceJob.stage_key, referenceJob.stage_label) || tr("处理中", "Reviewing");
      tone = "state-review";
    } else if (referenceJob.status === "failed") {
      label = tr("需要复核", "Review Required");
      tone = "state-risk";
    } else if (referenceJob.report) {
      const posture = getPosture(referenceJob.report);
      label = posture.label;
      tone = posture.badgeClass === "badge-good"
        ? "state-safe"
        : posture.badgeClass === "badge-risk"
          ? "state-risk"
          : "state-review";
    }
  }

  stateBadge.className = `console-status-badge ${tone}`;
  stateBadge.textContent = label;
  lastScan.textContent = lastText;
  demoBadge.className = referenceJob?.report?.demo_mode ? "console-mode-badge" : "console-mode-badge is-hidden";
  demoBadge.textContent = tr("演示数据", "Demo Data");
}

function renderExecutiveSummary(job) {
  const report = job?.report;
  const badge = document.getElementById("reportBadge");
  const headline = document.getElementById("reportHeadline");
  const narrative = document.getElementById("reportNarrative");
  const metaHost = document.getElementById("metaHost");
  const metaOs = document.getElementById("metaOs");
  const metaScanId = document.getElementById("metaScanId");
  const metaScanTime = document.getElementById("metaScanTime");
  const summaryGrid = document.getElementById("summaryGrid");
  const recommendationList = document.getElementById("recommendationList");

  if (PUBLIC_SITE_MODE) {
    badge.className = "report-badge report-badge-info";
    badge.textContent = hasDownloadAsset() ? tr("网站下载", "Website Download") : tr("等待发布", "Release Pending");
    headline.textContent = tr("先下载 Windows 客户端，再在本机执行扫描与处置。", "Download the Windows client to scan and remediate the local machine.");
    narrative.textContent = hasDownloadAsset()
      ? tr("网站负责分发桌面安装包。真实扫描、证据采集和卸载动作仍只会在安装后的 Windows 本机执行。", "The hosted site distributes the desktop installer. Real scanning, evidence collection, and uninstall actions still run locally on Windows after installation.")
      : tr("公网站点已经上线，但还没有挂载安装包。请先构建 Windows 发布包以开启客户端下载。", "The public site is live, but no installer package is attached yet. Build a Windows release to enable direct client downloads.");
    metaHost.textContent = tr("Windows 客户端", "Windows Client");
    metaOs.textContent = "Windows 10+";
    metaScanId.textContent = DOWNLOAD_ASSET.version || "--";
    metaScanTime.textContent = hasDownloadAsset() ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--";
    summaryGrid.innerHTML = [
      { value: hasDownloadAsset() ? DOWNLOAD_ASSET.version || "--" : "--", label: tr("安装包版本", "Installer Version") },
      { value: hasDownloadAsset() ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--", label: tr("安装包大小", "Package Size") },
      { value: tr("本地", "Local"), label: tr("执行范围", "Execution Scope") },
      { value: tr("保守", "Conservative"), label: tr("删除边界", "Removal Boundary") },
    ].map((card) => `
      <article class="summary-card">
        <span>${escapeHtml(card.label)}</span>
        <strong>${escapeHtml(String(card.value))}</strong>
      </article>
    `).join("");
    recommendationList.innerHTML = [
      {
        tone: "neutral",
        tag: tr("下载", "Download"),
        title: hasDownloadAsset() ? tr("安装 Windows 客户端", "Install the Windows client") : tr("构建发布包", "Build a release package"),
        body: hasDownloadAsset()
          ? tr("通过安装包部署本地工作台，然后在 Windows 主机上执行扫描和卸载任务。", "Use the direct installer to deploy the local workbench, then run scans and uninstall tasks on the Windows host.")
          : tr("当前还没有发布安装包。请先构建 dist/release，网站才能分发 Windows 客户端。", "No installer is published yet. Build dist/release first so the website can serve a Windows client."),
      },
      {
        tone: "warn",
        tag: tr("边界", "Boundary"),
        title: tr("网站不会扫描访问者电脑", "The hosted site does not scan the visitor machine"),
        body: tr("所有真实扫描与卸载动作仍然只会在已安装的 Windows 客户端中执行，而不是远端浏览器会话。", "All real scan and uninstall actions still execute inside the installed Windows client, not in the remote browser session."),
      },
      {
        tone: "info",
        tag: tr("审计", "Audit"),
        title: tr("报告与任务历史保存在本地", "Reports and task history stay local"),
        body: tr("已安装客户端会把扫描历史、卸载历史和报告产物保存在本地运行时目录，便于后续复核。", "The installed client keeps scan history, uninstall history, and report artifacts under the local runtime root for later review."),
      },
    ].map((item) => `
      <article class="recommendation-item recommendation-${escapeHtml(item.tone || "neutral")}">
        ${item.tag ? `<span class="recommendation-tag recommendation-tag-${escapeHtml(item.tone || "neutral")}">${escapeHtml(item.tag)}</span>` : ""}
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.body)}</p>
      </article>
    `).join("");
    renderUninstallTargets();
    return;
  }

  if (!report) {
    badge.className = "report-badge";
    badge.textContent = tr("空闲", "Idle");
    headline.textContent = job?.status === "failed" ? tr("最近一次扫描失败。", "The latest scan failed.") : tr("等待已完成的扫描", "Waiting for a completed scan");
    narrative.textContent = job?.error || tr("扫描成功完成后，报告工作台会自动填充内容。", "The report workbench will populate after a successful scan finishes.");
    metaHost.textContent = "--";
    metaOs.textContent = "--";
    metaScanId.textContent = job?.scan_id || "--";
    metaScanTime.textContent = "--";
    summaryGrid.innerHTML = buildEmptyCard(tr("有可用的已完成报告后，这里会显示摘要指标。", "Summary metrics appear after a completed report is available."));
    recommendationList.innerHTML = buildEmptyCard(tr("建议动作会根据最近一次完成的报告自动生成。", "Recommended actions are generated from the latest completed report."));
    renderUninstallTargets();
    return;
  }

  const posture = getPosture(report);
  badge.className = `report-badge ${posture.badgeClass}`;
  badge.textContent = report.demo_mode ? `${posture.label} / ${tr("演示", "Demo")}` : posture.label;
  headline.textContent = posture.headline;
  narrative.textContent = report.demo_mode
    ? `${tr("已加载演示数据。", "Demo fixture loaded.")} ${buildNarrative(report)}`
    : buildNarrative(report);
  metaHost.textContent = report.host || "--";
  metaOs.textContent = report.os || "--";
  metaScanId.textContent = report.scan_id || "--";
  metaScanTime.textContent = report.timestamp || "--";

  const summaryTargets = getRenderableUninstallTargets(job);
  const supportedTargets = summaryTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const resolvedTargets = supportedTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });
  const manualReviewTargets = summaryTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "partial" || remediation.status === "manual-review";
  });
  const checks = report.checks || [];
  const highRiskCount = checks.filter((check) => Number(check.risk_score || 0) >= HIGH_RISK_THRESHOLD).length;
  const mediumRiskCount = checks.filter((check) => {
    const score = Number(check.risk_score || 0);
    return score >= 40 && score < HIGH_RISK_THRESHOLD;
  }).length;
  const summaryCards = [
    { value: highRiskCount, label: tr("高风险", "High Risk") },
    { value: mediumRiskCount, label: tr("中风险", "Medium Risk") },
    { value: resolvedTargets.length, label: tr("已处置", "Resolved") },
    { value: manualReviewTargets.length, label: tr("人工复核", "Manual Review") },
  ];

  summaryGrid.innerHTML = summaryCards.map((card) => `
    <article class="summary-card">
      <span>${escapeHtml(card.label)}</span>
      <strong>${escapeHtml(String(card.value))}</strong>
    </article>
  `).join("");

  const recommendations = renderUninstallRecommendations(report);
  recommendationList.innerHTML = recommendations.map((item) => `
    <article class="recommendation-item recommendation-${escapeHtml(item.tone || "neutral")}">
      ${item.tag ? `<span class="recommendation-tag recommendation-tag-${escapeHtml(item.tone || "neutral")}">${escapeHtml(item.tag)}</span>` : ""}
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.body)}</p>
    </article>
  `).join("");

  renderUninstallTargets();
}

function renderUninstallTargets() {
  const container = document.getElementById("uninstallTargetList");
  const meta = document.getElementById("uninstallTargetMeta");
  const targets = getRenderableUninstallTargets();

  if (PUBLIC_SITE_MODE) {
    meta.textContent = hasDownloadAsset()
      ? tr("客户端完成本地扫描后才会显示目标", "Targets appear after the client completes a local scan")
      : tr("发布安装包后网站下载入口才会启用", "Publish an installer to activate website downloads");
    container.innerHTML = buildEmptyCard(
      hasDownloadAsset()
        ? tr("这个网站只分发 Windows 客户端。推导出的卸载目标只会在安装后的本地工作台里出现。", "This hosted page distributes the Windows client. Inferred uninstall targets appear only inside the local workbench after installation.")
        : tr("当前还没有可用发布包。请先构建 Windows 安装包，网站才能把用户引导到本地客户端。", "No release package is available yet. Build a Windows installer so the website can hand off to the local client.")
    );
    return;
  }

  if (!targets.length) {
    meta.textContent = tr("暂无可推导的卸载目标", "No inferred uninstall targets yet");
    container.innerHTML = buildEmptyCard(tr("后端会根据最近一次完成的扫描推导可处置目标。", "The backend will infer removable targets from the latest completed scan."));
    return;
  }

  const supported = targets.filter((target) => target.uninstall_supported);
  const sourceLabel = state.uninstallSourceScanId ? tr(` / 来源 ${state.uninstallSourceScanId}`, ` / Source ${state.uninstallSourceScanId}`) : "";
  meta.textContent = tr(`${supported.length} 个可直接处置 / 共 ${targets.length} 个目标${sourceLabel}`, `${supported.length} supported / ${targets.length} total${sourceLabel}`);
  const displayTargets = targets.slice(0, 6);

  container.innerHTML = displayTargets.map((target) => {
    const remediation = getRemediationStateForTarget(target);
    const statusClass = remediation.status === "removed" || remediation.status === "mitigated"
      ? "status-success"
      : remediation.status === "partial" || remediation.status === "manual-review"
        ? "status-partial"
        : remediation.status === "running"
          ? "status-running"
          : target.uninstall_supported
            ? "status-running"
            : "status-failed";
    const statusLabel = remediation.label || (
      target.uninstall_supported
        ? target.support_level === "full"
          ? tr("高优先级", "Urgent")
          : target.support_level === "cleanup"
            ? tr("可清理", "Cleanup")
            : tr("仅遏制", "Contain")
        : tr("受限", "Blocked")
    );
    const targetName = getTargetName(target);
    const targetType = getTargetTypeLabel(target.type);
    const targetSummary = buildTargetSummaryText(target);
    const targetReason = buildTargetReasonText(target);
    const vendorText = target.vendor && !["unknown", "--"].includes(String(target.vendor).trim().toLowerCase())
      ? `${target.vendor} / `
      : "";
    const targetHint = remediation.label ? remediation.detail : buildTargetActionHint(target);
    return `
      <article class="target-card">
        <div class="target-card-head">
          <div>
            <strong>${escapeHtml(targetName)}</strong>
            <span>${escapeHtml(targetType)} / ${escapeHtml(tr(`风险 ${String(target.risk_score)}`, `Risk ${String(target.risk_score)}`))} / ${escapeHtml(tr(`置信度 ${formatPercent(target.confidence || 0)}`, `Confidence ${formatPercent(target.confidence || 0)}`))}</span>
          </div>
          <span class="status-pill ${statusClass}">${escapeHtml(statusLabel)}</span>
        </div>
        <div class="target-card-body">
          <div>${escapeHtml(targetSummary)}</div>
          <div>${escapeHtml(`${vendorText}${targetReason}`)}</div>
        </div>
        <div class="finding-actions">
          <button class="action-btn ghost" type="button" data-target-action="scope" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("查看范围", "View Scope"))}</button>
          ${target.uninstall_supported && !["removed", "mitigated"].includes(remediation.status)
            ? `<button class="action-btn danger" type="button" data-target-action="uninstall" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("一键卸载", "Uninstall"))}</button>`
            : `<span class="panel-meta">${escapeHtml(targetHint)}</span>`}
        </div>
      </article>
    `;
  }).join("");
}

function renderProgress(job) {
  const progress = job?.progress ?? 0;
  document.getElementById("progressLabel").textContent = getStageLabel(job?.stage_key, job?.stage_label) || tr("就绪", "Ready");
  document.getElementById("progressValue").textContent = `${progress}%`;
  document.getElementById("progressBar").style.width = `${progress}%`;

  const activeIndex = Math.max(0, STAGES.findIndex((stage) => stage.key === (job?.stage_key || "queued")));
  document.getElementById("stageStrip").innerHTML = STAGES.map((stage, index) => {
    const classes = ["stage-pill"];
    if (index < activeIndex || (job?.status === "completed" && stage.key === "completed")) {
      classes.push("is-done");
    }
    if (index === activeIndex && ["queued", "running"].includes(job?.status)) {
      classes.push("is-active");
    }
    return `
      <div class="${classes.join(" ")}">
        <span class="eyebrow">${String(index + 1).padStart(2, "0")}</span>
        <strong>${escapeHtml(tr(stage.zh, stage.en))}</strong>
      </div>
    `;
  }).join("");

  const stageHistory = job?.stage_history || [];
  const historyContainer = document.getElementById("stageHistory");
  if (!stageHistory.length) {
    historyContainer.innerHTML = buildEmptyCard(tr("扫描开始后，这里会显示阶段历史。", "Stage history appears once a scan has started."));
    return;
  }

  historyContainer.innerHTML = [...stageHistory].reverse().map((item) => `
    <div class="stage-history-item">
      <div>
        <strong>${escapeHtml(getStageLabel(item.key, item.label))}</strong>
        <span>${escapeHtml(formatDate(item.at))}</span>
      </div>
      <strong>${escapeHtml(String(item.progress || 0))}%</strong>
    </div>
  `).join("");
}

function renderArtifacts(job) {
  const container = document.getElementById("artifactRow");
  if (!job?.artifacts?.json && !job?.artifacts?.docx) {
    container.innerHTML = buildEmptyCard(tr("扫描完成后，这里会出现报告下载入口。", "Report downloads appear when the scan completes."));
    return;
  }

  const items = [];
  if (job.artifacts.json_url) {
    items.push({ type: "JSON", label: tr("下载结构化报告", "Download structured report"), href: job.artifacts.json_url });
  }
  if (job.artifacts.docx_url) {
    items.push({ type: "DOCX", label: tr("下载文档报告", "Download document report"), href: job.artifacts.docx_url });
  }

  container.innerHTML = items.map((item) => `
    <a class="artifact-card" href="${item.href}">
      <span>${escapeHtml(item.type)}</span>
      <strong>${escapeHtml(item.label)}</strong>
    </a>
  `).join("");
}

function renderRuntime(job) {
  const container = document.getElementById("runtimeGrid");
  if (!job) {
    container.innerHTML = buildEmptyCard(tr("当前还没有运行时上下文。", "No runtime context available yet."));
    return;
  }

  const stats = job.report?.runtime?.stats || job.stats || {};
  const rows = [
    [tr("进程数", "Processes"), stats.processes],
    [tr("连接数", "Connections"), stats.connections],
    [tr("打开文件", "Open Files"), stats.open_files],
    [tr("环境信号", "Env Signals"), stats.env_signals],
    ["DNS", Array.isArray(stats.dns_servers) ? stats.dns_servers.join(", ") || "--" : "--"],
    [tr("外联数", "Outbound"), stats.outbound_count],
    [tr("云端点", "Cloud Endpoints"), stats.cloud_endpoints],
    [tr("模型进程", "Model Processes"), stats.model_processes],
  ];

  container.innerHTML = rows.map(([label, value]) => `
    <div class="runtime-item">
      <span class="runtime-key">${escapeHtml(String(label))}</span>
      <strong class="runtime-value">${escapeHtml(String(value ?? "--"))}</strong>
    </div>
  `).join("");
}

function renderSafetyNotes(job) {
  const meta = document.getElementById("safetyNotesMeta");
  const container = document.getElementById("safetyNotesList");
  const targets = getRenderableUninstallTargets(job);
  const blocked = targets.filter((target) => !target.uninstall_supported).length;
  const partial = getScopedUninstallHistory(job).filter((task) => task.status === "partial").length;
  const notes = [
    {
      title: tr("能力范围", "Capability scope"),
      body: tr("自动处置只覆盖边界清晰的用户级代理痕迹、持久化项、配置目录、缓存目录和明确识别出的程序文件。", "Automatic handling is limited to clearly scoped user-level agent footprints, persistence entries, config paths, cache paths, and explicit binaries."),
    },
    {
      title: tr("人工复核", "Manual review"),
      body: tr("受限、仅终止和部分完成都属于正常安全护栏状态，表示执行器主动保留了部分内容，或需要人工确认范围。", "Blocked, terminate-only, and partial outcomes are normal guardrail states. They mean the runner preserved something on purpose or needs a human to verify scope."),
    },
    {
      title: tr("删除边界", "Deletion boundary"),
      body: tr("执行器不会删除根目录、用户主目录、浏览器配置目录、工作区目录，或任何未通过安全校验的宽泛路径。", "The runner will not remove root paths, user home roots, browser profiles, workspace directories, or any broad directory that fails safety validation."),
    },
      {
        title: tr("历史持久化", "History persistence"),
        body: tr(`已完成的扫描和卸载摘要会保存在 ${CLIENT_BOOTSTRAP.runtimeRoot || "本地运行时目录"} 下，便于工作台在重启后恢复最近历史。`, `Completed scan and uninstall summaries are stored under ${CLIENT_BOOTSTRAP.runtimeRoot || "the local runtime root"} so the workbench can recover recent history after a restart.`),
      },
    ];

  if (CLIENT_BOOTSTRAP.desktopShell) {
    notes.push({
      title: tr("桌面会话", "Desktop session"),
      body: CLIENT_BOOTSTRAP.adminMode
        ? tr("客户端正在以桌面模式并带管理员权限运行，因此受保护的卸载步骤可以在本机执行。", "The client is running in desktop mode with administrator rights, so protected uninstall steps can execute on the local machine.")
        : tr("客户端正在以桌面模式运行，但当前没有管理员权限。部分卸载步骤会保留，直到启动器提权后再执行。", "The client is running in desktop mode without administrator rights. Some uninstall steps may be preserved until the launcher is elevated."),
    });
  }

  if (PUBLIC_SITE_MODE) {
    notes.push({
      title: tr("网站模式", "Hosted website mode"),
      body: hasDownloadAsset()
        ? tr("这个公开站点只分发 Windows 安装包。真实扫描、证据采集和卸载仍然在本地客户端安装后执行。", "This public site only distributes the Windows installer. Real scan, evidence collection, and uninstall still execute after the local client is installed.")
        : tr("这个公开站点当前还没有挂载安装包。请先发布构建产物，才能开启直接下载。", "This public site is running without an attached installer package. Publish a release build to enable direct downloads."),
    });
  }

  if (job?.report?.demo_mode || job?.demo_mode || job?.source_type === "demo") {
    notes.push({
      title: tr("演示数据", "Demo fixture"),
      body: tr("当前记录来自演示用的预置数据，不代表一次真实扫描或真实卸载。", "The current record was loaded from curated demo data for presentation. It does not represent a live scan or a live uninstall run."),
    });
  }

  meta.textContent = partial
    ? tr(`当前范围内还有 ${partial} 项残留需要复核。`, `${partial} residual review item(s) remain in this scope.`)
    : blocked
      ? tr(`还有 ${blocked} 个目标处于受限状态，需要人工跟进。`, `${blocked} target(s) remain blocked for manual follow-up.`)
      : tr("自动处置采用保守策略，并保留完整日志。", "Automatic handling is conservative and fully logged.");

  container.innerHTML = notes.map((note) => `
    <article class="result-item result-item-note">
      <strong>${escapeHtml(note.title)}</strong>
      <p>${escapeHtml(note.body)}</p>
    </article>
  `).join("");
}

function renderHistory() {
  const container = document.getElementById("historyList");
  if (!state.jobs.length) {
    container.innerHTML = buildEmptyCard(
      tr("还没有扫描历史。", "No scan history yet."),
      tr("等待首个扫描批次", "Awaiting first scan batch"),
    );
    return;
  }

  container.innerHTML = state.jobs.map((job) => {
    const active = state.currentJob?.id === job.id ? "active" : "";
    const riskCount = job.result_overview?.risk_count ?? job.report?.summary?.total_risks ?? "--";
    const demoSuffix = job.demo_mode || job.source_type === "demo" ? tr(" / 演示数据", " / Demo fixture") : "";
    return `
      <button class="history-card ${active}" type="button" data-job-id="${job.id}">
        <div class="history-head">
          <h3>${escapeHtml(job.scan_id || job.id.toUpperCase())}</h3>
          <span class="status-pill status-${escapeHtml(job.status)}">${escapeHtml(getJobStatusLabel(job.status))}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(`${getStageLabel(job.stage_key, job.stage_label)}${demoSuffix}`)}</span>
          <span>${escapeHtml(tr(`风险 ${String(riskCount)}`, `Risk ${String(riskCount)}`))}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(formatDate(job.updated_at))}</span>
          <span>${escapeHtml(String(job.progress || 0))}%</span>
        </div>
      </button>
    `;
  }).join("");
}

function renderUninstallHistory() {
  const container = document.getElementById("uninstallHistoryList");
  if (!state.uninstallHistory.length) {
    container.innerHTML = buildEmptyCard(
      tr("还没有发起过卸载任务。", "No uninstall tasks have been started yet."),
      tr("等待处置任务", "Awaiting remediation task"),
    );
    return;
  }

  container.innerHTML = state.uninstallHistory.slice(0, 5).map((task) => {
    const active = state.uninstallTask?.id === task.id ? "active" : "";
    const currentStepLabel = task.current_step
      ? getUninstallStepLabel(task.current_step)
      : tr("尚未开始步骤", "No step yet");
    return `
      <button class="history-card ${active}" type="button" data-uninstall-id="${task.id}">
        <div class="history-head">
          <h3>${escapeHtml(task.target_name)}</h3>
          <span class="status-pill status-${escapeHtml(task.status)}">${escapeHtml(getTaskStatusLabel(task.status))}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(currentStepLabel)}</span>
          <span>${escapeHtml(String(task.progress || 0))}%</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(formatDate(task.updated_at))}</span>
          <span>${escapeHtml(task.target_type ? getTargetTypeLabel(task.target_type) : "--")}</span>
        </div>
      </button>
    `;
  }).join("");
}

function renderDomainPortfolio(job) {
  const container = document.getElementById("domainPortfolio");
  const meta = document.getElementById("domainPortfolioMeta");
  const report = job?.report;
  if (!report) {
    container.innerHTML = buildEmptyCard(tr("有可用的已完成报告后，这里会显示安全域卡片。", "Security domain cards appear when a completed report is available."));
    meta.textContent = tr("等待已完成的报告", "Waiting for a completed report");
    syncDomainFilterOptions([]);
    return;
  }

  const domains = getDomainEntries(report);
  syncDomainFilterOptions(domains);
  const riskyDomains = domains.filter((domain) => domain.risks > 0).length;
  meta.textContent = tr(`${riskyDomains} / ${domains.length} 个安全域存在风险发现`, `${riskyDomains} / ${domains.length} domains with flagged findings`);

  container.innerHTML = domains.map((domain) => {
    const isSelected = state.filters.domain === domain.id;
    const width = Math.max(4, Number(domain.max_score || 0));
    const topFinding = [...domain.checks].sort((left, right) => right.risk_score - left.risk_score)[0];
    return `
      <button class="domain-tile ${isSelected ? "is-selected" : ""}" type="button" data-domain-filter="${domain.id}">
        <div class="domain-tile-head">
          <div class="domain-title">
            <span class="domain-icon">${escapeHtml(domain.icon || "")}</span>
            <div>
              <strong>${escapeHtml(safeText(domain.name, humanizeSlug(domain.id)))}</strong>
              <span>${escapeHtml(tr(`${String(domain.risks)} 个风险 / ${String(domain.total)} 项检查`, `${String(domain.risks)} risk / ${String(domain.total)} checks`))}</span>
            </div>
          </div>
          <strong>${escapeHtml(String(domain.max_score))}</strong>
        </div>
        <div class="domain-meter"><span style="width:${width}%"></span></div>
        <div class="domain-support">${escapeHtml(topFinding ? displayCheckTitle(topFinding) : tr("当前安全域中没有明显风险。", "No significant risk currently in this domain."))}</div>
      </button>
    `;
  }).join("");
}

function renderFindings(job) {
  const table = document.getElementById("findingsTable");
  const meta = document.getElementById("findingsMeta");
  const summary = document.getElementById("findingsSummaryChips");
  const report = job?.report;
  if (!report) {
    if (summary) {
      renderFindingsSummary([], 0);
    }
    table.innerHTML = buildEmptyCard(
      tr("扫描报告准备完成后，这里会显示发现项。", "Findings will populate after the scan report is ready."),
      tr("等待发现项数据集", "Awaiting findings dataset"),
    );
    meta.textContent = tr("0 条记录", "0 records");
    return;
  }

  const checks = applyFindingFilters(report.checks || []);
  meta.textContent = tr(`${checks.length} 条可见 / 共 ${(report.checks || []).length} 条`, `${checks.length} visible / ${(report.checks || []).length} total`);
  if (summary) {
    renderFindingsSummary(checks, (report.checks || []).length);
  }

  if (!checks.length) {
    state.selectedCheckId = null;
    table.innerHTML = buildEmptyCard(
      tr("当前筛选条件下没有匹配的发现项。", "No findings match the current filter set."),
      tr("筛选后无结果", "No matching findings"),
    );
    return;
  }

  if (!checks.some((check) => check.id === state.selectedCheckId)) {
    state.selectedCheckId = checks[0].id;
  }

  table.innerHTML = checks.map((check) => {
    const selected = state.selectedCheckId === check.id ? "is-selected" : "";
    const relatedTargets = getRelatedTargets(check.id);
    const primaryTarget = pickPrimaryTarget(relatedTargets);
    const remediation = markRelatedFindingsHandled(check.id);
    const resolved = remediation.status === "removed" || remediation.status === "mitigated";
    const targetLabel = primaryTarget ? getTargetName(primaryTarget) : tr("未推导出可处置目标", "No removable target inferred");
    const typeLabel = primaryTarget ? getTargetTypeLabel(primaryTarget.target_type || primaryTarget.type) : tr("待定目标类型", "Pending target type");
    const severity = getFindingRiskProfile(check);
    const workflow = getFindingWorkflowProfile(check, remediation);
    const width = Math.max(2, Number(check.risk_score || 0));
    const evidenceCount = String(check.evidence_count || 0);

    return `
      <button class="finding-row ${selected} ${resolved ? "is-resolved" : ""}" type="button" data-check-id="${check.id}">
        <div class="finding-row-grid">
          <div class="finding-primary">
            <div class="finding-title-row">
              <div class="finding-title">${escapeHtml(displayCheckTitle(check))}</div>
              <span class="finding-id">${escapeHtml(check.id)}</span>
            </div>
            <div class="finding-support">${escapeHtml(displayCheckDescription(check))}</div>
            <div class="finding-secondary">${escapeHtml(targetLabel)}</div>
          </div>
          <div class="finding-type-cell">
            <strong>${escapeHtml(typeLabel)}</strong>
            <span>${escapeHtml(getCheckDomainLabel(check))}</span>
          </div>
          <div class="finding-status-cell">
            <span class="workflow-badge ${escapeHtml(workflow.className)}">${escapeHtml(workflow.label)}</span>
            ${workflow.detail ? `<span class="finding-status-note">${escapeHtml(workflow.detail)}</span>` : ""}
          </div>
          <div class="finding-risk-cell">
            <span class="risk-pill ${escapeHtml(severity.className)}">${escapeHtml(severity.label)}</span>
            <strong>${escapeHtml(String(check.risk_score))}</strong>
            <div class="mini-meter"><span style="width:${width}%"></span></div>
          </div>
          <div class="finding-metric-cell">
            <strong>${escapeHtml(formatPercent(check.confidence))}</strong>
            <span>${escapeHtml(tr("置信度", "Confidence"))}</span>
          </div>
          <div class="finding-metric-cell">
            <strong>${escapeHtml(evidenceCount)}</strong>
            <span>${escapeHtml(tr("证据样本", "Evidence"))}</span>
          </div>
          <div class="finding-actions">
            ${renderFindingAction(primaryTarget, remediation)}
          </div>
        </div>
      </button>
    `;
  }).join("");
}

function renderFindingAction(target, remediation) {
  if (!target) {
    return `<span class="panel-meta">${escapeHtml(tr("无关联目标", "No target"))}</span>`;
  }
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return `<span class="status-pill status-success">${escapeHtml(remediation.label || tr("已处理", "Handled"))}</span>`;
  }
  if (remediation.status === "partial") {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("查看范围", "View Scope"))}</button>
      <span class="panel-meta">${escapeHtml(tr("需要残留复核", "Residual review required"))}</span>
    `;
  }
  if (remediation.status === "manual-review") {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("查看范围", "View Scope"))}</button>
      <span class="panel-meta">${escapeHtml(remediation.detail || tr("需要人工复核", "Manual review required"))}</span>
    `;
  }
  if (remediation.status === "running") {
    return `<span class="status-pill status-running">${escapeHtml(tr("进行中", "In Progress"))}</span>`;
  }
  if (!target.uninstall_supported) {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("查看范围", "View Scope"))}</button>
      <span class="panel-meta">${escapeHtml(buildTargetActionHint(target))}</span>
    `;
  }
  return `
    <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("查看范围", "View Scope"))}</button>
    <button class="action-btn danger" type="button" data-uninstall-action="launch" data-target-id="${escapeHtml(target.id)}">${escapeHtml(tr("一键卸载", "Uninstall"))}</button>
  `;
}

function getFindingRiskProfile(check) {
  const score = Number(check?.risk_score || 0);
  if (score >= HIGH_RISK_THRESHOLD) {
    return { label: tr("高", "High"), className: "risk-high" };
  }
  if (score >= 40) {
    return { label: tr("中", "Medium"), className: "risk-medium" };
  }
  return { label: tr("低", "Low"), className: "risk-low" };
}

function getFindingWorkflowProfile(check, remediation) {
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return {
      label: remediation.label || tr("已处理", "Handled"),
      className: "workflow-closed",
      detail: "",
    };
  }
  if (remediation.status === "partial") {
    return {
      label: remediation.label || tr("部分完成", "Partial"),
      className: "workflow-partial",
      detail: tr("仍需人工复核残留项", "Residual review is still required"),
    };
  }
  if (remediation.status === "manual-review") {
    return {
      label: remediation.label || tr("人工复核", "Manual Review"),
      className: "workflow-manual",
      detail: remediation.detail || tr("证据不足以执行自动文件删除", "Evidence is not precise enough for automatic file removal"),
    };
  }
  if (remediation.status === "running") {
    return {
      label: remediation.label || tr("进行中", "In Progress"),
      className: "workflow-running",
      detail: tr("后台任务正在执行处置步骤", "A background task is currently executing remediation steps"),
    };
  }
  if (!isFlagged(check)) {
    return {
      label: tr("已审阅", "Reviewed"),
      className: "workflow-reviewed",
      detail: tr("当前发现项没有形成高风险处置请求", "This finding does not currently require high-priority remediation"),
    };
  }
  return {
    label: tr("待处理", "Open"),
    className: "workflow-open",
    detail: tr("建议结合证据与目标范围继续处置", "Review the evidence and inferred target scope before taking action"),
  };
}

function renderEvidencePanel(job) {
  const meta = document.getElementById("evidenceMeta");
  const title = document.getElementById("evidenceTitle");
  const summary = document.getElementById("evidenceSummary");
  const viewer = document.getElementById("evidenceViewer");
  const check = getSelectedCheck(job);

  if (!check) {
    meta.textContent = tr("尚未选择发现项", "No finding selected");
    title.textContent = tr("选择任意发现项以查看证据细节。", "Select a finding to inspect evidence details.");
    summary.textContent = tr("证据样本和卸载范围会显示在这里。", "Evidence samples and uninstall scope will appear here.");
    viewer.textContent = tr("暂无证据可展示。", "No evidence available.");
    return;
  }

  const relatedTargets = getRelatedTargets(check.id);
  const remediation = markRelatedFindingsHandled(check.id);
  const targetSummary = relatedTargets.length
    ? tr(`关联目标：${relatedTargets.map((target) => target.display_name || target.name).join("、")}`, `Linked targets: ${relatedTargets.map((target) => target.display_name || target.name).join(", ")}`)
    : tr("这个发现项没有推导出可处置目标。", "No removable target was inferred from this finding.");
  const remediationText = remediation.label
    ? tr(` 当前处置状态：${remediation.label}。`, ` Current remediation state: ${remediation.label}.`)
    : "";

  meta.textContent = tr(`${getCheckDomainLabel(check)} / 风险 ${check.risk_score} / 置信度 ${formatPercent(check.confidence)}`, `${getCheckDomainLabel(check)} / Risk ${check.risk_score} / Confidence ${formatPercent(check.confidence)}`);
  title.textContent = `${displayCheckTitle(check)} (${check.id})`;
  summary.textContent = `${displayCheckDescription(check)} ${targetSummary}${remediationText}`;
  viewer.textContent = (check.evidence && check.evidence.length)
    ? JSON.stringify(check.evidence, null, 2)
    : tr("这个发现项没有返回证据样本。", "This finding did not return evidence samples.");
}

function renderUninstallPanel() {
  const meta = document.getElementById("uninstallTaskMeta");
  const title = document.getElementById("uninstallTaskTitle");
  const summary = document.getElementById("uninstallTaskSummary");
  const bar = document.getElementById("uninstallTaskBar");
  const steps = document.getElementById("uninstallStepList");
  const logs = document.getElementById("uninstallLogList");
  const task = state.uninstallTask;

  if (!task) {
    meta.textContent = tr("当前没有进行中的卸载任务", "No uninstall task in progress");
    title.textContent = tr("从发现项或建议动作中选择一个可处置目标。", "Select a removable target from Findings or Recommended Actions.");
    summary.textContent = tr("卸载执行器会在这里持续显示后台任务进度、步骤和日志。", "The uninstall runner uses a background task and reports progress, steps, and logs here.");
    bar.style.width = "0%";
    steps.innerHTML = buildEmptyCard(tr("卸载任务启动后，这里会显示步骤。", "Removal steps will appear after an uninstall task starts."));
    logs.innerHTML = buildEmptyCard(tr("任务开始执行后，这里会持续显示日志。", "Task logs will stream here once execution begins."));
    return;
  }

  meta.textContent = `${getTaskStatusLabel(task.status)} / ${formatDate(task.updated_at)}`;
  title.textContent = `${task.target_name} (${task.target_type ? getTargetTypeLabel(task.target_type) : "--"})`;
  const durationText = task.duration_ms ? ` / ${formatDuration(task.duration_ms)}` : "";
  summary.textContent = `${buildTaskSummaryText(task)}${durationText}`;
  bar.style.width = `${task.progress || 0}%`;

  steps.innerHTML = (task.steps || []).map((step) => {
    const classes = ["step-item"];
    if (step.status === "running") {
      classes.push("is-active");
    }
    if (step.status === "completed") {
      classes.push("is-done");
    }
    return `
      <div class="${classes.join(" ")}">
        <strong>${escapeHtml(String(step.index).padStart(2, "0"))}</strong>
        <div>
          <span>${escapeHtml(getUninstallStepLabel(step.label || ""))}</span>
          <small>${escapeHtml(getStepStatusLabel(step.status))}${step.duration_ms ? ` / ${escapeHtml(formatDuration(step.duration_ms))}` : ""}</small>
        </div>
      </div>
    `;
  }).join("") || buildEmptyCard(tr("暂无可显示的步骤。", "No steps available."));

  logs.innerHTML = (task.logs && task.logs.length)
    ? task.logs.slice().reverse().map((entry) => `
        <div class="log-item log-${escapeHtml(entry.level || "info")}">
          <span>${escapeHtml(formatDate(entry.at))}</span>
          <strong>${escapeHtml(getLogLevelLabel(entry.level || "info"))}</strong>
          <p>${escapeHtml(translateLogMessage(entry.message || ""))}</p>
        </div>
      `).join("")
    : buildEmptyCard(tr("还没有任务日志。", "No task logs yet."));
}

function renderUninstallResult() {
  const meta = document.getElementById("uninstallResultMeta");
  const summary = document.getElementById("uninstallResultSummary");
  const viewer = document.getElementById("uninstallResultViewer");
  const result = state.uninstallResult || (isTerminalTask(state.uninstallTask) ? state.uninstallTask : null);

  if (!result) {
    meta.textContent = tr("尚未选择卸载结果", "No uninstall result selected");
    summary.textContent = tr("任务完成后，这里会显示已删除、已保留和残留项。", "Removed, preserved, and leftover items will appear here after a task finishes.");
    viewer.innerHTML = buildEmptyCard(tr("还没有已完成的卸载结果。", "No completed uninstall result yet."));
    return;
  }

  const removed = result.removed_items || [];
  const preserved = result.preserved_items || [];
  const leftovers = result.leftover_items || [];
  const blockedReasons = (result.result?.blocked_reasons || []).map((item) => translateAuditText(item));
  const manualSteps = (result.result?.manual_steps || []).map((item) => translateManualStep(item));
  const resultTarget = {
    ...(result.result || {}),
    name: result.target_name || result.result?.name,
    display_name: result.target_name || result.result?.display_name,
    support_level: result.result?.support_level || result.support_level,
  };
  meta.textContent = `${getTaskStatusLabel(result.status)} / ${formatDate(result.finished_at || result.updated_at)}${result.duration_ms ? ` / ${formatDuration(result.duration_ms)}` : ""}`;
  const manualReview = result.result?.manual_review_required || preserved.length > 0 || leftovers.length > 0 || blockedReasons.length > 0;
  summary.textContent = manualReview
    ? tr(`已删除 ${removed.length} 项，已保留 ${preserved.length} 项，残留 ${leftovers.length} 项。需要人工复核。`, `${removed.length} removed, ${preserved.length} preserved, ${leftovers.length} leftover. Manual review required.`)
    : tr(`已删除 ${removed.length} 项，已保留 ${preserved.length} 项，残留 ${leftovers.length} 项。`, `${removed.length} removed, ${preserved.length} preserved, ${leftovers.length} leftover.`);

  viewer.innerHTML = [
    buildResultMetrics(result),
    manualReview ? `<div class="result-banner">${escapeHtml(buildTaskSummaryText(result))}</div>` : "",
    result.result?.target_summary ? `<div class="result-note">${escapeHtml(buildTargetSummaryText(resultTarget))}</div>` : "",
    result.result?.rationale ? `<div class="result-note">${escapeHtml(buildTargetReasonText(resultTarget))}</div>` : "",
    buildStringResultGroup(tr("阻断原因", "Blocked Reasons"), blockedReasons),
    buildStringResultGroup(tr("人工步骤", "Manual Steps"), manualSteps),
    buildStepHistoryGroup(result.step_history || []),
    buildResultGroup(tr("已删除", "Removed"), removed),
    buildResultGroup(tr("已保留", "Preserved"), preserved),
    buildResultGroup(tr("残留", "Leftovers"), leftovers),
    buildLogDetails(result.logs || []),
  ].join("");
}

function buildResultMetrics(result) {
  const stats = [
    [tr("耗时", "Duration"), formatDuration(result.duration_ms)],
    [tr("已删除", "Removed"), String((result.removed_items || []).length)],
    [tr("已保留", "Preserved"), String((result.preserved_items || []).length)],
    [tr("残留", "Leftover"), String((result.leftover_items || []).length)],
  ];
  return `
    <div class="result-metric-grid">
      ${stats.map(([label, value]) => `
        <article class="summary-card compact-card result-metric-card">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </article>
      `).join("")}
    </div>
  `;
}

function buildStringResultGroup(title, items) {
  if (!items || !items.length) {
    return "";
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="panel-meta">${escapeHtml(tr(`${String(items.length)} 项`, `${String(items.length)} item(s)`))}</span>
      </div>
      ${items.map((item) => `
        <div class="result-item result-item-note">
          <strong>${escapeHtml(title)}</strong>
          <p>${escapeHtml(String(item || "--"))}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function buildStepHistoryGroup(stepHistory) {
  if (!stepHistory || !stepHistory.length) {
    return "";
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>${escapeHtml(tr("步骤回放", "Step History"))}</strong>
        <span class="panel-meta">${escapeHtml(tr(`${String(stepHistory.length)} 步`, `${String(stepHistory.length)} step(s)`))}</span>
      </div>
      ${stepHistory.map((step) => `
        <div class="result-item result-item-note">
          <strong>${escapeHtml(String(step.index).padStart(2, "0"))} / ${escapeHtml(getUninstallStepLabel(step.label || ""))}</strong>
          <span>${escapeHtml(getStepStatusLabel(step.status || "unknown"))}${step.duration_ms ? ` / ${escapeHtml(formatDuration(step.duration_ms))}` : ""}</span>
          <p>${escapeHtml(`${formatDate(step.started_at)} -> ${formatDate(step.finished_at)}`)}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function buildLogDetails(logs) {
  if (!logs || !logs.length) {
    return "";
  }
  return `
    <details class="result-details">
      <summary>${escapeHtml(tr("执行日志", "Execution logs"))}</summary>
      <div class="log-list">
        ${logs.slice().reverse().map((entry) => `
          <div class="log-item log-${escapeHtml(entry.level || "info")}">
            <span>${escapeHtml(formatDate(entry.at))}</span>
            <strong>${escapeHtml(getLogLevelLabel(entry.level || "info"))}</strong>
            <p>${escapeHtml(translateLogMessage(entry.message || ""))}</p>
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

function buildResultGroup(title, items) {
  if (!items.length) {
    return `
      <div class="result-group">
        <div class="subsection-head">
          <strong>${escapeHtml(title)}</strong>
          <span class="panel-meta">${escapeHtml(tr("0 项", "0 item"))}</span>
        </div>
        ${buildEmptyCard(tr(`没有记录到${title}。`, `No ${title.toLowerCase()} recorded.`))}
      </div>
    `;
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="panel-meta">${escapeHtml(tr(`${String(items.length)} 项`, `${String(items.length)} item(s)`))}</span>
      </div>
      ${items.map((item) => `
        <div class="result-item">
          <strong>${escapeHtml(getResultItemTypeLabel(item.type || "item"))}</strong>
          <span>${escapeHtml(item.value || item.label || "--")}</span>
          <p>${escapeHtml(translateAuditText(item.detail || item.reason || "--"))}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function syncButtonState() {
  const running = state.currentJob && ["queued", "running"].includes(state.currentJob.status);
  const button = document.getElementById("startScanBtn");
  if (PUBLIC_SITE_MODE) {
    button.disabled = !hasDownloadAsset();
    button.textContent = hasDownloadAsset() ? tr("下载 Windows 客户端", "Download Windows Client") : tr("发布包缺失", "Release Package Missing");
    return;
  }
  button.disabled = Boolean(running);
  button.textContent = running ? tr("扫描进行中", "Scan Running") : tr("开始真实扫描", "Start Real Scan");
}

function renderEmptyState() {
  renderConsoleHeader(null);
  syncButtonState();
  syncOperationPanel(null);
  renderExecutiveSummary(null);
  renderProgress({ status: "queued", stage_key: "queued", progress: 0, stage_history: [] });
  renderArtifacts(null);
  renderRuntime(null);
  renderSafetyNotes(null);
  renderHistory();
  renderDomainPortfolio(null);
  renderFindings(null);
  renderEvidencePanel(null);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
  renderDownloadPanel();
  renderModal();
}

function renderPublicSiteMode() {
  renderConsoleHeader(null);
  document.title = hasDownloadAsset()
    ? tr("Police Claw Windows 客户端下载", "Police Claw Windows Client Download")
    : tr("Police Claw 发布包待就绪", "Police Claw Release Package Pending");
  setGlobalNotice(
    hasDownloadAsset() ? "info" : "warn",
    hasDownloadAsset() ? tr("下载 Windows 客户端", "Download the Windows client") : tr("安装包暂不可用", "Installer package not available"),
    hasDownloadAsset()
      ? tr("当前站点直接分发安装包。真实扫描和卸载仍然只会在客户端安装后于本机执行。", "The hosted site distributes the installer directly. Real scan and uninstall actions still run locally after the client is installed.")
      : tr("请先构建 dist/release/PoliceClaw-Setup-<version>.exe，网站下载入口才会生效。", "Build dist/release/PoliceClaw-Setup-<version>.exe to enable direct website downloads.")
  );
  renderExecutiveSummary(null);
  renderDownloadPanel();
  decorateConsoleSurface(null);
}

function renderGlobalNotice() {
  const node = document.getElementById("globalNotice");
  const notice = state.notice;
  if (!notice) {
    node.className = "inline-notice is-hidden";
    node.innerHTML = "";
    return;
  }
  node.className = `inline-notice notice-${escapeHtml(notice.tone || "info")}`;
  node.innerHTML = `
    <strong>${escapeHtml(notice.title || tr("提示", "Notice"))}</strong>
    <p>${escapeHtml(notice.message || "")}</p>
  `;
}

function setGlobalNotice(tone, title, message) {
  state.notice = {
    tone: tone || "info",
    title: title || tr("提示", "Notice"),
    message: message || "",
  };
  renderGlobalNotice();
}

function clearGlobalNotice() {
  state.notice = null;
  renderGlobalNotice();
}

function renderGlobalError(message, title = tr("工作台错误", "Workbench Error")) {
  setGlobalNotice("error", title, message);
}

function onHistoryClick(event) {
  const card = event.target.closest("[data-job-id]");
  if (!card) {
    return;
  }

  stopPolling();
  loadJob(card.dataset.jobId)
    .then(async () => {
      await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
      if (["queued", "running"].includes(state.currentJob?.status)) {
        startPolling(card.dataset.jobId);
      }
      loadJobs().catch(() => {});
    })
    .catch((error) => renderGlobalError(error.message));
}

function onUninstallHistoryClick(event) {
  const card = event.target.closest("[data-uninstall-id]");
  if (!card) {
    return;
  }

  stopUninstallPolling();
  loadUninstallTask(card.dataset.uninstallId)
    .then(async () => {
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      } else {
        startUninstallPolling(state.uninstallTask.id);
      }
    })
    .catch((error) => renderGlobalError(error.message));
}

function onDomainClick(event) {
  const button = event.target.closest("[data-domain-filter]");
  if (!button) {
    return;
  }

  state.filters.domain = state.filters.domain === button.dataset.domainFilter
    ? "all"
    : button.dataset.domainFilter;
  document.getElementById("domainFilter").value = state.filters.domain;
  renderDomainPortfolio(state.currentJob);
  renderFindings(state.currentJob);
}

function onFindingClick(event) {
  const action = event.target.closest("[data-uninstall-action]");
  if (action) {
    const target = findTargetById(action.dataset.targetId);
    if (!target) {
      return;
    }
    if (action.dataset.uninstallAction === "scope") {
      focusTargetScope(target.id);
    } else {
      openUninstallModal(target.id);
    }
    return;
  }

  const row = event.target.closest("[data-check-id]");
  if (!row || !state.currentJob?.report) {
    return;
  }

  state.selectedCheckId = row.dataset.checkId;
  renderFindings(state.currentJob);
  renderEvidencePanel(state.currentJob);
}

function onTargetActionClick(event) {
  const button = event.target.closest("[data-target-action]");
  if (!button) {
    return;
  }
  if (button.dataset.targetAction === "scope") {
    focusTargetScope(button.dataset.targetId);
  } else {
    openUninstallModal(button.dataset.targetId);
  }
}

function onFilterChange() {
  state.filters.search = document.getElementById("findingsSearch").value.trim();
  state.filters.domain = document.getElementById("domainFilter").value;
  state.filters.status = document.getElementById("statusFilter").value;
  state.filters.sort = document.getElementById("sortFilter").value;
  renderDomainPortfolio(state.currentJob);
  renderFindings(state.currentJob);
}

function onModalShellClick(event) {
  if (event.target.closest("[data-modal-close='true']")) {
    closeUninstallModal();
  }
}

function onModalInputChange() {
  state.uninstallModalState.mode = document.getElementById("uninstallMode").value;
  state.uninstallModalState.remove_startup = document.getElementById("removeStartupToggle").checked;
  state.uninstallModalState.remove_cache = document.getElementById("removeCacheToggle").checked;
  state.uninstallModalState.remove_config = document.getElementById("removeConfigToggle").checked;
  state.uninstallModalState.remove_binary = document.getElementById("removeBinaryToggle").checked;
  state.uninstallModalState.confirmation_text = document.getElementById("confirmationText").value.trim();
  state.uninstallModalState.error = "";
  renderModal();
}

function openUninstallModal(targetId) {
  const target = findTargetById(targetId);
  if (!target) {
    return;
  }
  state.uninstallModalState = {
    open: true,
    targetId,
    mode: "standard",
    remove_startup: Boolean(target.startup_entries?.length),
    remove_cache: Boolean(target.cache_paths?.length),
    remove_config: Boolean(target.config_paths?.length),
    remove_binary: Boolean(target.remove_binary_allowed),
    confirmation_text: "",
    error: target.uninstall_supported ? "" : (target.unsupported_reason || tr("这个目标当前不适合自动卸载。", "Target is not safe to uninstall.")),
  };
  renderModal();
}

function focusTargetScope(targetId) {
  const target = findTargetById(targetId);
  if (!target) {
    return;
  }
  const nextCheckId = (target.matched_check_ids || []).find((checkId) =>
    state.currentJob?.report?.checks?.some((check) => check.id === checkId)
  );
  if (nextCheckId) {
    state.selectedCheckId = nextCheckId;
    renderFindings(state.currentJob);
    renderEvidencePanel(state.currentJob);
  }
  const relatedTask = getTaskForTarget(target);
  if (relatedTask) {
    state.uninstallTask = relatedTask;
    renderUninstallPanel();
    if (isTerminalTask(relatedTask)) {
      loadUninstallResult(relatedTask.id).catch((error) => renderGlobalError(error.message));
    } else if (!state.uninstallPollingTaskId || state.uninstallPollingTaskId !== relatedTask.id) {
      startUninstallPolling(relatedTask.id);
    }
  }
}

function closeUninstallModal() {
  state.uninstallModalState = buildModalState();
  renderModal();
}

function renderModal() {
  const modal = document.getElementById("uninstallModal");
  const target = findTargetById(state.uninstallModalState.targetId);
  const submitBtn = document.getElementById("uninstallSubmitBtn");
  const errorNode = document.getElementById("uninstallModalError");

  modal.classList.toggle("is-hidden", !state.uninstallModalState.open);
  modal.setAttribute("aria-hidden", String(!state.uninstallModalState.open));

  document.getElementById("uninstallModalTarget").textContent = target ? getTargetName(target) : "--";
  document.getElementById("uninstallModalRisk").textContent = target
    ? tr(`${getRiskLevelLabel(target.risk_level)} / ${target.risk_score} / 命中 ${target.matched_findings_count} 条发现 / 置信度 ${formatPercent(target.confidence || 0)}`, `${getRiskLevelLabel(target.risk_level)} / ${target.risk_score} / ${target.matched_findings_count} matched findings / ${formatPercent(target.confidence || 0)} confidence`)
    : tr("风险 --", "Risk --");
  document.getElementById("uninstallModalReason").textContent = target?.uninstall_supported
    ? buildTargetActionHint(target)
    : (target ? buildBlockedReasonDetail(target.blocked_reason_code) : tr("请选择一个目标查看处置范围。", "Select a target to review scope."));

  document.getElementById("uninstallMode").value = state.uninstallModalState.mode;
  document.getElementById("removeStartupToggle").checked = Boolean(state.uninstallModalState.remove_startup);
  document.getElementById("removeCacheToggle").checked = Boolean(state.uninstallModalState.remove_cache);
  document.getElementById("removeConfigToggle").checked = Boolean(state.uninstallModalState.remove_config);
  document.getElementById("removeBinaryToggle").checked = Boolean(state.uninstallModalState.remove_binary);
  document.getElementById("removeBinaryToggle").disabled = Boolean(target && !target.remove_binary_allowed);
  document.getElementById("confirmationText").value = state.uninstallModalState.confirmation_text;

  document.getElementById("uninstallScopeList").innerHTML = target
    ? buildTargetScopeCards(target)
    : buildEmptyCard(tr("尚未选择目标。", "No target selected."));

  const canSubmit = Boolean(
    state.uninstallModalState.open &&
    target &&
    target.uninstall_supported &&
    state.uninstallModalState.confirmation_text === UNINSTALL_CONFIRMATION_TEXT
  );
  submitBtn.disabled = !canSubmit;
  errorNode.textContent = state.uninstallModalState.error || "";
}

function buildTargetScopeCards(target) {
  const cards = [
    {
      title: tr("处置策略", "Disposition"),
      count: target.planned_actions?.length || 0,
      body: target.planned_actions?.length
        ? `${target.planned_actions.map((action) => getPlannedActionLabel(action)).join(" | ")} | ${buildTargetReasonText(target)}`
        : buildTargetReasonText(target),
    },
    {
      title: tr("终止进程", "Terminate processes"),
      count: target.pids?.length || 0,
      body: target.pids?.length ? target.pids.join(", ") : tr("没有关联的活动进程。", "No linked active process."),
    },
    {
      title: tr("移除启动项", "Remove startup entries"),
      count: target.startup_entries?.length || 0,
      body: target.startup_entries?.length
        ? target.startup_entries.map((entry) => `${getStartupKindLabel(entry.kind)}: ${entry.label}`).join(" | ")
        : tr("没有发现用户级持久化项。", "No user-level persistence discovered."),
    },
    {
      title: tr("移除配置", "Remove config"),
      count: target.config_paths?.length || 0,
      body: target.config_paths?.length ? target.config_paths.join(" | ") : tr("没有明确的配置路径。", "No explicit config path."),
    },
    {
      title: tr("移除缓存", "Remove cache"),
      count: target.cache_paths?.length || 0,
      body: target.cache_paths?.length ? target.cache_paths.join(" | ") : tr("没有明确的缓存路径。", "No explicit cache path."),
    },
    {
      title: tr("移除程序文件", "Remove binaries"),
      count: target.executable_paths?.length || 0,
      body: target.remove_binary_allowed
        ? (target.executable_paths?.length ? target.executable_paths.join(" | ") : tr("没有明确的程序文件。", "No explicit binary file."))
        : (target.remove_binary_reason || tr("程序路径会保留给人工复核。", "Binary path will be preserved for manual review.")),
    },
  ];

  return cards.map((card) => `
    <article class="target-card">
      <div class="target-card-head">
        <div>
          <strong>${escapeHtml(card.title)}</strong>
          <span>${escapeHtml(tr(`${String(card.count)} 项`, `${String(card.count)} item(s)`))}</span>
        </div>
      </div>
      <div class="target-card-body">
        <div>${escapeHtml(card.body)}</div>
      </div>
    </article>
  `).join("");
}

async function submitUninstall() {
  const target = findTargetById(state.uninstallModalState.targetId);
  if (!target) {
    return;
  }
  if (state.uninstallModalState.confirmation_text !== UNINSTALL_CONFIRMATION_TEXT) {
    state.uninstallModalState.error = tr("确认文本不匹配。", "Confirmation text does not match.");
    renderModal();
    return;
  }

  try {
    clearGlobalNotice();
    const task = await requestJson(
      "/api/uninstall",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: target.id,
          mode: state.uninstallModalState.mode,
          job_id: state.uninstallSourceJobId,
          remove_startup: state.uninstallModalState.remove_startup,
          remove_cache: state.uninstallModalState.remove_cache,
          remove_config: state.uninstallModalState.remove_config,
          remove_binary: state.uninstallModalState.remove_binary,
          confirmation_text: state.uninstallModalState.confirmation_text,
        }),
      },
      tr("无法创建卸载任务。", "Unable to create the uninstall task."),
    );
    closeUninstallModal();
    state.uninstallTask = task;
    state.uninstallResult = null;
    renderUninstallPanel();
    startUninstallPolling(task.id);
    await Promise.all([loadUninstallHistory(), fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob))]);
  } catch (error) {
    state.uninstallModalState.error = error.message;
    renderGlobalError(error.message, tr("卸载请求失败", "Uninstall request failed"));
    renderModal();
  }
}

function getSelectedCheck(job) {
  const checks = job?.report?.checks || [];
  return checks.find((check) => check.id === state.selectedCheckId) || null;
}

function ensureSelectedCheck(job) {
  const checks = job?.report?.checks || [];
  if (!checks.length) {
    state.selectedCheckId = null;
    return;
  }
  if (checks.some((check) => check.id === state.selectedCheckId)) {
    return;
  }
  const topRisk = [...checks]
    .filter((check) => isFlagged(check))
    .sort((left, right) => right.risk_score - left.risk_score)[0];
  state.selectedCheckId = (topRisk || checks[0]).id;
}

function getRelatedTargets(checkId) {
  return getRenderableUninstallTargets().filter((target) => (target.matched_check_ids || []).includes(checkId));
}

function pickPrimaryTarget(targets) {
  if (!targets.length) {
    return null;
  }
  return [...targets].sort((left, right) => {
    const leftRank = getTargetPriority(left);
    const rightRank = getTargetPriority(right);
    return leftRank - rightRank || right.risk_score - left.risk_score || right.confidence - left.confidence;
  })[0];
}

function findTargetById(targetId) {
  return state.uninstallTargets.find((target) => target.id === targetId) || null;
}

function applyFindingFilters(checks) {
  const filtered = checks.filter((check) => {
    const searchFields = [
      check.id,
      check.label,
      check.description,
      displayCheckTitle(check),
      displayCheckDescription(check),
      check.domain,
      check.domain_name,
      getCheckDomainLabel(check),
    ];
    const matchesSearch = !state.filters.search || searchFields.some((field) =>
      String(field || "").toLowerCase().includes(state.filters.search.toLowerCase())
    );
    const matchesDomain = state.filters.domain === "all" || check.domain === state.filters.domain;
    const matchesStatus = (
      state.filters.status === "all" ||
      (state.filters.status === "risk" && isFlagged(check)) ||
      (state.filters.status === "clear" && !isFlagged(check)) ||
      (state.filters.status === "evidence" && Number(check.evidence_count || 0) > 0)
    );
    return matchesSearch && matchesDomain && matchesStatus;
  });

  return filtered.sort((left, right) => {
    if (state.filters.sort === "evidence") {
      return (right.evidence_count || 0) - (left.evidence_count || 0) || right.risk_score - left.risk_score;
    }
    if (state.filters.sort === "domain") {
      return getCheckDomainLabel(left).localeCompare(getCheckDomainLabel(right), getLanguageLocale()) ||
        right.risk_score - left.risk_score;
    }
    if (state.filters.sort === "name") {
      return displayCheckTitle(left).localeCompare(displayCheckTitle(right), getLanguageLocale());
    }
    return right.risk_score - left.risk_score || (right.evidence_count || 0) - (left.evidence_count || 0);
  });
}

function syncDomainFilterOptions(domains) {
  const select = document.getElementById("domainFilter");
  const current = state.filters.domain;
  const options = [`<option value="all">${escapeHtml(tr("全部安全域", "All Domains"))}</option>`].concat(
    domains.map((domain) => `<option value="${domain.id}">${escapeHtml(getDomainLabel(domain.id, domain.name))}</option>`)
  );
  select.innerHTML = options.join("");
  select.value = domains.some((domain) => domain.id === current) || current === "all" ? current : "all";
  state.filters.domain = select.value;
}

function getDomainEntries(report) {
  const checks = report.checks || [];
  return Object.entries(report.summary.domain_summary || {}).map(([id, summary]) => ({
    id,
    ...summary,
    name: getDomainLabel(id, summary.name),
    checks: checks.filter((check) => check.domain === id),
  }));
}

function getPosture(report) {
  const visibleTargets = getRenderableUninstallTargets();
  const autoRemediableTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const handledTargets = autoRemediableTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });
  const blockedHighRisk = visibleTargets.filter((target) => !target.uninstall_supported && Number(target.risk_score || 0) >= HIGH_RISK_THRESHOLD);
  const manualReviewTargets = visibleTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "partial" || remediation.status === "manual-review";
  });

  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length && !blockedHighRisk.length && !manualReviewTargets.length) {
    return {
      label: tr("已处置", "Remediated"),
      headline: tr("当前所有可直接处置的高风险目标都已完成卸载处理。", "All currently supported high-risk targets have completed uninstall handling."),
      badgeClass: "badge-good",
    };
  }
  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length && (blockedHighRisk.length || manualReviewTargets.length)) {
    return {
      label: tr("待人工复核", "Manual Review"),
      headline: tr("自动处置已经完成，但残留复核或受限目标仍需要人工跟进。", "Auto-remediation is complete, but residual review or blocked targets still need manual follow-up."),
      badgeClass: "badge-warn",
    };
  }

  const totalRisks = report.summary?.total_risks || 0;
  const maxRisk = report.summary?.max_risk_score || 0;
  if (totalRisks === 0) {
    return {
      label: tr("稳定", "Stable"),
      headline: tr("最新报告中没有发现高置信度风险热点。", "No high-confidence risk hotspots were detected in the latest report."),
      badgeClass: "badge-good",
    };
  }
  if (totalRisks <= 6 && maxRisk < 70) {
    return {
      label: tr("可控", "Contained"),
      headline: tr("仍有少量发现项，但整体态势处于可控范围。", "A small number of findings remain, but the overall posture is controlled."),
      badgeClass: "badge-warn",
    };
  }
  if (totalRisks <= 12) {
    return {
      label: tr("升级关注", "Escalated"),
      headline: tr("风险集中程度已经需要正式复核和处置。", "Risk exposure is concentrated enough to require formal review and action."),
      badgeClass: "badge-warn",
    };
  }
  return {
    label: tr("高压态势", "High Pressure"),
    headline: tr("最新报告显示高风险发现项高度集中。", "The latest report shows a dense concentration of high-risk findings."),
    badgeClass: "badge-risk",
  };
}

function buildNarrative(report) {
  const domains = getDomainEntries(report)
    .sort((left, right) => right.risks - left.risks || right.max_score - left.max_score);
  const topDomain = domains[0];
  const activeSignals = report.runtime?.result_overview?.active_signals ?? "--";
  const visibleTargets = getRenderableUninstallTargets();
  const targetLine = visibleTargets.length
    ? tr(` 后端为这份报告推导出了 ${visibleTargets.length} 个可处置目标。`, ` The backend inferred ${visibleTargets.length} uninstall target(s) for this report.`)
    : state.uninstallTargets.length && state.uninstallSourceScanId
      ? tr(` 当前卸载目标来自已完成的扫描 ${state.uninstallSourceScanId}。`, ` Uninstall targets are currently sourced from completed scan ${state.uninstallSourceScanId}.`)
    : "";
  if (!topDomain) {
    return tr(`本次扫描覆盖 ${report.summary.total_checks} 个检查项，未形成明显风险聚类。${targetLine}`, `The scan covered ${report.summary.total_checks} checks and did not form a material risk cluster.${targetLine}`);
  }
  return tr(
    `最近一次扫描于 ${report.timestamp} 在 ${report.host} 上运行，共覆盖 ${report.summary.total_checks} 个检查项，标记 ${report.summary.total_risks} 条风险发现，并触发 ${activeSignals} 个运行时信号。当前最热的安全域是 ${safeText(topDomain.name, humanizeSlug(topDomain.id))}，其中有 ${topDomain.risks} 条风险发现，峰值分数为 ${topDomain.max_score}。${targetLine}`,
    `The latest scan ran on ${report.host} at ${report.timestamp}. It covered ${report.summary.total_checks} checks, flagged ${report.summary.total_risks} findings, and activated ${activeSignals} runtime signals. The hottest domain is ${safeText(topDomain.name, humanizeSlug(topDomain.id))} with ${topDomain.risks} flagged finding(s) and a peak score of ${topDomain.max_score}.${targetLine}`,
  );
}

function buildRecommendations(report) {
  const flaggedChecks = [...(report.checks || [])]
    .filter((check) => isFlagged(check))
    .sort((left, right) => right.risk_score - left.risk_score || (right.evidence_count || 0) - (left.evidence_count || 0));
  const visibleTargets = getRenderableUninstallTargets();
  const urgentTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "full" && getRemediationStateForTarget(target).status === "ready");
  const cleanupTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "cleanup" && getRemediationStateForTarget(target).status === "ready");
  const terminateTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "terminate_only" && getRemediationStateForTarget(target).status === "ready");
  const partialTargets = visibleTargets.filter((target) => getRemediationStateForTarget(target).status === "partial");
  const blockedTargets = visibleTargets.filter((target) => !target.uninstall_supported && Number(target.risk_score || 0) >= HIGH_RISK_THRESHOLD);
  const autoRemediableTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const handledTargets = autoRemediableTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });

  if (!flaggedChecks.length) {
    return [
      {
        tag: tr("基线", "Baseline"),
        tone: "neutral",
        title: tr("归档基线报告", "Archive the baseline report"),
        body: tr("没有剩余的显著发现项。请保留 JSON 或 DOCX 导出作为当前工作站基线。", "No significant findings remain. Keep the JSON or DOCX export as the current workstation baseline."),
      },
      {
        tag: tr("节奏", "Cadence"),
        tone: "neutral",
        title: tr("保持复查频率", "Keep the cadence"),
        body: tr("在环境或工具链发生明显变化后，重新执行同样的扫描流程。", "Run the same scan flow again after meaningful environment or tooling changes."),
      },
    ];
  }

  const recommendations = [];
  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length) {
    recommendations.push({
      tag: blockedTargets.length || partialTargets.length ? tr("仍需复核", "Review Remaining") : tr("已完成", "Complete"),
      tone: blockedTargets.length || partialTargets.length ? "warn" : "good",
      title: tr("高优先级处置已完成", "High-priority remediation is complete"),
      body: blockedTargets.length || partialTargets.length
        ? tr("所有可直接支持的目标都已处理。关闭报告前，请复核残留项和受限目标。", "All directly supported targets were processed. Review residual items and blocked targets before closing the report.")
        : tr("这份报告中当前所有支持自动处置的目标都已处理完成。请复核残留说明并导出审计记录。", "All currently supported removable targets for this report have been handled. Review residual notes and export the audit trail."),
    });
  }
  if (urgentTargets[0]) {
    recommendations.push({
      tag: tr("优先卸载", "Urgent uninstall"),
      tone: "risk",
      title: tr(`优先处置 ${getTargetName(urgentTargets[0])}`, `Review ${getTargetName(urgentTargets[0])} first`),
      body: buildTargetSummaryText(urgentTargets[0]),
    });
  }
  if (cleanupTargets[0]) {
    recommendations.push({
      tag: tr("可清理", "Cleanup available"),
      tone: "warn",
      title: tr(`清理 ${getTargetName(cleanupTargets[0])} 的残留`, `Clean residual footprint for ${getTargetName(cleanupTargets[0])}`),
      body: buildTargetReasonText(cleanupTargets[0]),
    });
  }
  if (terminateTargets[0]) {
    recommendations.push({
      tag: tr("仅遏制", "Terminate only"),
      tone: "neutral",
      title: tr(`遏制 ${getTargetName(terminateTargets[0])}`, `Contain ${getTargetName(terminateTargets[0])}`),
      body: buildTargetReasonText(terminateTargets[0]),
    });
  }
  if (partialTargets[0]) {
    recommendations.push({
      tag: tr("人工复核", "Manual review"),
      tone: "warn",
      title: tr(`完成 ${partialTargets[0].display_name || partialTargets[0].name} 的人工复核`, `Finish manual review for ${partialTargets[0].display_name || partialTargets[0].name}`),
      body: tr("之前的卸载执行保留或遗留了部分项目。再次运行前，请先检查残留复核面板。", "A previous uninstall run preserved or left behind some items. Review the residual panel before rerunning anything."),
    });
  }
  if (blockedTargets[0]) {
    recommendations.push({
      tag: tr("受限", "Blocked"),
      tone: "risk",
      title: tr(`复核受限目标 ${getTargetName(blockedTargets[0])}`, `Review blocked target ${getTargetName(blockedTargets[0])}`),
      body: buildTargetReasonText(blockedTargets[0]),
    });
  }
  if (flaggedChecks[0]) {
    recommendations.push({
      tag: tr("核验", "Validate"),
      tone: "neutral",
      title: tr(`核验 ${displayCheckTitle(flaggedChecks[0])}`, `Validate ${displayCheckTitle(flaggedChecks[0])}`),
      body: tr("先从最高优先级的发现项开始，确认相关证据，再决定使用卸载流程还是人工遏制。", "Start with the top finding, confirm the evidence, and then decide whether to use the uninstall flow or manual containment."),
    });
  }
  if (!visibleTargets.length || urgentTargets.length || cleanupTargets.length || blockedTargets.length) {
    recommendations.push({
      tag: tr("审计", "Audit"),
      tone: "neutral",
      title: tr("导出处置链路", "Export the report trail"),
      body: tr("请把 JSON 或 DOCX 报告与卸载任务日志一起保留，确保处置路径可审计。", "Keep the JSON or DOCX report with the uninstall task logs so the containment path remains auditable."),
    });
  }
  return recommendations.slice(0, 4);
}

function renderUninstallRecommendations(report) {
  return buildRecommendations(report);
}

function getRequestedUninstallJobId(job) {
  if (!job || job.status !== "completed") {
    return null;
  }
  return job.id;
}

function getRenderableUninstallTargets(job = state.currentJob) {
  if (!state.uninstallTargets.length) {
    return [];
  }
  if (!job) {
    return state.uninstallTargets;
  }
  if (job.status === "completed" && state.uninstallSourceJobId !== job.id) {
    return [];
  }
  return state.uninstallTargets;
}

function getCurrentUninstallScope(job = state.currentJob) {
  if (job?.status === "completed") {
    return {
      jobId: job.id,
      scanId: job.report?.scan_id || job.scan_id || null,
    };
  }
  return {
    jobId: state.uninstallSourceJobId,
    scanId: state.uninstallSourceScanId,
  };
}

function taskMatchesSource(task, scope = getCurrentUninstallScope()) {
  if (!task) {
    return false;
  }
  if (!scope.jobId && !scope.scanId) {
    return true;
  }
  if (scope.jobId && task.source_job_id) {
    return task.source_job_id === scope.jobId;
  }
  if (scope.scanId && task.source_scan_id) {
    return task.source_scan_id === scope.scanId;
  }
  return true;
}

function getScopedUninstallHistory(job = state.currentJob) {
  const scope = getCurrentUninstallScope(job);
  return state.uninstallHistory.filter((task) => taskMatchesSource(task, scope));
}

function getRemediationStateForTarget(target) {
  const task = getTaskForTarget(target);
  if (task) {
    if (task.status === "success") {
      return target.support_level === "full"
        ? { status: "removed", label: tr("已移除", "Removed"), detail: tr("目标卸载已经完成。", "Target uninstall completed.") }
        : { status: "mitigated", label: tr("已缓解", "Mitigated"), detail: tr("受控清理或遏制已完成。", "Controlled cleanup or containment completed.") };
    }
    if (task.status === "partial") {
      return { status: "partial", label: tr("部分完成", "Partial"), detail: tr("仍然需要进行残留复核。", "Residual review is still required.") };
    }
    if (task.status === "failed") {
      return { status: "manual-review", label: tr("人工复核", "Manual Review"), detail: tr("最近一次卸载执行失败，需要人工复核。", "The last uninstall run failed and needs review.") };
    }
    if (["pending", "running"].includes(task.status)) {
      return { status: "running", label: tr("进行中", "In Progress"), detail: tr("处置任务正在执行中。", "Removal task is currently active.") };
    }
  }
  if (target.resolved || state.removedTargetIds.has(target.id)) {
    return target.support_level === "full"
      ? { status: "removed", label: tr("已移除", "Removed"), detail: tr("关联目标已经完成卸载处理。", "Linked target completed uninstall handling.") }
      : { status: "mitigated", label: tr("已缓解", "Mitigated"), detail: tr("关联目标已经完成受控清理或遏制。", "Linked target received controlled cleanup or containment.") };
  }
  if (!target.uninstall_supported) {
    if (MANUAL_REVIEW_BLOCK_CODES.has(target.blocked_reason_code)) {
      return { status: "manual-review", label: tr("人工复核", "Manual Review"), detail: buildBlockedReasonDetail(target.blocked_reason_code) };
    }
    return { status: "blocked", label: tr("受限", "Blocked"), detail: buildBlockedReasonDetail(target.blocked_reason_code) };
  }
  return { status: "ready", label: "", detail: "" };
}

function refreshRemovedTargetIds() {
  const resolvedIds = state.uninstallTargets
    .filter((target) => target.resolved)
    .map((target) => target.id);
  const historyIds = getScopedUninstallHistory()
    .filter((task) => task.status === "success")
    .map((task) => task.target_id);
  state.removedTargetIds = new Set([...resolvedIds, ...historyIds]);
}

function getTargetPriority(target) {
  const remediation = getRemediationStateForTarget(target);
  if (remediation.status === "running") {
    return 0;
  }
  if (target.support_level === "full" && remediation.status === "ready") {
    return 1;
  }
  if (target.support_level === "cleanup" && remediation.status === "ready") {
    return 2;
  }
  if (target.support_level === "terminate_only" && remediation.status === "ready") {
    return 3;
  }
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return 4;
  }
  if (remediation.status === "partial") {
    return 5;
  }
  if (remediation.status === "manual-review") {
    return 6;
  }
  if (!target.uninstall_supported) {
    return 7;
  }
  return 8;
}

function getTaskForTarget(target) {
  if (!target) {
    return null;
  }
  const scopedHistory = getScopedUninstallHistory();
  const direct = scopedHistory.find((task) => task.target_id === target.id);
  if (direct) {
    return direct;
  }
  return scopedHistory.find((task) => task.target_name === (target.display_name || target.name)) || null;
}

function markRelatedFindingsHandled(checkId) {
  const relatedTargets = getRelatedTargets(checkId);
  if (!relatedTargets.length) {
    return { status: "none", label: "", detail: "" };
  }
  const remediations = relatedTargets.map((target) => getRemediationStateForTarget(target));
  if (remediations.some((item) => item.status === "running")) {
    return { status: "running", label: tr("进行中", "In Progress"), detail: tr("处置任务正在执行中。", "Removal task is currently active.") };
  }
  if (remediations.some((item) => item.status === "partial")) {
    return { status: "partial", label: tr("部分完成", "Partial"), detail: tr("之前的一次卸载执行仍需要人工跟进。", "A previous uninstall pass needs manual follow-up.") };
  }
  if (remediations.some((item) => item.status === "manual-review")) {
    return { status: "manual-review", label: tr("人工复核", "Manual Review"), detail: tr("这个发现项只剩人工跟进。", "Only manual follow-up remains for this finding.") };
  }
  if (remediations.some((item) => item.status === "removed")) {
    return { status: "removed", label: tr("已移除", "Removed"), detail: tr("关联目标已经完成卸载处理。", "Linked target completed uninstall handling.") };
  }
  if (remediations.some((item) => item.status === "mitigated")) {
    return { status: "mitigated", label: tr("已缓解", "Mitigated"), detail: tr("关联目标已经完成受控清理或遏制。", "Linked target received controlled cleanup or containment.") };
  }
  if (relatedTargets.every((target) => !target.uninstall_supported)) {
    return { status: "blocked", label: tr("受限", "Blocked"), detail: tr("这个发现项只推导出了受限目标。", "Only blocked targets were inferred for this finding.") };
  }
  return { status: "ready", label: "", detail: "" };
}

function isFlagged(check) {
  return Number(check?.risk_score || 0) > 0;
}

function isTerminalTask(task) {
  return Boolean(task) && TASK_TERMINAL_STATUSES.has(task.status);
}

function displayCheckTitle(check) {
  const entry = getCheckTranslation(check);
  if (entry) {
    return tr(entry.zhTitle, entry.enTitle);
  }
  return safeText(check.label, humanizeSlug(check.id));
}

function displayCheckDescription(check) {
  return safeText(check.description, tr(`检查标识：${check.id}`, `Check identifier: ${check.id}`));
}

function getDomainLabel(domainId, rawName) {
  const entry = DOMAIN_TRANSLATIONS[String(domainId || "").trim().toLowerCase()];
  if (entry) {
    return tr(entry.zh, entry.en);
  }
  return safeText(rawName, humanizeSlug(domainId));
}

function getCheckTranslation(check) {
  return CHECK_TRANSLATIONS[String(check?.id || "").trim()] || null;
}

function getCheckDomainLabel(check) {
  return getDomainLabel(check?.domain, check?.domain_name);
}

function displayCheckDescription(check) {
  const entry = getCheckTranslation(check);
  if (entry) {
    return tr(entry.zhDescription, entry.enDescription);
  }
  return safeText(check.description, `Check ${check.id}`);
}

function getStageLabel(stageKey, stageLabel) {
  const stage = STAGES.find((item) => item.key === stageKey);
  if (stage) {
    return tr(stage.zh, stage.en);
  }
  return safeText(stageLabel, tr("排队中", "Queued"));
}

function safeText(value, fallback) {
  const text = String(value || "").trim();
  if (!text) {
    return fallback;
  }
  return looksBrokenText(text) ? fallback : text;
}

function looksBrokenText(text) {
  return /[�鈥馃锛€]/.test(text);
}

function humanizeSlug(value) {
  return String(value || "")
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatPercent(value) {
  const numeric = Number(value || 0);
  return `${Math.round(numeric * 100)}%`;
}

function formatFileSize(value) {
  const numeric = Number(value || 0);
  if (!numeric) {
    return "--";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = numeric;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = unitIndex === 0 ? 0 : size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function compareVersions(left, right) {
  const leftParts = String(left || "0").split(".").map((part) => Number(part || 0));
  const rightParts = String(right || "0").split(".").map((part) => Number(part || 0));
  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const leftValue = leftParts[index] || 0;
    const rightValue = rightParts[index] || 0;
    if (leftValue > rightValue) {
      return 1;
    }
    if (leftValue < rightValue) {
      return -1;
    }
  }
  return 0;
}

function formatDuration(value) {
  const numeric = Number(value || 0);
  if (!numeric) {
    return "--";
  }
  if (numeric < 1000) {
    return tr(`${numeric} 毫秒`, `${numeric} ms`);
  }
  const seconds = numeric / 1000;
  if (seconds < 60) {
    return tr(`${seconds.toFixed(1)} 秒`, `${seconds.toFixed(1)} s`);
  }
  return tr(`${Math.floor(seconds / 60)} 分 ${Math.round(seconds % 60)} 秒`, `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`);
}

function formatDate(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return new Intl.DateTimeFormat(getLanguageLocale(), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function buildEmptyCard(text, title = tr("等待信号", "Awaiting signal")) {
  return `
    <div class="empty-card">
      <span class="empty-card-kicker">${escapeHtml(tr("控制台状态", "Console state"))}</span>
      <strong class="empty-card-title">${escapeHtml(title)}</strong>
      <p class="empty-card-body">${escapeHtml(text)}</p>
    </div>
  `;
}

function renderConsoleHeader(job) {
  const stateBadge = document.getElementById("consoleStateBadge");
  const lastScan = document.getElementById("consoleLastScanText");
  const demoBadge = document.getElementById("consoleModeBadge");
  if (!stateBadge || !lastScan || !demoBadge) {
    return;
  }

  if (PUBLIC_SITE_MODE) {
    stateBadge.className = `console-status-badge ${hasDownloadAsset() ? "state-safe" : "state-review"}`;
    stateBadge.textContent = hasDownloadAsset()
      ? tr("站点交付", "Hosted Delivery")
      : tr("待发布", "Release Pending");
    lastScan.textContent = DOWNLOAD_ASSET.publishedAt ? formatDate(DOWNLOAD_ASSET.publishedAt) : (DOWNLOAD_ASSET.version || "--");
    demoBadge.className = "console-mode-badge is-hidden";
    demoBadge.textContent = tr("演示数据", "Demo Data");
    renderConsoleQuickStats(null);
    return;
  }

  const referenceJob = job || state.jobs.find((item) => item?.report) || state.jobs[0] || null;
  let label = tr("等待扫描", "Idle");
  let tone = "state-idle";
  let lastText = "--";

  if (referenceJob) {
    lastText = referenceJob.report?.timestamp || formatDate(referenceJob.updated_at || referenceJob.finished_at || referenceJob.created_at) || "--";
    if (["queued", "running"].includes(referenceJob.status)) {
      label = getStageLabel(referenceJob.stage_key, referenceJob.stage_label) || tr("处理中", "Reviewing");
      tone = "state-review";
    } else if (referenceJob.status === "failed") {
      label = tr("需要复核", "Review Required");
      tone = "state-risk";
    } else if (referenceJob.report) {
      const posture = getPosture(referenceJob.report);
      label = posture.label;
      tone = posture.badgeClass === "badge-good"
        ? "state-safe"
        : posture.badgeClass === "badge-risk"
          ? "state-risk"
          : "state-review";
    }
  }

  stateBadge.className = `console-status-badge ${tone}`;
  stateBadge.textContent = label;
  lastScan.textContent = lastText;
  demoBadge.className = referenceJob?.report?.demo_mode ? "console-mode-badge" : "console-mode-badge is-hidden";
  demoBadge.textContent = tr("演示数据", "Demo Data");
  renderConsoleQuickStats(referenceJob);
}

function renderConsoleQuickStats(job) {
  const host = document.getElementById("consoleQuickStats");
  if (!host) {
    return;
  }

  if (PUBLIC_SITE_MODE) {
    const version = safeText(DOWNLOAD_ASSET.version, "--");
    const size = DOWNLOAD_ASSET.sizeBytes ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--";
    host.innerHTML = [
      buildConsoleFact(tr("发布版本", "Release"), version, "safe"),
      buildConsoleFact(tr("安装包", "Installer"), size, "neutral"),
      buildConsoleFact(tr("通道", "Channel"), tr("稳定版", "Stable"), "review"),
    ].join("");
    return;
  }

  const report = job?.report || null;
  if (!report) {
    host.innerHTML = [
      buildConsoleFact(tr("高风险", "High Risk"), "--", "risk"),
      buildConsoleFact(tr("自动处置", "Auto Remediation"), "--", "neutral"),
      buildConsoleFact(tr("人工复核", "Manual Review"), "--", "review"),
    ].join("");
    return;
  }

  const checks = report.checks || [];
  const visibleTargets = getRenderableUninstallTargets();
  const autoTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const manualQueue = visibleTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "manual-review" || remediation.status === "partial";
  });

  host.innerHTML = [
    buildConsoleFact(tr("高风险", "High Risk"), String(checks.filter((check) => Number(check?.risk_score || 0) >= HIGH_RISK_THRESHOLD).length), "risk"),
    buildConsoleFact(tr("自动处置", "Auto Remediation"), String(autoTargets.length), autoTargets.length ? "safe" : "neutral"),
    buildConsoleFact(tr("人工复核", "Manual Review"), String(manualQueue.length), manualQueue.length ? "review" : "neutral"),
  ].join("");
}

function buildConsoleFact(label, value, tone = "neutral") {
  return `
    <article class="console-fact console-fact-${escapeHtml(tone)}">
      <span class="console-fact-label">${escapeHtml(label)}</span>
      <strong class="console-fact-value">${escapeHtml(value)}</strong>
    </article>
  `;
}

function renderFindingsSummary(checks, totalChecks = checks.length) {
  const host = document.getElementById("findingsSummaryChips");
  if (!host) {
    return;
  }

  const manualQueue = checks.filter((check) => {
    const remediation = markRelatedFindingsHandled(check.id);
    return remediation.status === "manual-review" || remediation.status === "partial";
  }).length;

  host.innerHTML = [
    buildFindingsSummaryChip(tr("可见记录", "Visible"), `${checks.length}/${totalChecks}`, "neutral"),
    buildFindingsSummaryChip(tr("高风险", "High Risk"), String(checks.filter((check) => Number(check?.risk_score || 0) >= HIGH_RISK_THRESHOLD).length), "risk"),
    buildFindingsSummaryChip(tr("人工复核", "Manual Review"), String(manualQueue), manualQueue ? "review" : "neutral"),
  ].join("");
}

function buildFindingsSummaryChip(label, value, tone = "neutral") {
  return `
    <article class="findings-summary-chip findings-summary-${escapeHtml(tone)}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </article>
  `;
}

function syncOperationPanel(job) {
  if (PUBLIC_SITE_MODE) {
    document.getElementById("jobStateText").textContent = hasDownloadAsset()
      ? tr("公开下载站", "Public download site")
      : tr("发布包不可用", "Release package unavailable");
    document.getElementById("jobMetaText").textContent = hasDownloadAsset()
      ? tr(`Windows 安装包 ${DOWNLOAD_ASSET.version || "--"} 已可直接下载。`, `Windows installer ${DOWNLOAD_ASSET.version || "--"} is ready for direct download.`)
      : tr("请先构建 Windows 发布包，网站才会开放直接下载。", "Build a Windows release package to enable direct website downloads.");
    document.getElementById("scanIdLabel").textContent = DOWNLOAD_ASSET.version || "--";
    document.getElementById("scanTimeLabel").textContent = hasDownloadAsset()
      ? formatFileSize(DOWNLOAD_ASSET.sizeBytes)
      : "--";
    document.getElementById("uninstallAvailableLabel").textContent = "--";
    document.getElementById("uninstallLastStatus").textContent = tr("仅本地", "Local Only");
    document.getElementById("uninstallLastMeta").textContent = tr(
      "真实扫描与卸载只在安装后的 Windows 客户端中可用。",
      "Real scan and uninstall remain available after the Windows client is installed.",
    );
    renderOperationSignals(null);
    return;
  }

  const stageText = getStageLabel(job?.stage_key, job?.stage_label);
  const statusText = job?.status === "failed"
    ? tr("扫描失败", "Scan failed")
    : stageText || tr("等待扫描", "Waiting for a scan");
  const metaText = job?.report
    ? `${job.report.host || "--"} / ${job.report.os || "--"}`
    : job?.created_at
      ? tr(`任务创建于 ${formatDate(job.created_at)}`, `Job created at ${formatDate(job.created_at)}`)
      : tr("当前还没有活动中的扫描任务", "No active scan job yet");

  document.getElementById("jobStateText").textContent = statusText;
  document.getElementById("jobMetaText").textContent = metaText;
  document.getElementById("scanIdLabel").textContent = job?.scan_id || "--";
  document.getElementById("scanTimeLabel").textContent = job?.report?.timestamp || "--";

  const scopedTargets = getRenderableUninstallTargets(job);
  const directTargets = scopedTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  document.getElementById("uninstallAvailableLabel").textContent = String(directTargets.length);

  const scopedHistory = getScopedUninstallHistory(job);
  const lastTask = scopedHistory[0] || state.uninstallHistory[0];
  document.getElementById("uninstallLastStatus").textContent = lastTask
    ? getTaskStatusLabel(lastTask.status)
    : tr("无", "None");
  document.getElementById("uninstallLastMeta").textContent = lastTask
    ? `${lastTask.target_name} / ${formatDate(lastTask.updated_at)}${lastTask.status === "partial" ? tr(" / 需要人工复核", " / Manual review required") : ""}`
    : state.uninstallSourceScanId
      ? tr(`目标来源于扫描 ${state.uninstallSourceScanId}`, `Targets sourced from scan ${state.uninstallSourceScanId}`)
      : tr("还没有执行过卸载任务", "No uninstall task has run yet");
  renderOperationSignals(job);
}

function renderOperationSignals(job) {
  const host = document.getElementById("opsSignalStrip");
  if (!host) {
    return;
  }

  if (PUBLIC_SITE_MODE) {
    host.innerHTML = [
      buildOperationSignal(tr("分发模式", "Delivery"), tr("公网", "Hosted"), "neutral"),
      buildOperationSignal(tr("平台", "Platform"), "Windows", "neutral"),
      buildOperationSignal(tr("执行位置", "Execution"), tr("本地", "Local"), "review"),
    ].join("");
    return;
  }

  const report = job?.report || null;
  const directTargets = getRenderableUninstallTargets(job).filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const scopedHistory = getScopedUninstallHistory(job);
  const lastTask = scopedHistory[0] || state.uninstallHistory[0] || null;
  const openFindings = report ? (report.checks || []).filter((check) => isFlagged(check)).length : null;

  host.innerHTML = [
    buildOperationSignal(tr("开放风险", "Open Findings"), openFindings === null ? "--" : String(openFindings), openFindings ? "risk" : "neutral"),
    buildOperationSignal(tr("直接处置", "Direct Targets"), String(directTargets.length), directTargets.length ? "safe" : "neutral"),
    buildOperationSignal(tr("最近任务", "Last Task"), lastTask ? getTaskStatusLabel(lastTask.status) : tr("无", "None"), lastTask?.status === "partial" ? "review" : lastTask ? "safe" : "neutral"),
  ].join("");
}

function buildOperationSignal(label, value, tone = "neutral") {
  return `
    <article class="ops-signal ops-signal-${escapeHtml(tone)}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </article>
  `;
}

function getReleaseDisplayState() {
  const release = state.releaseInfo || {};
  const releaseVersion = safeText(release.version, DOWNLOAD_ASSET.version || "");
  const releaseFilename = safeText(release.installer_filename, DOWNLOAD_ASSET.filename || "");
  const releaseSizeBytes = Number(release.installer_size_bytes || DOWNLOAD_ASSET.sizeBytes || 0);
  const downloadUrl = safeText(release.download_url, PUBLIC_DOWNLOAD_URL || DOWNLOAD_ASSET.url || "");
  const publishedAt = safeText(release.published_at, "");
  const comparison = compareVersions(releaseVersion, APP_VERSION);

  if (state.releaseStatus === "checking") {
    return {
      pillClass: "status-queued",
      pillLabel: tr("检查中", "Checking"),
      metaText: tr("正在检查公开发布通道中的最新 Windows 安装包。", "Checking the public release channel for the latest Windows installer."),
      summaryText: tr("工作台正在查询线上发布清单，以便本地客户端比较当前安装版本和最新公开版本。", "The workbench is querying the hosted release manifest so the local client can compare installed and published versions."),
      buttonLabel: hasDownloadAsset() ? tr("下载 Windows 客户端", "Download Windows Client") : tr("检查发布状态", "Checking Release"),
      version: releaseVersion || DOWNLOAD_ASSET.version || "--",
      filename: releaseFilename || DOWNLOAD_ASSET.filename || "--",
      sizeLabel: formatFileSize(releaseSizeBytes),
      publishedLabel: publishedAt ? formatDate(publishedAt) : "--",
      downloadUrl,
    };
  }

  if (state.releaseStatus === "ready" && releaseVersion) {
    if (comparison > 0) {
      return {
        pillClass: "status-partial",
        pillLabel: tr("有可用更新", "Update Available"),
        metaText: tr(`公开版本 ${releaseVersion} 比当前安装版本 ${APP_VERSION} 更新。`, `Public release ${releaseVersion} is newer than the installed client ${APP_VERSION}.`),
        summaryText: tr("如果你想在下一次本地扫描前使用最新工作台修复和发布信息，请先下载最新 Windows 客户端。", "Download the latest Windows client package before the next local scan if you want the newest workbench fixes and release metadata."),
        buttonLabel: tr("下载更新", "Download Update"),
        version: releaseVersion,
        filename: releaseFilename || "--",
        sizeLabel: formatFileSize(releaseSizeBytes),
        publishedLabel: publishedAt ? formatDate(publishedAt) : "--",
        downloadUrl,
      };
    }
    return {
      pillClass: "status-success",
      pillLabel: tr("已是最新", "Up To Date"),
      metaText: tr(`当前安装版本 ${APP_VERSION} 与最新公开版本一致。`, `Installed client ${APP_VERSION} matches the latest public release.`),
      summaryText: tr("发布通道状态正常。下载链接仍可用于重装、分发给同事或在隔离环境中做验证。", "The release channel is healthy. Download links remain available for reinstall, peer deployment, or clean-room verification."),
      buttonLabel: tr("下载 Windows 客户端", "Download Windows Client"),
      version: releaseVersion,
      filename: releaseFilename || "--",
      sizeLabel: formatFileSize(releaseSizeBytes),
      publishedLabel: publishedAt ? formatDate(publishedAt) : "--",
      downloadUrl,
    };
  }

  if (hasDownloadAsset()) {
    return {
      pillClass: "status-running",
      pillLabel: tr("站点已挂载", "Bundled"),
      metaText: tr(`${DOWNLOAD_ASSET.filename} 已挂载到当前站点。`, `${DOWNLOAD_ASSET.filename} is attached to the current host.`),
      summaryText: tr("当前环境可以直接分发本地安装包。由于没有拿到线上发布清单，因此只展示站点自带文件。", "The current environment can hand off a local installer package directly. Release manifest details were not available, so only the bundled file is shown."),
      buttonLabel: tr("下载 Windows 客户端", "Download Windows Client"),
      version: DOWNLOAD_ASSET.version || "--",
      filename: DOWNLOAD_ASSET.filename || "--",
      sizeLabel: formatFileSize(DOWNLOAD_ASSET.sizeBytes),
      publishedLabel: "--",
      downloadUrl: DOWNLOAD_ASSET.url || "",
    };
  }

  return {
    pillClass: "status-neutral",
    pillLabel: tr("不可用", "Unavailable"),
    metaText: state.releaseStatus === "unavailable"
      ? tr("当前客户端会话无法检查公开发布通道。", "The public release channel could not be checked from this client session.")
      : tr("尚未检测到发布安装包。", "No release package detected yet."),
    summaryText: tr("请把 Windows 安装包构建并发布到公开发布通道，这样网站和本地工作台才能提供稳定下载路径。", "Build or publish the Windows installer to the public release channel so the website and local workbench can expose a stable download path."),
    buttonLabel: tr("安装包不可用", "Installer Unavailable"),
    version: "--",
    filename: "--",
    sizeLabel: "--",
    publishedLabel: "--",
    downloadUrl: "",
  };
}

function renderDownloadPanel() {
  const topLink = document.getElementById("downloadTopLink");
  const heroLink = document.getElementById("heroDownloadLink");
  const heroMeta = document.getElementById("heroDownloadMeta");
  const statusPill = document.getElementById("downloadStatusPill");
  const panelMeta = document.getElementById("downloadPanelMeta");
  const panelSummary = document.getElementById("downloadPanelSummary");
  const factList = document.getElementById("downloadFactList");
  const button = document.getElementById("downloadClientBtn");
  const releaseState = getReleaseDisplayState();
  const available = hasDownloadAsset() || Boolean(releaseState.downloadUrl);
  const url = releaseState.downloadUrl || (hasDownloadAsset() ? DOWNLOAD_ASSET.url : "#");
  const label = available
    ? tr(`Windows 安装包 ${releaseState.version || DOWNLOAD_ASSET.version || ""}`.trim(), `Windows installer ${releaseState.version || DOWNLOAD_ASSET.version || ""}`.trim())
    : tr("尚未挂载安装包", "No installer package attached");

  [topLink, heroLink].forEach((link) => {
    link.href = url;
    link.classList.toggle("is-hidden", !available);
  });

  heroMeta.textContent = available
    ? `${label} / ${releaseState.sizeLabel}`
    : tr("请先构建 dist/release/PoliceClaw-Setup-<version>.exe，网站才会开放直接下载。", "Build dist/release/PoliceClaw-Setup-<version>.exe to expose a direct website download.");

  statusPill.className = `status-pill ${releaseState.pillClass}`;
  statusPill.textContent = releaseState.pillLabel;

  panelMeta.textContent = releaseState.metaText;
  panelSummary.textContent = releaseState.summaryText;
  factList.innerHTML = [
    [tr("已安装", "Installed"), APP_VERSION || "--"],
    [tr("最新版本", "Latest"), releaseState.version || DOWNLOAD_ASSET.version || "--"],
    [tr("安装包", "Package"), releaseState.filename || DOWNLOAD_ASSET.filename || "--"],
    [tr("大小", "Size"), releaseState.sizeLabel],
    [tr("发布时间", "Published"), releaseState.publishedLabel],
    [tr("作用范围", "Scope"), tr("本地 Windows 客户端", "Local Windows client")],
  ].map(([labelText, value]) => `
    <div class="runtime-item">
      <span class="runtime-key">${escapeHtml(String(labelText))}</span>
      <strong class="runtime-value">${escapeHtml(String(value))}</strong>
    </div>
  `).join("");

  button.href = url;
  button.setAttribute("aria-disabled", available ? "false" : "true");
  button.classList.toggle("is-disabled", !available);
  button.textContent = releaseState.buttonLabel;
}

function hasDownloadAsset() {
  return Boolean(DOWNLOAD_ASSET.available && DOWNLOAD_ASSET.url);
}

function openDownloadAsset() {
  const releaseState = getReleaseDisplayState();
  if (!releaseState.downloadUrl && !hasDownloadAsset()) {
    renderGlobalError(tr("当前站点还没有挂载 Windows 安装包。", "No Windows installer package is attached to the hosted site yet."), tr("下载不可用", "Download Unavailable"));
    return;
  }
  window.location.href = releaseState.downloadUrl || DOWNLOAD_ASSET.url;
}

async function requestJson(url, options = {}, fallbackMessage = tr("请求失败。", "Request failed.")) {
  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers: buildRequestHeaders(options.headers || {}),
    });
  } catch (error) {
    throw new Error(fallbackMessage);
  }
  return parseJson(response, fallbackMessage);
}

function buildRequestHeaders(headers = {}) {
  const merged = new Headers(headers);
  merged.set("Accept", "application/json");
  if (API_TOKEN) {
    merged.set(API_HEADER_NAME, API_TOKEN);
  }
  return merged;
}

async function parseJson(response, fallbackMessage = tr("请求失败。", "Request failed.")) {
  const rawText = await response.text();
  let payload = {};
  if (rawText) {
    try {
      payload = JSON.parse(rawText);
    } catch (error) {
      payload = {};
    }
  }
  if (!response.ok) {
    const message = payload.message || payload.error || `${fallbackMessage} (${response.status})`;
    throw new Error(message);
  }
  if (payload && typeof payload === "object" && !Array.isArray(payload) && Object.prototype.hasOwnProperty.call(payload, "ok")) {
    const { ok, ...rest } = payload;
    return rest;
  }
  return payload;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function decorateConsoleSurface(job) {
  renderScopeBadge(job);
  decorateFindingsTable(job);
  decorateTargetRail(job);
  renderActionQueueSummary(job);
}

function renderScopeBadge(job) {
  const host = document.getElementById("scopeBadgeHost");
  if (!host) {
    return;
  }
  const hosted = PUBLIC_SITE_MODE;
  const demo = Boolean(job?.report?.demo_mode || job?.demo_mode || job?.source_type === "demo");
  host.className = `scope-badge ${hosted ? "scope-badge-hosted" : demo ? "scope-badge-demo" : ""}`.trim();
  host.innerHTML = `
    <span class="scope-badge-label">${escapeHtml(tr("聚焦范围", "Focused Scope"))}</span>
    <strong class="scope-badge-title">${escapeHtml("AI agents / skills / scripts")}</strong>
    <span class="scope-badge-note">${escapeHtml(
      hosted
        ? tr("官网只负责客户端下载，真实扫描与处置仍在本机执行。", "The hosted site only distributes the client. Real scan and remediation still execute locally.")
        : tr("只覆盖本地执行风险面，不扩展为通用系统防护产品。", "Scoped to local execution risks instead of general system hardening.")
    )}</span>
  `;
}

function decorateFindingsTable(job) {
  const report = job?.report;
  const table = document.getElementById("findingsTable");
  if (!table || !report) {
    return;
  }
  table.querySelectorAll(".finding-row").forEach((row) => {
    const checkId = row.getAttribute("data-check-id");
    const check = (report.checks || []).find((item) => item.id === checkId);
    if (!check) {
      return;
    }
    const relatedTargets = getRelatedTargets(check.id);
    const primaryTarget = pickPrimaryTarget(relatedTargets);
    const remediation = markRelatedFindingsHandled(check.id);
    const severity = getFindingRiskProfile(check);
    row.classList.toggle("finding-row-risk", severity.className === "risk-high");
    row.classList.toggle("finding-row-review", remediation.status === "partial" || remediation.status === "manual-review");

    const primary = row.querySelector(".finding-primary");
    if (!primary || primary.querySelector(".finding-meta-strip")) {
      return;
    }

    const supportLabel = primaryTarget
      ? getSupportLevelLabel(primaryTarget.support_level || (primaryTarget.uninstall_supported ? "cleanup" : "blocked"))
      : tr("未推导目标", "No target");
    const tone = primaryTarget?.uninstall_supported ? "ready" : "review";
    const meta = document.createElement("div");
    meta.className = "finding-meta-strip";
    meta.innerHTML = `
      <span class="finding-aux-pill finding-aux-${escapeHtml(tone)}">${escapeHtml(supportLabel)}</span>
      <span class="finding-inline-note">${escapeHtml(tr(`${relatedTargets.length} 个目标`, `${relatedTargets.length} target(s)`))}</span>
    `;
    primary.appendChild(meta);
  });
}

function decorateTargetRail(job) {
  const container = document.getElementById("uninstallTargetList");
  if (!container) {
    return;
  }
  const targets = getRenderableUninstallTargets(job);
  container.querySelectorAll(".target-card").forEach((card) => {
    const targetButton = card.querySelector("[data-target-id]");
    const target = targets.find((item) => item.id === targetButton?.getAttribute("data-target-id"));
    if (!target) {
      return;
    }
    const remediation = getRemediationStateForTarget(target);
    const tone = getTargetPriorityTone(target, remediation);
    card.classList.add(`target-card-${tone}`);
    if (card.querySelector(".target-inline-meta")) {
      return;
    }
    const matchedFindings = Number(target.matched_findings_count || 0);
    const plannedActions = Array.isArray(target.planned_actions) ? target.planned_actions.length : 0;
    const meta = document.createElement("div");
    meta.className = "target-inline-meta";
    meta.innerHTML = `
      <span class="target-priority-badge target-priority-${escapeHtml(tone)}">${escapeHtml(getTargetPriorityLabel(target, remediation))}</span>
      <span>${escapeHtml(tr(`${matchedFindings} 个关联发现`, `${matchedFindings} related finding(s)`))}</span>
      <span>${escapeHtml(tr(`${plannedActions} 个处置动作`, `${plannedActions} planned action(s)`))}</span>
    `;
    const head = card.querySelector(".target-card-head");
    head?.insertAdjacentElement("afterend", meta);
  });
}

function renderActionQueueSummary(job) {
  const section = document.getElementById("targetsSection");
  if (!section) {
    return;
  }
  let host = document.getElementById("actionQueueSummary");
  if (!host) {
    host = document.createElement("div");
    host.id = "actionQueueSummary";
    host.className = "action-queue-summary";
    const list = document.getElementById("recommendationList");
    list?.insertAdjacentElement("beforebegin", host);
  }
  if (PUBLIC_SITE_MODE) {
    host.innerHTML = `
      <article class="action-queue-chip action-queue-chip-neutral">
        <span>${escapeHtml(tr("分发模式", "Delivery"))}</span>
        <strong>${escapeHtml(tr("客户端优先", "Client first"))}</strong>
      </article>
      <article class="action-queue-chip action-queue-chip-neutral">
        <span>${escapeHtml(tr("处置位置", "Execution"))}</span>
        <strong>${escapeHtml(tr("本机执行", "Local host"))}</strong>
      </article>
      <article class="action-queue-chip action-queue-chip-review">
        <span>${escapeHtml(tr("风险边界", "Guardrail"))}</span>
        <strong>${escapeHtml(tr("保守处置", "Conservative"))}</strong>
      </article>
    `;
    return;
  }
  const targets = getRenderableUninstallTargets(job);
  const direct = targets.filter((target) => target.uninstall_supported && target.support_level === "full").length;
  const cleanup = targets.filter((target) => target.uninstall_supported && target.support_level === "cleanup").length;
  const review = targets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return !target.uninstall_supported || remediation.status === "partial" || remediation.status === "manual-review";
  }).length;
  host.innerHTML = `
    <article class="action-queue-chip action-queue-chip-risk">
      <span>${escapeHtml(tr("优先处置", "Priority"))}</span>
      <strong>${escapeHtml(String(direct))}</strong>
    </article>
    <article class="action-queue-chip action-queue-chip-safe">
      <span>${escapeHtml(tr("可清理", "Cleanup"))}</span>
      <strong>${escapeHtml(String(cleanup))}</strong>
    </article>
    <article class="action-queue-chip action-queue-chip-review">
      <span>${escapeHtml(tr("人工复核", "Manual"))}</span>
      <strong>${escapeHtml(String(review))}</strong>
    </article>
  `;
}

function getTargetPriorityTone(target, remediation) {
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return "resolved";
  }
  if (remediation.status === "partial" || remediation.status === "manual-review") {
    return "review";
  }
  if (target.uninstall_supported && target.support_level === "full") {
    return "urgent";
  }
  if (target.uninstall_supported) {
    return "cleanup";
  }
  return "blocked";
}

function getTargetPriorityLabel(target, remediation) {
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return remediation.label || tr("已处理", "Handled");
  }
  if (remediation.status === "partial") {
    return tr("残留复核", "Residual Review");
  }
  if (remediation.status === "manual-review") {
    return tr("人工复核", "Manual Review");
  }
  if (target.uninstall_supported && target.support_level === "full") {
    return tr("优先处置", "Priority Remediation");
  }
  if (target.uninstall_supported) {
    return tr("可清理", "Cleanup Available");
  }
  return tr("受限目标", "Restricted Target");
}
