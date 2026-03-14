import { useState, useEffect, useRef } from "react";

const DOMAINS = [
  { id: "credential", name: "凭证与身份安全", icon: "🔐", weight: 1.5, color: "#f43f5e" },
  { id: "transaction", name: "交易与金融安全", icon: "💰", weight: 1.4, color: "#f59e0b" },
  { id: "behavior", name: "用户行为追踪", icon: "👁️", weight: 1.2, color: "#a78bfa" },
  { id: "system", name: "系统权限与控制", icon: "⚙️", weight: 1.3, color: "#fb923c" },
  { id: "data", name: "数据采集与外泄", icon: "📡", weight: 1.4, color: "#38bdf8" },
  { id: "model", name: "模型与 AI 上下文", icon: "🧠", weight: 1.2, color: "#34d399" },
  { id: "audit", name: "审计与合规", icon: "🛡️", weight: 1.0, color: "#94a3b8" },
];

const CHECKS = [
  { id: "cred_password", dom: "credential", label: "抓取账户密码" },
  { id: "cred_ssh", dom: "credential", label: "读取 SSH 密钥" },
  { id: "cred_api", dom: "credential", label: "窃取 API Token" },
  { id: "cred_cookie", dom: "credential", label: "抓取浏览器 Cookie" },
  { id: "cred_wallet", dom: "credential", label: "读取加密钱包" },
  { id: "cred_2fa", dom: "credential", label: "窃取 2FA 凭证" },
  { id: "cred_cert", dom: "credential", label: "读取证书与私钥" },
  { id: "txn_unauth", dom: "transaction", label: "未授权进行交易" },
  { id: "txn_crypto", dom: "transaction", label: "加密货币自动交易" },
  { id: "txn_payment", dom: "transaction", label: "篡改支付信息" },
  { id: "txn_mining", dom: "transaction", label: "挖矿行为" },
  { id: "beh_search", dom: "behavior", label: "抓取搜索行为" },
  { id: "beh_code", dom: "behavior", label: "追踪代码编写" },
  { id: "beh_debug", dom: "behavior", label: "追踪调试行为" },
  { id: "beh_keylog", dom: "behavior", label: "键盘记录" },
  { id: "beh_screen", dom: "behavior", label: "屏幕截图与录制" },
  { id: "beh_clip", dom: "behavior", label: "剪贴板监控" },
  { id: "beh_oplog", dom: "behavior", label: "操作记录抓取" },
  { id: "sys_root", dom: "system", label: "root/SYSTEM 权限运行" },
  { id: "sys_persist", dom: "system", label: "持久化驻留" },
  { id: "sys_inject", dom: "system", label: "进程注入" },
  { id: "sys_driver", dom: "system", label: "内核模块/驱动加载" },
  { id: "sys_firewall", dom: "system", label: "防火墙规则篡改" },
  { id: "sys_dns", dom: "system", label: "DNS 劫持" },
  { id: "data_file", dom: "data", label: "读取私人文件" },
  { id: "data_content", dom: "data", label: "抓取文件内容" },
  { id: "data_cloud", dom: "data", label: "上传云端文件" },
  { id: "data_idle", dom: "data", label: "待机偷跑数据" },
  { id: "data_stream", dom: "data", label: "平台可见全部数据流" },
  { id: "data_dns_tun", dom: "data", label: "DNS 隧道外泄" },
  { id: "data_steg", dom: "data", label: "隐写术数据外泄" },
  { id: "data_usb", dom: "data", label: "USB/外接设备拷贝" },
  { id: "data_backup", dom: "data", label: "备份文件外泄" },
  { id: "model_ctx", dom: "model", label: "数据进入模型上下文" },
  { id: "model_prompt", dom: "model", label: "Prompt 抓取" },
  { id: "model_ft", dom: "model", label: "用户数据用于微调" },
  { id: "model_embed", dom: "model", label: "敏感数据向量化" },
  { id: "model_api", dom: "model", label: "模型 API 泄露数据" },
  { id: "audit_sys", dom: "audit", label: "安全审计体系" },
  { id: "audit_tamper", dom: "audit", label: "审计日志篡改" },
  { id: "audit_comply", dom: "audit", label: "合规性缺失" },
  { id: "audit_leak", dom: "audit", label: "综合数据泄露风险" },
];

function simulate() {
  return CHECKS.map((c) => {
    const isAuditSys = c.id === "audit_sys";
    const r = Math.random();
    const detected = isAuditSys ? r > 0.45 : r > 0.68;
    const risk = isAuditSys
      ? detected ? 0 : 60
      : detected ? Math.min(100, Math.floor(Math.random() * 75 + 25)) : 0;
    return { ...c, detected, risk, status: detected ? "是" : "否",
      evidence: detected ? Math.floor(Math.random() * 4) + 1 : 0 };
  });
}

function Bar({ score, animate, color }) {
  const c = score >= 70 ? "#ef4444" : score >= 35 ? "#f59e0b" : score > 0 ? "#3b82f6" : color || "#22c55e";
  return (
    <div style={{ flex: 1, height: 5, background: "rgba(255,255,255,0.05)", borderRadius: 3, overflow: "hidden", minWidth: 60 }}>
      <div style={{ width: animate ? `${score}%` : "0%", height: "100%", background: c,
        borderRadius: 3, transition: "width 0.9s cubic-bezier(0.22,1,0.36,1)" }} />
    </div>
  );
}

function DomainCard({ domain, items, animate, expanded, onToggle }) {
  const risks = items.filter(i => i.id === "audit_sys" ? !i.detected : i.detected).length;
  const maxScore = Math.max(0, ...items.map(i => i.risk));
  const pct = items.length ? Math.round((risks / items.length) * 100) : 0;

  return (
    <div style={{
      background: "rgba(255,255,255,0.015)",
      border: `1px solid ${risks > 0 ? "rgba(239,68,68,0.15)" : "rgba(255,255,255,0.05)"}`,
      borderRadius: 10, overflow: "hidden",
      opacity: animate ? 1 : 0, transform: animate ? "translateY(0)" : "translateY(12px)",
      transition: "all 0.5s cubic-bezier(0.22,1,0.36,1)",
    }}>
      <div onClick={onToggle} style={{
        display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", cursor: "pointer",
      }}>
        <span style={{ fontSize: 22 }}>{domain.icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#e0e0e0", letterSpacing: 0.3 }}>{domain.name}</div>
          <div style={{ fontSize: 10, color: "#666", marginTop: 2 }}>{items.length} 项检查</div>
        </div>
        {risks > 0 ? (
          <div style={{
            background: "rgba(239,68,68,0.12)", color: "#ef4444",
            fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 20,
          }}>{risks} 风险</div>
        ) : (
          <div style={{
            background: "rgba(34,197,94,0.1)", color: "#22c55e",
            fontSize: 11, fontWeight: 600, padding: "3px 10px", borderRadius: 20,
          }}>安全</div>
        )}
        <div style={{ fontSize: 10, color: "#555", fontFamily: "monospace", width: 36, textAlign: "right" }}>
          {maxScore > 0 ? maxScore : "—"}
        </div>
        <span style={{
          fontSize: 10, color: "#555", transition: "transform 0.2s",
          transform: expanded ? "rotate(180deg)" : "rotate(0)",
        }}>▼</span>
      </div>

      {expanded && (
        <div style={{ borderTop: "1px solid rgba(255,255,255,0.04)", padding: "4px 8px 10px" }}>
          {items.map((item, i) => {
            const isRisk = item.id === "audit_sys" ? !item.detected : item.detected;
            return (
              <div key={item.id} style={{
                display: "grid", gridTemplateColumns: "24px 1fr 44px 40px 80px",
                alignItems: "center", gap: 8, padding: "7px 8px", borderRadius: 4,
                fontSize: 12,
              }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.02)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <span style={{ fontSize: 8, textAlign: "center",
                  color: isRisk ? "#ef4444" : "#22c55e" }}>
                  {isRisk ? "●" : "○"}
                </span>
                <span style={{ color: "#ccc", fontSize: 12 }}>{item.label}</span>
                <span style={{
                  textAlign: "center", fontWeight: 700, fontSize: 11,
                  fontFamily: "monospace",
                  color: isRisk ? "#ef4444" : "#22c55e",
                }}>{item.status}</span>
                <span style={{ textAlign: "center", fontSize: 10, color: "#666", fontFamily: "monospace" }}>
                  {item.risk}
                </span>
                <Bar score={item.risk} animate={animate} color={domain.color} />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function PoliceClaw() {
  const [phase, setPhase] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState("");
  const [results, setResults] = useState([]);
  const [animate, setAnimate] = useState(false);
  const [expandedDoms, setExpandedDoms] = useState({});
  const [scanId] = useState(() => Math.random().toString(36).slice(2, 10).toUpperCase());
  const ivRef = useRef(null);

  const stages = [
    "采集进程与命令行...", "扫描网络连接...", "分析网络流量特征...",
    "检测文件系统敏感路径...", "检测模型 API 调用...", "识别安全信号...",
    "计算风险评分...", "生成分类报告...",
  ];

  function startScan() {
    setPhase("scanning"); setProgress(0); setResults([]); setAnimate(false); setExpandedDoms({});
    let p = 0, si = 0;
    setStage(stages[0]);
    ivRef.current = setInterval(() => {
      p += Math.random() * 5 + 1.5;
      const newSi = Math.min(stages.length - 1, Math.floor((p / 100) * stages.length));
      if (newSi !== si) { si = newSi; setStage(stages[si]); }
      if (p >= 100) {
        clearInterval(ivRef.current);
        setProgress(100); setStage("完成");
        setTimeout(() => {
          setResults(simulate()); setPhase("done");
          setTimeout(() => setAnimate(true), 80);
        }, 300);
      } else setProgress(Math.min(p, 99));
    }, 100);
  }

  useEffect(() => () => clearInterval(ivRef.current), []);

  const byDomain = {};
  DOMAINS.forEach(d => byDomain[d.id] = []);
  results.forEach(r => byDomain[r.dom]?.push(r));

  const totalRisks = results.filter(r => r.id === "audit_sys" ? !r.detected : r.detected).length;
  const maxRisk = results.length ? Math.max(...results.map(r => r.risk)) : 0;
  const grade = totalRisks === 0 ? { l: "安全", c: "#22c55e", b: "rgba(34,197,94,0.08)" }
    : totalRisks <= 5 ? { l: "警告", c: "#f59e0b", b: "rgba(245,158,11,0.08)" }
    : { l: "危险", c: "#ef4444", b: "rgba(239,68,68,0.08)" };

  return (
    <div style={{
      minHeight: "100vh",
      background: "linear-gradient(170deg, #05050f 0%, #0a0a20 35%, #080818 70%, #05050f 100%)",
      color: "#d0d0d0", fontFamily: "'SF Pro Text', -apple-system, 'Segoe UI', sans-serif",
      padding: "20px 12px",
    }}>
      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        @keyframes glow { 0%,100%{box-shadow:0 0 8px rgba(233,69,96,.3)} 50%{box-shadow:0 0 20px rgba(233,69,96,.6)} }
        @keyframes scanBar { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
      `}</style>

      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: 24 }}>
        <div style={{ fontSize: 36, marginBottom: 2 }}>🦞</div>
        <h1 style={{ fontSize: 24, fontWeight: 800, color: "#fff", letterSpacing: 4,
          margin: "0 0 4px", textTransform: "uppercase" }}>Police Claw</h1>
        <p style={{ color: "#444", fontSize: 10, letterSpacing: 1.5, margin: 0 }}>
          AI Agent / Variant Lobster / Skills · 全域安全审计 · v3.0
        </p>
        <p style={{ color: "#333", fontSize: 9, letterSpacing: 1, margin: "4px 0 0" }}>
          42 项检查 · 7 大安全域 · 6 层采集架构
        </p>
      </div>

      {/* Main Card */}
      <div style={{
        maxWidth: 720, margin: "0 auto",
        background: "rgba(255,255,255,0.012)",
        border: "1px solid rgba(255,255,255,0.04)",
        borderRadius: 14, overflow: "hidden",
      }}>
        {/* Control */}
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "14px 18px", borderBottom: "1px solid rgba(255,255,255,0.04)",
        }}>
          <span style={{ color: "#444", fontSize: 10, fontFamily: "monospace" }}>
            ID: {scanId}
          </span>
          <button onClick={startScan} disabled={phase === "scanning"} style={{
            background: phase === "scanning" ? "#222" : "linear-gradient(135deg, #e94560, #b91c3c)",
            color: "#fff", border: "none", padding: "9px 26px", borderRadius: 8,
            fontSize: 12, fontWeight: 700, cursor: phase === "scanning" ? "not-allowed" : "pointer",
            letterSpacing: 1.5, transition: "all .2s",
            animation: phase === "idle" ? "glow 2.5s infinite" : "none",
          }}>
            {phase === "idle" ? "启动扫描" : phase === "scanning" ? "扫描中..." : "重新扫描"}
          </button>
        </div>

        {/* Progress */}
        {phase === "scanning" && (
          <div style={{ padding: "16px 18px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6,
              fontSize: 11, color: "#666" }}>
              <span style={{ animation: "pulse 1.2s infinite" }}>{stage}</span>
              <span style={{ fontFamily: "monospace", color: "#e94560" }}>{Math.floor(progress)}%</span>
            </div>
            <div style={{ width: "100%", height: 3, background: "#111", borderRadius: 2, overflow: "hidden" }}>
              <div style={{
                width: `${progress}%`, height: "100%", borderRadius: 2,
                background: "linear-gradient(90deg, #e94560, #ff6b81, #e94560)",
                backgroundSize: "200% 100%",
                animation: "scanBar 1.5s linear infinite",
                transition: "width .1s linear",
              }} />
            </div>
          </div>
        )}

        {/* Summary */}
        {phase === "done" && (
          <div style={{
            display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr",
            gap: 10, padding: "16px 18px", animation: "fadeUp .4s ease",
          }}>
            <div style={{ background: grade.b, borderRadius: 8, padding: 14, textAlign: "center" }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: grade.c }}>{grade.l}</div>
              <div style={{ fontSize: 9, color: "#666", marginTop: 3 }}>整体评级</div>
            </div>
            <div style={{ background: "rgba(239,68,68,0.05)", borderRadius: 8, padding: 14, textAlign: "center" }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: totalRisks > 0 ? "#ef4444" : "#22c55e" }}>
                {totalRisks}<span style={{ fontSize: 11, color: "#555" }}>/{results.length}</span>
              </div>
              <div style={{ fontSize: 9, color: "#666", marginTop: 3 }}>风险项</div>
            </div>
            <div style={{ background: "rgba(59,130,246,0.05)", borderRadius: 8, padding: 14, textAlign: "center" }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: maxRisk >= 70 ? "#ef4444" : maxRisk >= 35 ? "#f59e0b" : "#3b82f6" }}>
                {maxRisk}
              </div>
              <div style={{ fontSize: 9, color: "#666", marginTop: 3 }}>最高风险分</div>
            </div>
            <div style={{ background: "rgba(139,92,246,0.05)", borderRadius: 8, padding: 14, textAlign: "center" }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: "#a78bfa" }}>7</div>
              <div style={{ fontSize: 9, color: "#666", marginTop: 3 }}>安全域</div>
            </div>
          </div>
        )}

        {/* Domain Cards */}
        {phase === "done" && (
          <div style={{ padding: "4px 14px 16px", display: "flex", flexDirection: "column", gap: 8 }}>
            {DOMAINS.map((dom, i) => (
              <div key={dom.id} style={{
                transitionDelay: `${i * 70}ms`,
              }}>
                <DomainCard
                  domain={dom}
                  items={byDomain[dom.id] || []}
                  animate={animate}
                  expanded={!!expandedDoms[dom.id]}
                  onToggle={() => setExpandedDoms(p => ({ ...p, [dom.id]: !p[dom.id] }))}
                />
              </div>
            ))}
          </div>
        )}

        {/* Idle */}
        {phase === "idle" && (
          <div style={{ padding: "50px 20px 60px", textAlign: "center" }}>
            <div style={{ fontSize: 44, marginBottom: 14, opacity: 0.2 }}>🛡️</div>
            <p style={{ fontSize: 13, color: "#555", margin: "0 0 6px" }}>点击「启动扫描」开始全域安全审计</p>
            <p style={{ fontSize: 10, color: "#333", margin: 0 }}>
              将执行 42 项检查，覆盖凭证·交易·行为·系统·数据·模型·审计 七大安全域
            </p>
          </div>
        )}

        {/* Footer */}
        <div style={{
          padding: "10px 18px", borderTop: "1px solid rgba(255,255,255,0.03)",
          display: "flex", justifyContent: "space-between", fontSize: 9, color: "#333",
        }}>
          <span>Police Claw Enterprise v3.0</span>
          <span>Collector → Traffic → FS → Model → Signal → Risk → Report</span>
        </div>
      </div>
    </div>
  );
}
