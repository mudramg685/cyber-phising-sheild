/* ==========================================================================
   BAITWATCH — Phishing Defense Simulator (frontend)
   React 18 UMD + Babel Standalone — no build step. Served by FastAPI at "/".
   ========================================================================== */

const { useState, useEffect, useRef, useCallback } = React;

/* --------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------- */

/** Small fetch wrapper: JSON in, JSON out, readable errors from FastAPI. */
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const d = data && data.detail;
    const msg = typeof d === "string" ? d
      : Array.isArray(d) ? d.map((e) => e.msg.replace(/^Value error, /, "")).join("; ")
      : `Request failed (HTTP ${res.status})`;
    throw new Error(msg);
  }
  return data;
}

/** localStorage that never throws (private windows, blocked storage, etc.). */
const store = {
  get(key, fallback) {
    try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); }
    catch (_) { return fallback; }
  },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {} },
};

/** Fisher–Yates shuffle (returns a new array). */
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** "HH:MM:SS" local time from an ISO string. */
const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour12: false }) : "--:--:--");

/** Colour tone for a defense score. */
const scoreTone = (s) => (s >= 85 ? "safe" : s >= 70 ? "warn" : "threat");

/** Split "Name <addr@domain>" into parts for the reader header. */
function parseSender(sender) {
  const m = /^(.*?)\s*<([^>]+)>$/.exec(sender || "");
  return m ? { name: m[1] || m[2], address: m[2] } : { name: sender, address: "" };
}

/* --------------------------------------------------------------------------
   Hooks
   -------------------------------------------------------------------------- */

/** Types `text` out one character at a time. */
function useTypewriter(text, speed = 55, startDelay = 400) {
  const [out, setOut] = useState("");
  useEffect(() => {
    setOut("");
    let i = 0, timer;
    const start = setTimeout(function tick() {
      i += 1;
      setOut(text.slice(0, i));
      if (i < text.length) timer = setTimeout(tick, speed);
    }, startDelay);
    return () => { clearTimeout(start); clearTimeout(timer); };
  }, [text, speed, startDelay]);
  return out;
}

/** Animates a number from its previous value to `target`. */
function useCountUp(target, duration = 900, decimals = 0) {
  const [val, setVal] = useState(0);
  const fromRef = useRef(0);
  useEffect(() => {
    const from = fromRef.current, to = Number(target) || 0;
    let raf, t0;
    const step = (t) => {
      if (!t0) t0 = t;
      const p = Math.min(1, (t - t0) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(from + (to - from) * eased);
      if (p < 1) raf = requestAnimationFrame(step);
      else fromRef.current = to;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return val.toFixed(decimals);
}

/** Runs `fn` now and every `ms` milliseconds while mounted. */
function usePolling(fn, ms) {
  const saved = useRef(fn);
  useEffect(() => { saved.current = fn; }, [fn]);
  useEffect(() => {
    saved.current();
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [ms]);
}

/* --------------------------------------------------------------------------
   Inline SVG icons (no external images)
   -------------------------------------------------------------------------- */

const RadarIcon = () => (
  <svg className="radar" viewBox="0 0 40 40" aria-hidden="true">
    <circle cx="20" cy="20" r="18" className="radar-ring" />
    <circle cx="20" cy="20" r="11" className="radar-ring" />
    <circle cx="20" cy="20" r="4" className="radar-ring" />
    <g className="radar-sweep"><path d="M20 20 L20 2 A18 18 0 0 1 35.6 11 Z" /></g>
    <circle cx="28" cy="13" r="1.8" className="radar-blip" />
    <circle cx="20" cy="20" r="1.6" className="radar-core" />
  </svg>
);

const Icon = {
  inbox: (
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 13l2.5-8h13L21 13v6H3z" /><path d="M3 13h5l1.5 2.5h5L16 13h5" /></svg>
  ),
  shuffle: (
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h4l10 12h4M17 3l4 3-4 3M3 18h4l3-3.6M14 9.6L17 6h4M17 15l4 3-4 3" /></svg>
  ),
  chip: (
    <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1.5" /><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4M10 10h4v4h-4z" /></svg>
  ),
};

/* --------------------------------------------------------------------------
   Shared UI pieces
   -------------------------------------------------------------------------- */

/** Defense-score bar that fills from 0 on mount and re-animates on change. */
function ScoreBar({ value }) {
  const [w, setW] = useState(0);
  useEffect(() => { const t = setTimeout(() => setW(value), 60); return () => clearTimeout(t); }, [value]);
  return (
    <div className="scorebar" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value} aria-label="Defense score">
      <div className={`scorebar-fill tone-${scoreTone(value)}`} style={{ width: `${w}%` }} />
      <span className="scorebar-num">{value.toFixed(1)}</span>
    </div>
  );
}

/** [PHISH] / [LEGIT] style tag. */
const Tag = ({ phish }) => (
  <span className={`tag ${phish ? "tag-phish" : "tag-legit"}`}>{phish ? "[PHISH]" : "[LEGIT]"}</span>
);

/** Panel with a terminal-style header label. */
const Panel = ({ label, title, className = "", children, actions }) => (
  <section className={`panel ${className}`}>
    <header className="panel-head">
      <div>
        {label && <div className="term-label">&gt; {label}</div>}
        {title && <h2 className="panel-title">{title}</h2>}
      </div>
      {actions && <div className="panel-actions">{actions}</div>}
    </header>
    {children}
  </section>
);

/** Toast notifications (aria-live so screen readers announce feedback). */
function Toasts({ toasts, dismiss }) {
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          <div className="toast-head">
            <strong>{t.title}</strong>
            <button className="toast-x" onClick={() => dismiss(t.id)} aria-label="Dismiss notification">×</button>
          </div>
          {t.message && <p>{t.message}</p>}
          {t.flags && t.flags.length > 0 && (
            <ul className="flag-list">{t.flags.map((f, i) => <li key={i}>{f}</li>)}</ul>
          )}
        </div>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------------------
   Top navigation + agent switcher
   -------------------------------------------------------------------------- */

const VIEWS = [
  { id: "landing", label: "Home" },
  { id: "command", label: "Command Center" },
  { id: "inbox", label: "Inbox" },
  { id: "training", label: "Training Bay" },
];

function Nav({ view, setView, agents, agentId, setAgentId }) {
  const agent = agents.find((a) => a.id === agentId);
  return (
    <nav className="nav">
      <button className="logo" onClick={() => setView("landing")} aria-label="BAITWATCH home">
        <RadarIcon />
        <span className="logo-text">BAIT<span>WATCH</span></span>
      </button>

      <div className="nav-links" role="tablist" aria-label="Main views">
        {VIEWS.map((v) => (
          <button
            key={v.id}
            role="tab"
            aria-selected={view === v.id}
            className={`nav-link ${view === v.id ? "active" : ""}`}
            onClick={() => setView(v.id)}
          >
            {v.label}
          </button>
        ))}
      </div>

      <div className="agent-switch">
        <label htmlFor="agent-select" className="term-label">&gt; active_agent</label>
        <select id="agent-select" value={agentId || ""} onChange={(e) => setAgentId(Number(e.target.value))}>
          {agents.map((a) => (
            <option key={a.id} value={a.id}>{a.name} · {a.department}</option>
          ))}
        </select>
        {agent && (
          <div className="agent-status">
            <span className="dot" aria-hidden="true" /> agent_status: ONLINE ·{" "}
            <span className={`tone-text-${scoreTone(agent.defense_score)}`}>DEF {agent.defense_score.toFixed(1)}</span>
          </div>
        )}
      </div>
    </nav>
  );
}

/* --------------------------------------------------------------------------
   View 1: Landing
   -------------------------------------------------------------------------- */

function Landing({ setView }) {
  const tagline = useTypewriter("Every inbox is a battlefield.");
  const features = [
    { icon: Icon.inbox, tone: "threat", title: "Mixed Bait Inbox",
      text: "Real-looking phishing lures shuffled in with legitimate mail. Open, report or clear — every call moves your defense score." },
    { icon: Icon.shuffle, tone: "info", title: "Shuffled Intel Quizzes",
      text: "Four randomised questions per run — MFA fatigue, quishing, BEC, typosquats — with explanations for every answer." },
    { icon: Icon.chip, tone: "safe", title: "AI Threat Scanner",
      text: "A TF-IDF + logistic-regression model rates the phishing risk of any draft before it is deployed as a drill." },
  ];
  return (
    <div className="landing">
      <section className="hero">
        <div className="term-label">&gt; sys.init(baitwatch) … <span className="tone-text-safe">OK</span></div>
        <h1 className="glitch" data-text="BAITWATCH">BAITWATCH</h1>
        <p className="tagline" aria-label="Every inbox is a battlefield.">
          <span aria-hidden="true">{tagline}</span><span className="caret" aria-hidden="true">▌</span>
        </p>
        <p className="hero-sub">
          A safe phishing-defense simulator. Train your agents against live-fire bait, measure who bites,
          and turn every click into a lesson. All links resolve to <code>safe-training-domain.local</code>.
        </p>
        <div className="hero-cta">
          <button className="btn btn-primary" onClick={() => setView("inbox")}>Enter Inbox ▸</button>
          <button className="btn btn-ghost" onClick={() => setView("command")}>Command Center</button>
        </div>
      </section>

      <section className="features" aria-label="Features">
        {features.map((f) => (
          <article key={f.title} className={`panel feature feature-${f.tone}`}>
            <div className="feature-icon">{f.icon}</div>
            <h3>{f.title}</h3>
            <p>{f.text}</p>
          </article>
        ))}
      </section>
    </div>
  );
}

/* --------------------------------------------------------------------------
   View 2: Command Center (admin)
   -------------------------------------------------------------------------- */

function StatTile({ label, value, decimals = 0, tone }) {
  const shown = useCountUp(value, 900, decimals);
  return (
    <div className={`panel stat stat-${tone}`}>
      <div className="term-label">&gt; {label}</div>
      <div className="stat-value">{shown}</div>
    </div>
  );
}

/** Animated AI risk meter (bar + needle + count-up). */
function RiskMeter({ result, loading }) {
  const pct = result ? result.risk_probability : 0;
  const shown = useCountUp(pct, 1100, 1);
  const [w, setW] = useState(0);
  useEffect(() => { const t = setTimeout(() => setW(pct), 50); return () => clearTimeout(t); }, [pct]);

  if (loading) return <div className="risk-meter scanning"><div className="scan-beam" /> &gt; scanning payload…</div>;
  if (!result) return null;
  const tone = result.is_phishing ? "threat" : pct >= 35 ? "warn" : "safe";
  return (
    <div className={`risk-meter tone-border-${tone}`} aria-live="polite">
      <div className="risk-top">
        <span className={`risk-label tone-text-${tone}`}>{result.is_phishing ? "⚠ " : "✓ "}{result.label}</span>
        <span className={`risk-pct tone-text-${tone}`}>{shown}%</span>
      </div>
      <div className="risk-track">
        <div className="risk-fill" style={{ width: `${w}%` }} />
        <div className="risk-needle" style={{ left: `${w}%` }} />
        <div className="risk-threshold" title="Decision threshold: 50%" />
      </div>
      <div className="risk-scale"><span>0</span><span>50 — threshold</span><span>100</span></div>
      <div className="term-label">&gt; model: {result.algorithm}</div>
    </div>
  );
}

const EMPTY_DRILL = {
  title: "", sender: "", subject: "", body_text: "",
  simulated_url: "https://safe-training-domain.local/verify",
  difficulty: "Medium", is_suspicious: true, red_flags: "",
};

function DeployDrill({ onDeployed, pushToast }) {
  const [form, setForm] = useState(EMPTY_DRILL);
  const [scan, setScan] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  async function runScan() {
    if (!form.subject.trim() && !form.body_text.trim()) {
      pushToast({ type: "info", title: "Nothing to scan", message: "Add a subject or body first." });
      return;
    }
    setScanning(true); setScan(null);
    try {
      const [res] = await Promise.all([
        api("/api/ml/predict-email", { method: "POST", body: { subject: form.subject, body: form.body_text } }),
        new Promise((r) => setTimeout(r, 650)), // let the scan animation breathe
      ]);
      setScan(res);
    } catch (err) {
      pushToast({ type: "warning", title: "Scan failed", message: err.message });
    } finally { setScanning(false); }
  }

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      const d = await api("/api/drills", { method: "POST", body: form });
      pushToast({ type: "success", title: "Drill deployed", message: `"${d.subject}" sent to every agent.` });
      setForm(EMPTY_DRILL); setScan(null);
      onDeployed();
    } catch (err) {
      pushToast({ type: "warning", title: "Deploy failed", message: err.message });
    } finally { setBusy(false); }
  }

  return (
    <Panel label="drill.deploy()" title="Deploy Drill" className="deploy">
      <form onSubmit={submit} className="form">
        <div className="form-row">
          <label>Title<input value={form.title} onChange={set("title")} required minLength={2} placeholder="Fake invoice overdue" /></label>
          <label>Difficulty
            <select value={form.difficulty} onChange={set("difficulty")}>
              <option>Easy</option><option>Medium</option><option>Hard</option>
            </select>
          </label>
        </div>
        <label>Sender<input value={form.sender} onChange={set("sender")} required minLength={3} placeholder="Accounts <billing@nexac0rp-pay.biz>" /></label>
        <label>Subject<input value={form.subject} onChange={set("subject")} required minLength={2} placeholder="Invoice #4471 overdue — pay today" /></label>
        <label>Body<textarea rows={5} value={form.body_text} onChange={set("body_text")} required minLength={5} placeholder="Email body…" /></label>
        <label>Simulated URL <span className="hint">(must be safe-training-domain.local)</span>
          <input value={form.simulated_url} onChange={set("simulated_url")} required />
        </label>
        <label className="check">
          <input type="checkbox" checked={form.is_suspicious} onChange={set("is_suspicious")} />
          <span>This drill is phishing bait <span className="hint">(subject auto-prefixed with [SIMULATION])</span></span>
        </label>
        {form.is_suspicious && (
          <label>Red flags <span className="hint">(one per line)</span>
            <textarea rows={3} value={form.red_flags} onChange={set("red_flags")} placeholder={"Look-alike domain\nPayment pressure"} />
          </label>
        )}
        <div className="form-actions">
          <button type="button" className="btn btn-info" onClick={runScan} disabled={scanning}>
            {scanning ? "Scanning…" : "⌁ Scan with AI"}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Deploying…" : "Deploy ▸"}</button>
        </div>
      </form>
      <RiskMeter result={scan} loading={scanning} />
    </Panel>
  );
}

function RecruitAgent({ onCreated, pushToast }) {
  const blank = { name: "", email: "", department: "", role: "Agent" };
  const [f, setF] = useState(blank);
  const [open, setOpen] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  async function submit(e) {
    e.preventDefault();
    try {
      const a = await api("/api/agents", { method: "POST", body: f });
      pushToast({ type: "success", title: "Agent recruited", message: `${a.name} joined ${a.department}.` });
      setF(blank); setOpen(false); onCreated();
    } catch (err) { pushToast({ type: "warning", title: "Could not add agent", message: err.message }); }
  }
  if (!open) return <button className="btn btn-ghost btn-sm" onClick={() => setOpen(true)}>+ Recruit agent</button>;
  return (
    <form className="form recruit" onSubmit={submit}>
      <input aria-label="Name" placeholder="Name" value={f.name} onChange={set("name")} required minLength={2} />
      <input aria-label="Email" type="email" placeholder="email@nexacorp.com" value={f.email} onChange={set("email")} required />
      <input aria-label="Department" placeholder="Department" value={f.department} onChange={set("department")} required />
      <select aria-label="Role" value={f.role} onChange={set("role")}><option>Agent</option><option>Admin</option></select>
      <button className="btn btn-primary btn-sm" type="submit">Add</button>
      <button className="btn btn-ghost btn-sm" type="button" onClick={() => setOpen(false)}>Cancel</button>
    </form>
  );
}

const ACTION_META = {
  opened: { label: "OPENED", tone: "info" },
  clicked_link: { label: "CLICKED_LINK", tone: "threat" },
  reported: { label: "REPORTED", tone: "safe" },
  marked_safe: { label: "MARKED_SAFE", tone: "warn" },
};

function CommandCenter({ agents, refreshAgents, pushToast }) {
  const [stats, setStats] = useState(null);
  const [log, setLog] = useState([]);

  const load = useCallback(async () => {
    try {
      const [s, l] = await Promise.all([api("/api/stats"), api("/api/interactions?limit=20"), refreshAgents()]);
      setStats(s); setLog(l);
    } catch (_) { /* transient — next poll retries */ }
  }, [refreshAgents]);

  usePolling(load, 5000); // live log refresh

  async function reset() {
    if (!window.confirm("Reset the whole simulation to seed data? All interactions and quiz results will be erased.")) return;
    try {
      await api("/api/admin/reset", { method: "POST" });
      pushToast({ type: "info", title: "Simulation reset", message: "All data restored to the seed state." });
      load();
    } catch (err) { pushToast({ type: "warning", title: "Reset failed", message: err.message }); }
  }

  return (
    <div className="command">
      <div className="view-head">
        <div>
          <div className="term-label">&gt; role: ADMIN · uplink: SECURE</div>
          <h1 className="view-title">Command Center</h1>
        </div>
        <button className="btn btn-danger btn-sm" onClick={reset}>⟲ Reset simulation</button>
      </div>

      <div className="stats">
        <StatTile label="agents" value={stats ? stats.total_agents : 0} tone="info" />
        <StatTile label="drills" value={stats ? stats.total_drills : 0} tone="info" />
        <StatTile label="baits_taken" value={stats ? stats.baits_taken : 0} tone="threat" />
        <StatTile label="threats_reported" value={stats ? stats.threats_reported : 0} tone="safe" />
        <StatTile label="avg_defense" value={stats ? stats.avg_defense_score : 0} decimals={1} tone="warn" />
      </div>

      <div className="command-grid">
        <DeployDrill onDeployed={load} pushToast={pushToast} />

        <div className="command-side">
          <Panel label="agents.rank()" title="Leaderboard" actions={<RecruitAgent onCreated={load} pushToast={pushToast} />}>
            <div className="table-wrap">
              <table className="board">
                <thead>
                  <tr><th>#</th><th>Agent</th><th>Dept</th><th className="col-score">Defense</th><th title="Drills received">Drl</th><th title="Baits taken">Bait</th><th title="Threats reported">Rpt</th></tr>
                </thead>
                <tbody>
                  {agents.map((a, i) => (
                    <tr key={a.id}>
                      <td className="rank">{String(i + 1).padStart(2, "0")}</td>
                      <td>
                        <div className="agent-name">{a.name}{a.role === "Admin" && <span className="role-badge">ADMIN</span>}</div>
                        <div className="agent-mail">{a.email}</div>
                      </td>
                      <td>{a.department}</td>
                      <td className="col-score"><ScoreBar value={a.defense_score} /></td>
                      <td>{a.drills_received}</td>
                      <td className="tone-text-threat">{a.baits_taken}</td>
                      <td className="tone-text-safe">{a.threats_reported}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel label="tail -f interactions.log" title="Live Interaction Log" className="log-panel">
            <ol className="log" aria-live="off">
              {log.length === 0 && <li className="log-empty">&gt; awaiting activity…</li>}
              {log.map((e) => {
                const m = ACTION_META[e.action] || { label: e.action, tone: "info" };
                return (
                  <li key={e.id} className="log-line">
                    <span className="log-time">[{clock(e.timestamp)}]</span>{" "}
                    <span className="log-agent">{e.agent_name}</span>{" "}
                    <span className={`log-action tone-text-${m.tone}`}>{m.label}</span>{" "}
                    <Tag phish={e.is_suspicious} />{" "}
                    <span className="log-subject">{e.drill_subject}</span>
                  </li>
                );
              })}
            </ol>
          </Panel>
        </div>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------------
   View 3: Inbox (agent)
   -------------------------------------------------------------------------- */

function Inbox({ agent, refreshAgents, pushToast, triggerBreach }) {
  const [drills, setDrills] = useState([]);
  const [acts, setActs] = useState({});      // drillId -> Set(actions) for this agent
  const [selectedId, setSelectedId] = useState(null);
  const [busy, setBusy] = useState(false);
  const [stampId, setStampId] = useState(null);
  const [hoverUrl, setHoverUrl] = useState("");
  const orderRef = useRef(null);              // stable shuffled order for this session
  const readerRef = useRef(null);

  const loadActs = useCallback(async () => {
    if (!agent) return;
    const rows = await api(`/api/interactions?agent_id=${agent.id}&limit=500`);
    const map = {};
    rows.forEach((r) => { (map[r.drill_id] = map[r.drill_id] || new Set()).add(r.action); });
    setActs(map);
  }, [agent && agent.id]);

  useEffect(() => {
    (async () => {
      try {
        const list = await api("/api/drills");
        // "Mixed bait": shuffle once, then keep that order (new drills go on top).
        if (!orderRef.current) orderRef.current = shuffle(list.map((d) => d.id));
        const known = new Set(orderRef.current);
        const fresh = list.filter((d) => !known.has(d.id)).map((d) => d.id);
        orderRef.current = [...fresh, ...orderRef.current.filter((id) => list.some((d) => d.id === id))];
        const byId = Object.fromEntries(list.map((d) => [d.id, d]));
        setDrills(orderRef.current.map((id) => byId[id]));
      } catch (err) { pushToast({ type: "warning", title: "Inbox offline", message: err.message }); }
    })();
  }, []);

  useEffect(() => { setSelectedId(null); loadActs().catch(() => {}); }, [loadActs]);

  if (!agent) return <div className="empty">&gt; no agent selected</div>;

  const selected = drills.find((d) => d.id === selectedId);
  const has = (id, a) => !!(acts[id] && acts[id].has(a));
  const verdictOf = (id) => (has(id, "reported") ? "reported" : has(id, "marked_safe") ? "marked_safe" : null);
  const unread = drills.filter((d) => !has(d.id, "opened")).length;

  async function send(drillId, action) {
    const res = await api("/api/agent/interact", { method: "POST", body: { agent_id: agent.id, drill_id: drillId, action } });
    if (res.logged) setActs((prev) => ({ ...prev, [drillId]: new Set([...(prev[drillId] || []), action]) }));
    return res;
  }

  async function open(d) {
    setSelectedId(d.id);
    setHoverUrl("");
    if (window.matchMedia("(max-width: 900px)").matches && readerRef.current) {
      setTimeout(() => readerRef.current.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }
    if (!has(d.id, "opened")) send(d.id, "opened").catch(() => {});
  }

  async function act(action) {
    if (!selected || busy) return;
    setBusy(true);
    try {
      const res = await send(selected.id, action);
      if (res.effect === "breach") triggerBreach();
      if (res.effect === "neutralised") { setStampId(selected.id); setTimeout(() => setStampId(null), 2400); }
      const delta = res.score_delta ? ` (${res.score_delta > 0 ? "+" : ""}${res.score_delta} → ${res.new_score})` : "";
      pushToast({ type: res.feedback_type, title: res.title + delta, message: res.message, flags: res.red_flags });
      refreshAgents();
    } catch (err) {
      pushToast({ type: "warning", title: "Action failed", message: err.message });
    } finally { setBusy(false); }
  }

  const sender = selected ? parseSender(selected.sender) : null;
  const verdict = selected ? verdictOf(selected.id) : null;
  const revealed = selected && (verdict || (selected.is_suspicious && has(selected.id, "clicked_link")));

  return (
    <div className="inbox">
      <div className="view-head">
        <div>
          <div className="term-label">&gt; mailbox: {agent.email} · unread: {unread}</div>
          <h1 className="view-title">Inbox</h1>
        </div>
        <div className="term-label">&gt; hover links before you click. trust nothing.</div>
      </div>

      <div className="inbox-grid">
        <Panel label="mail.list()" className="mail-list-panel">
          <ul className="mail-list">
            {drills.map((d) => {
              const v = verdictOf(d.id);
              const s = parseSender(d.sender);
              return (
                <li key={d.id}>
                  <button
                    className={`mail-item ${selectedId === d.id ? "selected" : ""} ${has(d.id, "opened") ? "" : "unread"}`}
                    onClick={() => open(d)}
                    aria-current={selectedId === d.id}
                  >
                    <div className="mail-from">{s.name}</div>
                    <div className="mail-subject">{d.subject}</div>
                    <div className="mail-meta">
                      <span className={`diff diff-${d.difficulty.toLowerCase()}`}>{d.difficulty}</span>
                      {v && <Tag phish={d.is_suspicious} />}
                      {v && <span className={`verdict ${(v === "reported") === d.is_suspicious ? "ok" : "bad"}`}>
                        {(v === "reported") === d.is_suspicious ? "✓ correct" : "✗ wrong"}
                      </span>}
                      {!v && has(d.id, "clicked_link") && d.is_suspicious && <span className="verdict bad">⚠ clicked</span>}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </Panel>

        <section className="panel reader" ref={readerRef} aria-label="Email reader">
          {!selected ? (
            <div className="reader-empty">
              <RadarIcon />
              <p>&gt; select a message to inspect it</p>
            </div>
          ) : (
            <>
              {stampId === selected.id && <div className="stamp" role="img" aria-label="Threat neutralised">THREAT<br />NEUTRALISED</div>}
              <header className="reader-head">
                <h2 className="reader-subject">{selected.subject}</h2>
                <dl className="reader-meta">
                  <div><dt>from</dt><dd><strong>{sender.name}</strong> {sender.address && <span className="addr">&lt;{sender.address}&gt;</span>}</dd></div>
                  <div><dt>to</dt><dd>{agent.email}</dd></div>
                  <div><dt>level</dt><dd><span className={`diff diff-${selected.difficulty.toLowerCase()}`}>{selected.difficulty}</span> {revealed && <Tag phish={selected.is_suspicious} />}</dd></div>
                </dl>
              </header>

              <div className="reader-body">{selected.body_text}</div>

              <p className="reader-linkline">
                <button
                  className="fake-link"
                  onMouseEnter={() => setHoverUrl(selected.simulated_url)}
                  onMouseLeave={() => setHoverUrl("")}
                  onFocus={() => setHoverUrl(selected.simulated_url)}
                  onBlur={() => setHoverUrl("")}
                  onClick={() => act("clicked_link")}
                >
                  {selected.is_suspicious ? "▸ Secure link: click here to continue" : "▸ View details"}
                </button>
              </p>

              {revealed && selected.is_suspicious && selected.red_flags.length > 0 && (
                <div className="debrief">
                  <div className="term-label tone-text-threat">&gt; debrief.red_flags</div>
                  <ul className="flag-list">{selected.red_flags.map((f, i) => <li key={i}>{f}</li>)}</ul>
                </div>
              )}

              <div className="reader-actions">
                <button className="btn btn-danger" onClick={() => act("clicked_link")} disabled={busy}>⇗ Open Link</button>
                <button className="btn btn-primary" onClick={() => act("reported")} disabled={busy || !!verdict}>⚑ Report Threat</button>
                <button className="btn btn-info" onClick={() => act("marked_safe")} disabled={busy || !!verdict}>✓ Mark Safe</button>
              </div>
              {verdict && <div className="term-label">&gt; verdict_filed: {verdict.toUpperCase()}</div>}

              <div className="statusbar" aria-live="polite">{hoverUrl ? `→ ${hoverUrl}` : " "}</div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------------
   View 4: Training Bay
   -------------------------------------------------------------------------- */

function ModuleCard({ mod, index }) {
  const [open, setOpen] = useState(index === 0);
  const id = `mod-${mod.id}`;
  return (
    <article className={`panel module ${open ? "open" : ""}`}>
      <button className="module-head" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
        <span className="module-num">M{String(index + 1).padStart(2, "0")}</span>
        <span className="module-title">{mod.title}</span>
        <span className="module-chev" aria-hidden="true">{open ? "−" : "+"}</span>
      </button>
      <div id={id} className="module-body" hidden={!open}>
        <p>{mod.summary}</p>
        <ul className="tips">{mod.tips.map((t, i) => <li key={i}>{t}</li>)}</ul>
        <div className="term-label">&gt; {mod.reason}</div>
      </div>
    </article>
  );
}

function Quiz({ agent, onGraded, pushToast }) {
  const [questions, setQuestions] = useState([]);
  const [answers, setAnswers] = useState({});
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setResult(null); setAnswers({});
    try { setQuestions(await api("/api/training/quiz-questions?count=4")); }
    catch (err) { pushToast({ type: "warning", title: "Quiz unavailable", message: err.message }); }
  }, []);
  useEffect(() => { load(); }, [load, agent.id]);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api("/api/training/quiz", {
        method: "POST",
        body: { agent_id: agent.id, answers: questions.map((q) => ({ question_id: q.id, selected_index: answers[q.id] })) },
      });
      setResult(res);
      pushToast({
        type: res.score === res.total ? "success" : "info",
        title: `Quiz graded: ${res.score}/${res.total}`,
        message: `Bonus +${res.bonus} → defense score ${res.new_score}.`,
      });
      onGraded();
    } catch (err) { pushToast({ type: "warning", title: "Submit failed", message: err.message }); }
    finally { setBusy(false); }
  }

  const complete = questions.length > 0 && questions.every((q) => answers[q.id] !== undefined);

  if (result) {
    return (
      <Panel label="quiz.review()" title={`Results — ${result.score}/${result.total}`}
        actions={<button className="btn btn-info btn-sm" onClick={load}>↻ New shuffled quiz</button>}>
        <div className="quiz-score">
          <ScoreBar value={(result.score / result.total) * 100} />
          <span className="term-label">&gt; bonus +{result.bonus} · new score {result.new_score}</span>
        </div>
        <ol className="review">
          {result.review.map((r) => (
            <li key={r.question_id} className={`review-item ${r.is_correct ? "ok" : "bad"}`}>
              <div className="review-topic">{r.is_correct ? "✓" : "✗"} {r.topic}</div>
              <p className="q-text">{r.question}</p>
              <p>Your answer: <span className={r.is_correct ? "tone-text-safe" : "tone-text-threat"}>{r.options[r.selected_index] || "—"}</span></p>
              {!r.is_correct && <p>Correct: <span className="tone-text-safe">{r.options[r.correct_index]}</span></p>}
              <p className="explain">{r.explanation}</p>
            </li>
          ))}
        </ol>
      </Panel>
    );
  }

  return (
    <Panel label="quiz.shuffle(4)" title="Intel Quiz" actions={<button className="btn btn-ghost btn-sm" onClick={load}>↻ Re-roll</button>}>
      <form onSubmit={submit} className="quiz">
        {questions.map((q, qi) => (
          <fieldset key={q.id} className="question">
            <legend><span className="q-num">Q{qi + 1}</span> <span className="q-topic">{q.topic}</span></legend>
            <p className="q-text">{q.question}</p>
            <div className="options">
              {q.options.map((opt, oi) => (
                <label key={oi} className={`option ${answers[q.id] === oi ? "picked" : ""}`}>
                  <input type="radio" name={`q-${q.id}`} checked={answers[q.id] === oi} onChange={() => setAnswers({ ...answers, [q.id]: oi })} />
                  <span className="opt-key">{String.fromCharCode(65 + oi)}</span>
                  <span>{opt}</span>
                </label>
              ))}
            </div>
          </fieldset>
        ))}
        <button className="btn btn-primary" type="submit" disabled={!complete || busy}>
          {busy ? "Grading…" : complete ? "Submit answers ▸" : `Answer all ${questions.length} questions`}
        </button>
      </form>
    </Panel>
  );
}

function TrainingBay({ agent, refreshAgents, pushToast }) {
  const [data, setData] = useState(null);
  const load = useCallback(async () => {
    if (!agent) return;
    try { setData(await api(`/api/training/${agent.id}`)); }
    catch (err) { pushToast({ type: "warning", title: "Training offline", message: err.message }); }
  }, [agent && agent.id]);
  useEffect(() => { load(); }, [load]);

  if (!agent) return <div className="empty">&gt; no agent selected</div>;
  return (
    <div className="training">
      <div className="view-head">
        <div>
          <div className="term-label">&gt; adaptive_curriculum for {agent.name} · score {agent.defense_score.toFixed(1)} · baits {agent.baits_taken}</div>
          <h1 className="view-title">Training Bay</h1>
        </div>
      </div>
      <div className="training-grid">
        <div className="modules">
          <div className="term-label">&gt; assigned_modules: {data ? data.modules.length : "…"}</div>
          {data && data.modules.map((m, i) => <ModuleCard key={m.id} mod={m} index={i} />)}
        </div>
        <Quiz agent={agent} pushToast={pushToast} onGraded={() => { refreshAgents(); load(); }} />
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------------
   Root app
   -------------------------------------------------------------------------- */

function App() {
  const [view, setViewState] = useState(() => store.get("bw.view", "landing"));
  const [agents, setAgents] = useState([]);
  const [agentId, setAgentIdState] = useState(() => store.get("bw.agent", null));
  const [toasts, setToasts] = useState([]);
  const [breach, setBreach] = useState(false);

  const setView = (v) => { setViewState(v); store.set("bw.view", v); window.scrollTo({ top: 0 }); };
  const setAgentId = (id) => { setAgentIdState(id); store.set("bw.agent", id); };

  const refreshAgents = useCallback(async () => {
    const list = await api("/api/agents");
    setAgents(list);
    // Keep the selection valid (e.g. after a reset); default to the first non-admin agent.
    setAgentIdState((cur) => {
      if (list.some((a) => a.id === cur)) return cur;
      const pick = (list.find((a) => a.role === "Agent") || list[0] || {}).id || null;
      store.set("bw.agent", pick);
      return pick;
    });
    return list;
  }, []);

  useEffect(() => { refreshAgents().catch(() => {}); }, [refreshAgents]);

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const pushToast = useCallback((t) => {
    if (!t || t.type === "none") return;
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { ...t, id }]);
    setTimeout(() => dismiss(id), t.flags && t.flags.length ? 9000 : 5000);
  }, [dismiss]);

  /** Red screen-shake + glitch flash when a bait link is clicked. */
  const triggerBreach = useCallback(() => {
    setBreach(false);
    requestAnimationFrame(() => setBreach(true));
    setTimeout(() => setBreach(false), 900);
  }, []);

  const agent = agents.find((a) => a.id === agentId) || null;

  return (
    <div className={`app ${breach ? "shake" : ""}`}>
      {breach && <div className="breach-flash" aria-hidden="true"><span className="glitch" data-text="BREACH DETECTED">BREACH DETECTED</span></div>}
      <Nav view={view} setView={setView} agents={agents} agentId={agentId} setAgentId={setAgentId} />
      <main className="main">
        {view === "landing" && <Landing setView={setView} />}
        {view === "command" && <CommandCenter agents={agents} refreshAgents={refreshAgents} pushToast={pushToast} />}
        {view === "inbox" && <Inbox key={agentId} agent={agent} refreshAgents={refreshAgents} pushToast={pushToast} triggerBreach={triggerBreach} />}
        {view === "training" && <TrainingBay key={agentId} agent={agent} refreshAgents={refreshAgents} pushToast={pushToast} />}
      </main>
      <footer className="footer">
        <span>&gt; BAITWATCH v1.0 · training simulation only · all links → safe-training-domain.local</span>
      </footer>
      <Toasts toasts={toasts} dismiss={dismiss} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
