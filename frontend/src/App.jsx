import { useState, useEffect, useRef, useCallback } from "react";

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const API_BASE = import.meta?.env?.VITE_API_URL || "http://localhost:8000";
const WS_BASE  = API_BASE.replace(/^http/, "ws");

const api = {
  get:  (path)       => fetch(`${API_BASE}${path}`).then(r => r.json()),
  post: (path, body) => fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).then(r => r.json()),
  delete: (path) => fetch(`${API_BASE}${path}`, {
    method: "DELETE",
  }).then(r => r.json()),
};

// ─────────────────────────────────────────────
// STYLES
// ─────────────────────────────────────────────
const S = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&family=Inter:wght@300;400;500&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#0a0b0e; --bg2:#0f1117; --bg3:#151820; --bg4:#1c2030;
    --border:rgba(255,255,255,0.07); --border-hi:rgba(255,255,255,0.15);
    --text:#e8eaf0; --muted:#5a6070; --dim:#8890a0;
    --red:#e84040; --red-glow:rgba(232,64,64,0.15);
    --green:#22c55e; --yellow:#f59e0b; --blue:#3b82f6; --orange:#ff6b35;
    --purple:#a855f7;
  }
  body { background:var(--bg); color:var(--text); font-family:'Inter',sans-serif; min-height:100vh; }
  .app { display:flex; flex-direction:column; min-height:100vh; }
  .header { display:flex; align-items:center; justify-content:space-between; padding:0 32px; height:64px; border-bottom:1px solid var(--border); background:rgba(10,11,14,0.97); position:sticky; top:0; z-index:100; backdrop-filter:blur(12px); }
  .logo { display:flex; align-items:center; gap:12px; }
  .logo-hex { width:30px; height:30px; background:var(--red); clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%); box-shadow:0 0 16px var(--red-glow); flex-shrink:0; }
  .logo-name { font-family:'Syne',sans-serif; font-weight:800; font-size:18px; letter-spacing:-0.5px; }
  .logo-name span { color:var(--red); }
  .header-nav { display:flex; gap:4px; }
  .nav-btn { padding:6px 16px; border-radius:6px; font-size:13px; cursor:pointer; border:none; background:transparent; color:var(--dim); transition:all .2s; font-family:'Inter',sans-serif; }
  .nav-btn:hover { background:var(--bg3); color:var(--text); }
  .nav-btn.on { background:var(--bg3); color:var(--text); border:1px solid var(--border-hi); }
  .pulse-dot { width:6px; height:6px; border-radius:50%; background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .status-row { display:flex; align-items:center; gap:8px; font-size:12px; color:var(--muted); font-family:'DM Mono',monospace; }
  .body { display:flex; flex:1; }
  .sidebar { width:240px; flex-shrink:0; border-right:1px solid var(--border); padding:20px 12px; display:flex; flex-direction:column; gap:6px; background:var(--bg2); }
  .slabel { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1.5px; padding:6px 8px; margin-top:8px; font-family:'DM Mono',monospace; }
  .sitem { display:flex; align-items:center; gap:10px; padding:9px 12px; border-radius:8px; cursor:pointer; font-size:13px; color:var(--dim); transition:all .15s; border:1px solid transparent; }
  .sitem:hover { background:var(--bg3); color:var(--text); }
  .sitem.on { background:var(--red-glow); color:var(--text); border-color:rgba(232,64,64,.25); }
  .sbadge { margin-left:auto; background:var(--red); color:#fff; font-size:10px; padding:2px 6px; border-radius:10px; font-family:'DM Mono',monospace; animation:pulse 1.5s infinite; }
  .content { flex:1; padding:32px; overflow-y:auto; }
  .card { background:var(--bg2); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:16px; }
  .ctitle { font-family:'Syne',sans-serif; font-size:15px; font-weight:700; margin-bottom:16px; display:flex; align-items:center; gap:8px; }
  .fg { margin-bottom:20px; }
  .flabel { font-size:12px; color:var(--dim); margin-bottom:8px; display:block; font-weight:500; text-transform:uppercase; letter-spacing:.8px; }
  .finput { width:100%; padding:11px 15px; background:var(--bg3); border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:14px; font-family:'Inter',sans-serif; outline:none; transition:all .2s; }
  .finput:focus { border-color:rgba(232,64,64,.5); box-shadow:0 0 0 3px rgba(232,64,64,.07); }
  .finput::placeholder { color:var(--muted); }
  .grid2 { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }
  .grid3 { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
  .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
  .sel-card { padding:15px; border:1px solid var(--border); border-radius:10px; cursor:pointer; transition:all .2s; background:var(--bg3); }
  .sel-card:hover { border-color:var(--border-hi); }
  .sel-card.on { border-color:var(--red); background:var(--red-glow); }
  .sel-card .ic { font-size:22px; margin-bottom:8px; }
  .sel-card .nm { font-size:13px; font-weight:600; margin-bottom:4px; }
  .sel-card .ds { font-size:11px; color:var(--muted); line-height:1.5; }
  .sel-card.agent.on { border-color:var(--blue); background:rgba(59,130,246,.08); }
  .caps { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; }
  .cap { font-size:10px; padding:2px 7px; border-radius:10px; background:rgba(59,130,246,.12); color:var(--blue); font-family:'DM Mono',monospace; }
  .int-row { display:flex; gap:8px; }
  .int-btn { flex:1; padding:10px 6px; border-radius:8px; border:1px solid var(--border); cursor:pointer; text-align:center; font-size:12px; font-weight:600; background:var(--bg3); color:var(--dim); transition:all .2s; }
  .int-btn:hover { border-color:var(--border-hi); color:var(--text); }
  .int-dot { width:8px; height:8px; border-radius:50%; margin:0 auto 5px; }
  .int-sub { font-size:10px; font-weight:400; opacity:.7; margin-top:3px; }
  .steps { display:flex; align-items:center; margin-bottom:36px; }
  .sc { width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:600; flex-shrink:0; border:2px solid var(--border); font-family:'DM Mono',monospace; transition:all .3s; cursor:default; }
  .sc.done { background:var(--red); border-color:var(--red); color:#fff; }
  .sc.active { border-color:var(--red); color:var(--red); box-shadow:0 0 14px var(--red-glow); }
  .sc.prev { cursor:pointer; }
  .sc.prev:hover { border-color:var(--border-hi); }
  .sl { font-size:13px; color:var(--muted); margin-left:8px; }
  .sl.active { color:var(--text); }
  .scon { flex:1; height:1px; background:var(--border); margin:0 12px; }
  .scon.done { background:rgba(232,64,64,.3); }
  .btn { padding:11px 22px; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; border:none; transition:all .2s; font-family:'Inter',sans-serif; display:inline-flex; align-items:center; gap:7px; }
  .btn-p { background:var(--red); color:#fff; }
  .btn-p:hover:not(:disabled) { background:#c93535; box-shadow:0 4px 18px rgba(232,64,64,.3); transform:translateY(-1px); }
  .btn-p:disabled { opacity:.45; cursor:not-allowed; }
  .btn-s { background:var(--bg3); color:var(--text); border:1px solid var(--border); }
  .btn-s:hover { border-color:var(--border-hi); }
  .btn-row { display:flex; gap:12px; justify-content:flex-end; margin-top:28px; }
  .rv-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-bottom:16px; }
  .rv-item { background:var(--bg3); border:1px solid var(--border); border-radius:8px; padding:14px; }
  .rv-lbl { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:4px; font-family:'DM Mono',monospace; }
  .rv-val { font-size:13px; font-weight:600; word-break:break-all; }
  .stat { background:var(--bg2); border:1px solid var(--border); border-radius:12px; padding:20px; }
  .stat-lbl { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; font-family:'DM Mono',monospace; }
  .stat-val { font-family:'Syne',sans-serif; font-size:28px; font-weight:800; }
  .stat-sub { font-size:11px; color:var(--muted); margin-top:4px; }
  .prog-wrap { background:var(--bg3); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:20px; }
  .prog-top { display:flex; justify-content:space-between; margin-bottom:10px; font-size:13px; }
  .prog-track { height:7px; background:var(--bg); border-radius:4px; overflow:hidden; }
  .prog-fill { height:100%; border-radius:4px; background:linear-gradient(90deg,var(--red),var(--orange)); transition:width .8s ease; }
  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:20px; }
  .tab { padding:10px 18px; font-size:13px; cursor:pointer; border:none; background:transparent; color:var(--muted); border-bottom:2px solid transparent; margin-bottom:-1px; font-family:'Inter',sans-serif; transition:all .2s; }
  .tab:hover { color:var(--text); }
  .tab.on { color:var(--text); border-bottom-color:var(--red); }
  .agent-row { display:flex; align-items:center; gap:14px; padding:13px 16px; background:var(--bg3); border:1px solid var(--border); border-radius:10px; margin-bottom:8px; transition:all .2s; }
  .agent-row:hover { border-color:var(--border-hi); }
  .adot { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
  .adot.running { background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 1.5s infinite; }
  .adot.done    { background:var(--muted); }
  .adot.error   { background:var(--red); }
  .adot.pending { background:var(--yellow); }
  .ainfo { flex:1; }
  .aname { font-size:13px; font-weight:600; }
  .atask { font-size:11px; color:var(--muted); font-family:'DM Mono',monospace; margin-top:2px; }
  .abar { width:110px; height:4px; background:var(--border); border-radius:2px; overflow:hidden; }
  .afill { height:100%; border-radius:2px; transition:width .5s; }
  .afill.running { background:var(--green); }
  .afill.done    { background:var(--muted); }
  .afill.error   { background:var(--red); }
  .apct { font-size:11px; color:var(--muted); font-family:'DM Mono',monospace; width:34px; text-align:right; }
  .logbox { background:#050608; border:1px solid var(--border); border-radius:10px; padding:16px; font-family:'DM Mono',monospace; font-size:11.5px; height:220px; overflow-y:auto; line-height:1.8; }
  .ltime { color:var(--muted); flex-shrink:0; }
  .linfo { color:var(--blue); }
  .lwarn { color:var(--yellow); }
  .lerror { color:var(--red); }
  .lok   { color:var(--green); }
  .lmsg  { color:var(--dim); }
  .finding { display:flex; gap:14px; align-items:flex-start; padding:15px; background:var(--bg3); border:1px solid var(--border); border-radius:10px; margin-bottom:8px; cursor:pointer; transition:all .2s; }
  .finding:hover { border-color:var(--border-hi); }
  .fsev { padding:4px 10px; border-radius:6px; font-size:10px; font-weight:700; text-transform:uppercase; font-family:'DM Mono',monospace; flex-shrink:0; margin-top:2px; white-space:nowrap; }
  .sKRITISCH,.sCRITICAL { background:rgba(232,64,64,.12); color:var(--red); border:1px solid rgba(232,64,64,.25); }
  .sHOCH,.sHIGH        { background:rgba(255,107,53,.12); color:var(--orange); border:1px solid rgba(255,107,53,.25); }
  .sMITTEL,.sMEDIUM    { background:rgba(245,158,11,.12); color:var(--yellow); border:1px solid rgba(245,158,11,.25); }
  .sINFO,.sLOW         { background:rgba(59,130,246,.1); color:var(--blue); border:1px solid rgba(59,130,246,.25); }
  .ftitle { font-size:13px; font-weight:600; margin-bottom:4px; }
  .fdesc  { font-size:12px; color:var(--muted); line-height:1.5; }
  .fagent { font-size:11px; color:var(--muted); margin-top:5px; font-family:'DM Mono',monospace; }
  .risk-box { display:flex; align-items:center; gap:28px; padding:22px; background:var(--bg3); border:1px solid var(--border); border-radius:12px; margin-bottom:20px; }
  .risk-circle { width:96px; height:96px; border-radius:50%; flex-shrink:0; display:flex; flex-direction:column; align-items:center; justify-content:center; border:3px solid var(--red); box-shadow:0 0 28px var(--red-glow),inset 0 0 20px rgba(232,64,64,.05); background:rgba(232,64,64,.05); }
  .risk-num { font-family:'Syne',sans-serif; font-size:30px; font-weight:800; color:var(--red); line-height:1; }
  .risk-lbl { font-size:9px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-top:3px; }
  .badge { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:20px; font-size:11px; font-weight:600; border:1px solid; margin-bottom:8px; font-family:'DM Mono',monospace; }
  .badge-red    { background:rgba(232,64,64,.1); color:var(--red); border-color:rgba(232,64,64,.3); }
  .badge-green  { background:rgba(34,197,94,.08); color:var(--green); border-color:rgba(34,197,94,.25); }
  .badge-blue   { background:rgba(59,130,246,.08); color:var(--blue); border-color:rgba(59,130,246,.25); }
  .badge-purple { background:rgba(168,85,247,.08); color:var(--purple); border-color:rgba(168,85,247,.25); }
  .ph { text-align:center; padding:56px 32px; color:var(--muted); }
  .ph-icon { font-size:44px; margin-bottom:14px; opacity:.4; }
  .alert { padding:12px 16px; border-radius:8px; font-size:12px; margin-bottom:14px; display:flex; align-items:flex-start; gap:10px; background:rgba(245,158,11,.07); border:1px solid rgba(245,158,11,.2); color:var(--dim); }
  .kpi-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }
  .kpi { background:var(--bg3); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
  .kvi { font-family:'Syne',sans-serif; font-size:22px; font-weight:800; margin-bottom:3px; }
  .kvl { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; }
  .section-title { font-family:'Syne',sans-serif; font-size:15px; font-weight:700; margin-bottom:14px; display:flex; align-items:center; gap:8px; }
  .no-agents { padding:20px; background:rgba(245,158,11,.06); border:1px solid rgba(245,158,11,.18); border-radius:10px; font-size:13px; color:var(--yellow); }
  .loading { display:flex; align-items:center; gap:10px; color:var(--muted); font-size:13px; padding:24px 0; }
  @keyframes spin { to{transform:rotate(360deg)} }
  .spinner { width:16px; height:16px; border:2px solid var(--border); border-top-color:var(--red); border-radius:50%; animation:spin .7s linear infinite; }
  @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
  .fi { animation:fadeIn .25s ease forwards; }
  ::-webkit-scrollbar { width:4px; } ::-webkit-scrollbar-track { background:transparent; } ::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }

  /* Agent management */
  .agent-card { background:var(--bg3); border:1px solid var(--border); border-radius:10px; padding:18px; display:flex; align-items:center; gap:16px; margin-bottom:10px; transition:all .2s; }
  .agent-card:hover { border-color:var(--border-hi); }
  .agent-card-ic { font-size:28px; flex-shrink:0; }
  .agent-card-info { flex:1; min-width:0; }
  .agent-card-name { font-size:14px; font-weight:600; margin-bottom:3px; }
  .agent-card-url { font-size:11px; color:var(--muted); font-family:'DM Mono',monospace; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .agent-card-caps { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; }
  .agent-status-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
  .agent-status-dot.online { background:var(--green); box-shadow:0 0 8px var(--green); animation:pulse 2s infinite; }
  .agent-status-dot.manual { background:var(--yellow); box-shadow:0 0 8px var(--yellow); }
  .btn-danger { background:rgba(232,64,64,.1); color:var(--red); border:1px solid rgba(232,64,64,.2); }
  .btn-danger:hover { background:rgba(232,64,64,.2); border-color:var(--red); }
  .reg-form { background:var(--bg3); border:1px solid var(--border); border-radius:12px; padding:24px; margin-top:16px; }
  .reg-form.collapsed { display:none; }
  .icon-picker { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }
  .icon-opt { width:36px; height:36px; border-radius:8px; border:1px solid var(--border); background:var(--bg); cursor:pointer; font-size:18px; display:flex; align-items:center; justify-content:center; transition:all .2s; }
  .icon-opt:hover { border-color:var(--border-hi); background:var(--bg3); }
  .icon-opt.on { border-color:var(--blue); background:rgba(59,130,246,.12); }
  .tag-input-wrap { display:flex; flex-wrap:wrap; gap:6px; padding:8px 12px; background:var(--bg3); border:1px solid var(--border); border-radius:8px; cursor:text; min-height:44px; align-items:center; }
  .tag-input-wrap:focus-within { border-color:rgba(232,64,64,.5); box-shadow:0 0 0 3px rgba(232,64,64,.07); }
  .tag-chip { display:inline-flex; align-items:center; gap:5px; padding:3px 10px; background:rgba(59,130,246,.12); color:var(--blue); border-radius:20px; font-size:11px; font-family:'DM Mono',monospace; }
  .tag-chip button { background:none; border:none; color:var(--blue); cursor:pointer; padding:0; font-size:13px; line-height:1; opacity:.7; }
  .tag-chip button:hover { opacity:1; }
  .tag-bare-input { background:transparent; border:none; outline:none; color:var(--text); font-size:13px; min-width:80px; font-family:'Inter',sans-serif; flex:1; }
  .success-banner { background:rgba(34,197,94,.08); border:1px solid rgba(34,197,94,.25); color:var(--green); padding:12px 16px; border-radius:8px; font-size:13px; margin-bottom:14px; display:flex; align-items:center; gap:10px; }
  .error-banner { background:rgba(232,64,64,.08); border:1px solid rgba(232,64,64,.25); color:var(--red); padding:12px 16px; border-radius:8px; font-size:13px; margin-bottom:14px; display:flex; align-items:center; gap:10px; }

  /* Kill-Chain */
  .kc-track { display:flex; align-items:center; gap:0; margin-bottom:24px; }
  .kc-phase { flex:1; text-align:center; padding:14px 8px; background:var(--bg3); border:1px solid var(--border); position:relative; cursor:default; transition:all .3s; }
  .kc-phase:first-child { border-radius:10px 0 0 10px; }
  .kc-phase:last-child { border-radius:0 10px 10px 0; }
  .kc-phase.active { background:rgba(232,64,64,.1); border-color:rgba(232,64,64,.3); }
  .kc-phase.done { background:rgba(34,197,94,.08); border-color:rgba(34,197,94,.2); }
  .kc-ic { font-size:18px; margin-bottom:4px; }
  .kc-name { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.6px; }
  .kc-status { font-size:9px; color:var(--muted); margin-top:3px; font-family:'DM Mono',monospace; }

  /* Module cards */
  .mod-card { background:var(--bg3); border:1px solid var(--border); border-radius:10px; padding:16px; transition:all .2s; }
  .mod-card:hover { border-color:var(--border-hi); }
  .mod-ic { font-size:24px; margin-bottom:8px; }
  .mod-name { font-size:13px; font-weight:600; margin-bottom:4px; }
  .mod-desc { font-size:11px; color:var(--muted); line-height:1.5; margin-bottom:8px; }
  .mod-tag { display:inline-block; font-size:9px; padding:2px 8px; border-radius:10px; font-family:'DM Mono',monospace; margin-right:4px; }
  .mod-tag-phase { background:rgba(168,85,247,.1); color:var(--purple); }
  .mod-tag-type { background:rgba(59,130,246,.1); color:var(--blue); }
`;

// ─────────────────────────────────────────────
// STATIC DATA
// ─────────────────────────────────────────────
const INTENSITY = [
  { id:"low",      label:"Sanft",      sub:"Nur Aufklaerung", color:"#22c55e" },
  { id:"medium",   label:"Moderat",    sub:"Standard-Test",   color:"#f59e0b" },
  { id:"high",     label:"Intensiv",   sub:"Tiefe Analyse",   color:"#ff6b35" },
  { id:"critical", label:"Vollstaendig",sub:"Alle Methoden",  color:"#e84040" },
];

const KILL_CHAIN = [
  { id:"recon",       icon:"🔭", name:"Reconnaissance",  phase:1 },
  { id:"poisoning",   icon:"🧪", name:"Poisoning",       phase:2 },
  { id:"hijacking",   icon:"🔓", name:"Hijacking",       phase:3 },
  { id:"persistence", icon:"🔗", name:"Persistence",     phase:4 },
  { id:"pivot",       icon:"🔀", name:"Pivot",           phase:5 },
  { id:"impact",      icon:"💥", name:"Impact",          phase:6 },
];

const MODULES = [
  { id:"system_prompt_extraction", icon:"📜", name:"System Prompt Extraction", desc:"Extrahiert versteckte System-Prompts aus KI-Modellen durch gezielte Prompt-Techniken.", phase:"Reconnaissance", type:"passive" },
  { id:"prompt_injection",         icon:"💉", name:"Prompt Injection",         desc:"Injiziert bösartige Anweisungen in KI-Systeme zur Umgehung von Sicherheitsregeln.", phase:"Poisoning",       type:"active" },
  { id:"jailbreak",                icon:"🔓", name:"Jailbreak",                desc:"Umgeht Sicherheitsbeschränkungen von KI-Modellen durch kreative Prompt-Strategien.", phase:"Hijacking",       type:"active" },
  { id:"tool_abuse",               icon:"🔧", name:"Tool Abuse",               desc:"Missbraucht Tool-Aufrufe und Funktions-Interfaces von KI-Systemen.",                 phase:"Hijacking",       type:"active" },
  { id:"data_exfiltration",        icon:"📤", name:"Data Exfiltration",        desc:"Extrahiert sensible Daten aus KI-Systemen durch gezielte Abfragen.",                  phase:"Impact",          type:"active" },
  { id:"social_engineering",       icon:"🎭", name:"Social Engineering",       desc:"Manipuliert KI-Assistenten durch soziale Interaktionsmuster.",                         phase:"Persistence",     type:"passive" },
];

function riskScore(findings = []) {
  const weights = { KRITISCH:25, CRITICAL:25, HOCH:15, HIGH:15, MITTEL:7, MEDIUM:7, INFO:1, LOW:1 };
  return Math.min(100, findings.reduce((s, f) => s + (weights[f.severity?.toUpperCase()] || 0), 0));
}

function generateReport(mission, agents) {
  const rs = riskScore(mission.findings);
  const now = new Date().toLocaleDateString("de-DE", { year:"numeric", month:"long", day:"numeric" });
  let md = `# REDSWARM Security Report\n\n`;
  md += `**Mission:** ${mission.config?.name || mission.id}\n`;
  md += `**Ziel:** ${mission.config?.target_url}\n`;
  md += `**Datum:** ${now}\n`;
  md += `**Risiko-Score:** ${rs}/100\n\n`;
  md += `## Zusammenfassung\n\n`;
  md += `${mission.findings?.length || 0} Sicherheitsprobleme gefunden.\n\n`;
  md += `| Schweregrad | Anzahl |\n|---|---|\n`;
  const sevs = ["KRITISCH","HOCH","MITTEL","INFO"];
  sevs.forEach(s => {
    const count = (mission.findings||[]).filter(f => {
      const us = f.severity?.toUpperCase();
      if (s === "KRITISCH") return us === "KRITISCH" || us === "CRITICAL";
      if (s === "HOCH") return us === "HOCH" || us === "HIGH";
      if (s === "MITTEL") return us === "MITTEL" || us === "MEDIUM";
      return us === "INFO" || us === "LOW";
    }).length;
    md += `| ${s} | ${count} |\n`;
  });
  md += `\n## Findings\n\n`;
  (mission.findings||[]).forEach((f, i) => {
    const agentName = agents.find(a => a.agent_id === f.agent_id)?.name || f.agent_id;
    md += `### ${i+1}. ${f.title}\n`;
    md += `- **Schweregrad:** ${f.severity}\n`;
    md += `- **Agent:** ${agentName}\n`;
    md += `- **Beschreibung:** ${f.description}\n`;
    if (f.evidence) md += `- **Evidenz:** ${f.evidence}\n`;
    if (f.remediation) md += `- **Empfehlung:** ${f.remediation}\n`;
    md += `\n`;
  });
  md += `---\n*Generiert von REDSWARM AI Red Team*\n`;
  return md;
}

// ─────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────
export default function App() {
  const [view,    setView]    = useState("wizard");
  const [step,    setStep]    = useState(1);

  const [agents,   setAgents]   = useState([]);
  const [missions, setMissions] = useState([]);
  const [loading,  setLoading]  = useState(false);
  const [backendOk, setBackendOk] = useState(null);

  const [cfg, setCfg] = useState({
    name: "", target_url: "", target_type: "", intensity: "medium",
    agent_ids: [], options: {}, kill_chain_phases: [1,2,3,4,5,6],
    scan_depth: "standard", attack_vectors: [], objective: "",
  });

  const [liveMission, setLiveMission] = useState(null);
  const [liveTab,     setLiveTab]     = useState("agents");
  const [logs,        setLogs]        = useState([]);
  const wsRef = useRef(null);
  const logRef = useRef(null);

  // Agent-Registrierung (manuell)
  const ICON_PRESETS = ["🤖","🔭","💉","⚔️","🎯","🕵️","🧪","🔓","🔧","📡","💀","🦾","🛸","🧠","🔬"];
  const emptyReg = { agent_id:"", name:"", icon:"🤖", description:"", base_url:"", capabilities:[], target_types:[] };
  const [showRegForm, setShowRegForm] = useState(false);
  const [regForm,     setRegForm]     = useState(emptyReg);
  const [regCapInput, setRegCapInput] = useState("");
  const [regTgtInput, setRegTgtInput] = useState("");
  const [regStatus,   setRegStatus]   = useState(null); // null | "ok" | "error"
  const [regMsg,      setRegMsg]      = useState("");
  const [pingStatus,  setPingStatus]  = useState({}); // agent_id → "ok"|"error"|"checking"

  // ── Backend health + initial data ──────────
  useEffect(() => {
    api.get("/health")
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
    fetchAgents();
    fetchMissions();
  }, []);

  const fetchAgents = async () => {
    try { setAgents(await api.get("/agents")); } catch { setAgents([]); }
  };
  const fetchMissions = async () => {
    try { setMissions(await api.get("/missions")); } catch { setMissions([]); }
  };

  // ── WebSocket connection ────────────────────
  const connectWS = useCallback((missionId) => {
    if (wsRef.current) wsRef.current.close();
    const ws = new WebSocket(`${WS_BASE}/missions/${missionId}/ws`);

    ws.onmessage = (e) => {
      const event = JSON.parse(e.data);
      if (event.event === "state_sync") { setLiveMission(event.payload); return; }
      if (["mission_started","mission_stopped","mission_complete"].includes(event.event)) {
        setLiveMission(prev => prev ? { ...prev, status: event.event === "mission_started" ? "running" : event.event } : prev);
      }
      if (event.event === "progress" && event.agent_id) {
        setLiveMission(prev => {
          if (!prev) return prev;
          return { ...prev, agent_states: { ...prev.agent_states,
            [event.agent_id]: { ...prev.agent_states?.[event.agent_id], progress: event.payload.percent, status: "running", current_task: event.payload.current_task }
          }};
        });
      }
      if (event.event === "finding") {
        setLiveMission(prev => prev ? { ...prev, findings: [...(prev.findings || []), { id: Date.now(), agent_id: event.agent_id, ...event.payload }] } : prev);
      }
      if (event.event === "complete" && event.agent_id) {
        setLiveMission(prev => {
          if (!prev) return prev;
          return { ...prev, agent_states: { ...prev.agent_states,
            [event.agent_id]: { ...prev.agent_states?.[event.agent_id], status: "done", progress: 100 }
          }};
        });
      }
      if (event.event === "log" || event.event === "finding") {
        const msg = event.event === "finding"
          ? `[FINDING] ${event.payload.severity} - ${event.payload.title}`
          : event.payload.message;
        setLogs(prev => [...prev.slice(-199), {
          time: new Date(event.timestamp).toLocaleTimeString("de-DE"),
          level: event.payload?.level || (event.event === "finding" ? "warn" : "info"),
          agent: event.agent_id, msg,
        }]);
      }
      if (ws.readyState === WebSocket.OPEN) ws.send("ping");
    };
    ws.onerror = () => addLog("error", "sys", "WebSocket Verbindungsfehler");
    wsRef.current = ws;
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const addLog = (level, agent, msg) => {
    setLogs(prev => [...prev.slice(-199), { time: new Date().toLocaleTimeString("de-DE"), level, agent, msg }]);
  };

  // ── Mission control ────────────────────────
  const startMission = async () => {
    setLoading(true);
    try {
      const res = await api.post("/missions", cfg);
      if (res.mission_id) {
        addLog("ok", "sys", `Mission gestartet: ${res.mission_id}`);
        connectWS(res.mission_id);
        setLiveMission({
          id: res.mission_id, config: cfg, status: "running", findings: [],
          agent_states: Object.fromEntries(cfg.agent_ids.map(id => [id, { progress: 0, status: "pending", current_task: "" }]))
        });
        setView("live");
        fetchMissions();
      }
    } catch { addLog("error", "sys", "Mission konnte nicht gestartet werden"); }
    setLoading(false);
  };

  const stopMission = async () => {
    if (!liveMission?.id) return;
    await api.post(`/missions/${liveMission.id}/stop`, {});
  };

  const openMission = (m) => {
    setLiveMission(m);
    if (m.status === "running") connectWS(m.id);
    setView(m.status === "complete" ? "report" : "live");
  };

  // ── Manuelle Agent-Registrierung ────────────
  const registerAgent = async () => {
    if (!regForm.agent_id || !regForm.name || !regForm.base_url) {
      setRegStatus("error"); setRegMsg("Agent-ID, Name und Base-URL sind Pflichtfelder.");
      return;
    }
    try {
      const res = await api.post("/agents/register", {
        ...regForm,
        capabilities: regForm.capabilities.length ? regForm.capabilities : ["general"],
        target_types:  regForm.target_types.length  ? regForm.target_types  : ["webapp"],
      });
      if (res.status === "registered") {
        setRegStatus("ok"); setRegMsg(`Agent "${regForm.name}" erfolgreich registriert.`);
        setRegForm(emptyReg); setShowRegForm(false);
        fetchAgents();
      } else {
        setRegStatus("error"); setRegMsg(res.detail || "Unbekannter Fehler beim Registrieren.");
      }
    } catch {
      setRegStatus("error"); setRegMsg("Backend nicht erreichbar.");
    }
  };

  const unregisterAgent = async (agentId) => {
    try {
      await api.delete(`/agents/${agentId}`);
      fetchAgents();
    } catch { /* silent */ }
  };

  const pingAgent = async (agent) => {
    setPingStatus(p => ({ ...p, [agent.agent_id]: "checking" }));
    try {
      const res = await fetch(`${agent.base_url || agent.callback_url}/health`, { signal: AbortSignal.timeout(3000) });
      setPingStatus(p => ({ ...p, [agent.agent_id]: res.ok ? "ok" : "error" }));
    } catch {
      setPingStatus(p => ({ ...p, [agent.agent_id]: "error" }));
    }
  };

  const addTag = (field, val, setInput) => {
    const tag = val.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    if (!tag) return;
    setRegForm(f => ({ ...f, [field]: f[field].includes(tag) ? f[field] : [...f[field], tag] }));
    setInput("");
  };

  const exportReport = () => {
    if (!liveMission) return;
    const md = generateReport(liveMission, agents);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `redswarm-report-${liveMission.config?.name || liveMission.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const overallProgress = liveMission
    ? Object.values(liveMission.agent_states || {}).reduce((s, a) => s + (a.progress || 0), 0) /
      Math.max(1, Object.keys(liveMission.agent_states || {}).length)
    : 0;

  // Kill-Chain phase status from findings
  const getPhaseStatus = (phaseId) => {
    if (!liveMission) return "pending";
    const phaseMap = { recon:"Reconnaissance", poisoning:"Poisoning", hijacking:"Hijacking", persistence:"Persistence", pivot:"Pivot", impact:"Impact" };
    const hasFindings = (liveMission.findings||[]).some(f => f.phase === phaseMap[phaseId] || f.kill_chain_phase === phaseId);
    const isRunning = liveMission.status === "running";
    if (hasFindings) return "done";
    if (isRunning) return "active";
    return "pending";
  };

  // ─────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────
  return (
    <>
      <style>{S}</style>
      <div className="app">
        {/* HEADER */}
        <header className="header">
          <div className="logo">
            <div className="logo-hex" />
            <span className="logo-name">RED<span>SWARM</span></span>
          </div>
          <nav className="header-nav">
            {[["wizard","Mission"],["live","Monitor"],["agents","Agents"],["modules","Module"],["report","Bericht"]].map(([v,l]) => (
              <button key={v} className={`nav-btn ${view===v?"on":""}`} onClick={() => setView(v)}>{l}</button>
            ))}
          </nav>
          <div className="status-row">
            <div className="pulse-dot" style={{background: backendOk===false ? "var(--red)" : "var(--green)", boxShadow: `0 0 8px ${backendOk===false ? "var(--red)" : "var(--green)"}`}} />
            <span>{backendOk===null ? "Verbinde..." : backendOk ? `Backend OK | ${agents.length} Agents` : "Backend nicht erreichbar"}</span>
          </div>
        </header>

        <div className="body">
          {/* SIDEBAR */}
          <aside className="sidebar">
            <div className="slabel">Navigation</div>
            {[["wizard","🎯","Mission erstellen"],["live","📡","Live-Monitor"],["agents","🤖","Agents"],["modules","🧩","Module"],["report","📊","Bericht"]].map(([v,ic,l]) => (
              <div key={v} className={`sitem ${view===v?"on":""}`} onClick={() => setView(v)}>
                <span>{ic}</span>{l}
                {v==="live" && liveMission?.status==="running" && <span className="sbadge">LIVE</span>}
              </div>
            ))}

            <div className="slabel" style={{marginTop:16}}>Vergangene Missionen</div>
            {missions.length === 0
              ? <div style={{fontSize:12, color:"var(--muted)", padding:"8px 12px"}}>Keine Missionen</div>
              : missions.slice(-5).reverse().map(m => (
                <div key={m.id} className="sitem" onClick={() => openMission(m)}>
                  <span>{m.status==="running"?"⚡":m.status==="complete"?"✓":"○"}</span>
                  <span style={{fontSize:12, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>{m.config?.name || m.id.slice(0,8)}</span>
                </div>
              ))
            }

            <div className="slabel" style={{marginTop:16}}>Registrierte Agents</div>
            {agents.map(a => (
              <div key={a.agent_id} className="sitem" style={{cursor:"default"}}>
                <span>{a.icon}</span>
                <span style={{fontSize:12}}>{a.name}</span>
              </div>
            ))}
          </aside>

          {/* CONTENT */}
          <main className="content fi" key={view}>

            {/* ═══════════ WIZARD ═══════════ */}
            {view === "wizard" && (
              <>
                <div style={{marginBottom:28}}>
                  <div className="badge badge-red">⚡ Neue Mission</div>
                  <h1 style={{fontFamily:"Syne",fontSize:26,fontWeight:800,margin:"4px 0 8px"}}>Mission konfigurieren</h1>
                  <p style={{fontSize:13,color:"var(--muted)"}}>Schritt fuer Schritt — keine technischen Kenntnisse erforderlich.</p>
                </div>

                {/* Step bar */}
                <div className="steps">
                  {[{n:1,l:"Ziel"},{n:2,l:"Agents"},{n:3,l:"Optionen"},{n:4,l:"Start"}].map((s,i,arr) => (
                    <div key={s.n} style={{display:"flex",alignItems:"center",flex:i<arr.length-1?1:0}}>
                      <div style={{display:"flex",alignItems:"center",gap:8}}>
                        <div className={`sc ${step>s.n?"done":step===s.n?"active":""} ${step>s.n?"prev":""}`}
                          onClick={() => step > s.n && setStep(s.n)}>
                          {step > s.n ? "✓" : s.n}
                        </div>
                        <span className={`sl ${step===s.n?"active":""}`}>{s.l}</span>
                      </div>
                      {i<arr.length-1 && <div className={`scon ${step>s.n?"done":""}`} />}
                    </div>
                  ))}
                </div>

                {/* STEP 1 — Ziel */}
                {step === 1 && (
                  <div className="fi">
                    <div className="card">
                      <div className="ctitle">📋 Mission-Details</div>
                      <div className="fg">
                        <label className="flabel">Name der Mission</label>
                        <input className="finput" placeholder="z.B. Webseiten-Audit Q1 2025" value={cfg.name} onChange={e => setCfg(c=>({...c,name:e.target.value}))} />
                      </div>
                      <div className="fg">
                        <label className="flabel">Ziel-URL oder IP</label>
                        <input className="finput" placeholder="https://example.com" value={cfg.target_url} onChange={e => setCfg(c=>({...c,target_url:e.target.value}))} />
                      </div>
                      <div className="fg">
                        <label className="flabel">Ziel-Beschreibung (optional)</label>
                        <input className="finput" placeholder="z.B. KI-Chatbot mit RAG-System und Tool-Use" value={cfg.objective} onChange={e => setCfg(c=>({...c,objective:e.target.value}))} />
                      </div>
                      <div className="fg" style={{marginBottom:0}}>
                        <label className="flabel">Art des Ziels</label>
                        <input className="finput" placeholder="webapp, api, chatbot, ..." value={cfg.target_type} onChange={e => setCfg(c=>({...c,target_type:e.target.value}))} />
                        <div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}>
                          {["webapp","api","chatbot","network","social"].map(t => (
                            <button key={t} className="btn btn-s" style={{padding:"5px 12px",fontSize:11,borderColor:cfg.target_type===t?"var(--red)":undefined,color:cfg.target_type===t?"var(--red)":undefined}} onClick={()=>setCfg(c=>({...c,target_type:t}))}>{t}</button>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="card">
                      <div className="ctitle">⚡ Intensitaet</div>
                      <div className="int-row">
                        {INTENSITY.map(l => (
                          <button key={l.id} className="int-btn" style={cfg.intensity===l.id?{borderColor:l.color,color:l.color,background:`${l.color}18`}:{}} onClick={()=>setCfg(c=>({...c,intensity:l.id}))}>
                            <div className="int-dot" style={{background:l.color}} />
                            {l.label}
                            <div className="int-sub">{l.sub}</div>
                          </button>
                        ))}
                      </div>
                      <div className="alert" style={{marginTop:14}}>
                        <span>⚠️</span>
                        <span>Teste nur Systeme mit ausdruecklicher schriftlicher Genehmigung. Unbefugte Tests sind strafbar.</span>
                      </div>
                    </div>
                    <div className="btn-row">
                      <button className="btn btn-p" disabled={!cfg.target_url || !cfg.target_type} onClick={() => setStep(2)}>Weiter →</button>
                    </div>
                  </div>
                )}

                {/* STEP 2 — Agents */}
                {step === 2 && (
                  <div className="fi">
                    <div className="card">
                      <div className="ctitle">🤖 Agents auswaehlen</div>
                      {agents.length === 0 ? (
                        <div className="no-agents">
                          ⚠️ Keine Agents registriert. Starte deine Agent-Container — sie registrieren sich automatisch.
                          <button className="btn btn-s" style={{marginTop:10,display:"block"}} onClick={fetchAgents}>🔄 Aktualisieren</button>
                        </div>
                      ) : (
                        <div className="grid3">
                          {agents.map(a => (
                            <div key={a.agent_id}
                              className={`sel-card agent ${cfg.agent_ids.includes(a.agent_id)?"on":""}`}
                              onClick={() => setCfg(c => ({
                                ...c,
                                agent_ids: c.agent_ids.includes(a.agent_id)
                                  ? c.agent_ids.filter(id=>id!==a.agent_id)
                                  : [...c.agent_ids, a.agent_id]
                              }))}>
                              <div className="ic">{a.icon}</div>
                              <div className="nm">{a.name}</div>
                              <div className="ds">{a.description}</div>
                              {a.capabilities?.length > 0 && (
                                <div className="caps">{a.capabilities.slice(0,4).map(cap => <span key={cap} className="cap">{cap}</span>)}</div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="btn-row">
                      <button className="btn btn-s" onClick={()=>setStep(1)}>← Zurueck</button>
                      <button className="btn btn-p" disabled={cfg.agent_ids.length===0} onClick={()=>setStep(3)}>Weiter →</button>
                    </div>
                  </div>
                )}

                {/* STEP 3 — Erweiterte Optionen */}
                {step === 3 && (
                  <div className="fi">
                    <div className="card">
                      <div className="ctitle">🎯 Kill-Chain Phasen</div>
                      <p style={{fontSize:12,color:"var(--muted)",marginBottom:14}}>Waehle welche Angriffsphasen durchlaufen werden sollen:</p>
                      <div className="kc-track">
                        {KILL_CHAIN.map(kc => (
                          <div key={kc.id}
                            className={`kc-phase ${cfg.kill_chain_phases.includes(kc.phase)?"active":""}`}
                            style={{cursor:"pointer"}}
                            onClick={() => setCfg(c => ({
                              ...c,
                              kill_chain_phases: c.kill_chain_phases.includes(kc.phase)
                                ? c.kill_chain_phases.filter(p=>p!==kc.phase)
                                : [...c.kill_chain_phases, kc.phase].sort()
                            }))}>
                            <div className="kc-ic">{kc.icon}</div>
                            <div className="kc-name">{kc.name}</div>
                            <div className="kc-status">{cfg.kill_chain_phases.includes(kc.phase) ? "AKTIV" : "AUS"}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="card">
                      <div className="ctitle">📦 Scan-Tiefe</div>
                      <div className="int-row">
                        {[{id:"quick",label:"Schnell",sub:"~2 Min",color:"#22c55e"},{id:"standard",label:"Standard",sub:"~10 Min",color:"#f59e0b"},{id:"deep",label:"Tiefenscan",sub:"~30 Min",color:"#e84040"}].map(d => (
                          <button key={d.id} className="int-btn" style={cfg.scan_depth===d.id?{borderColor:d.color,color:d.color,background:`${d.color}18`}:{}} onClick={()=>setCfg(c=>({...c,scan_depth:d.id}))}>
                            <div className="int-dot" style={{background:d.color}} />
                            {d.label}
                            <div className="int-sub">{d.sub}</div>
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="card">
                      <div className="ctitle">💉 Angriffsvektoren (optional)</div>
                      <p style={{fontSize:12,color:"var(--muted)",marginBottom:14}}>Spezifische Module auswaehlen oder leer lassen fuer automatische Auswahl:</p>
                      <div className="grid3">
                        {MODULES.map(m => (
                          <div key={m.id}
                            className={`sel-card ${cfg.attack_vectors.includes(m.id)?"on":""}`}
                            onClick={() => setCfg(c => ({
                              ...c,
                              attack_vectors: c.attack_vectors.includes(m.id)
                                ? c.attack_vectors.filter(v=>v!==m.id)
                                : [...c.attack_vectors, m.id]
                            }))}>
                            <div className="ic">{m.icon}</div>
                            <div className="nm">{m.name}</div>
                            <div className="ds">{m.desc}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="btn-row">
                      <button className="btn btn-s" onClick={()=>setStep(2)}>← Zurueck</button>
                      <button className="btn btn-p" onClick={()=>setStep(4)}>Weiter →</button>
                    </div>
                  </div>
                )}

                {/* STEP 4 — Review & Launch */}
                {step === 4 && (
                  <div className="fi">
                    <div className="card">
                      <div className="ctitle">✅ Zusammenfassung</div>
                      <div className="rv-grid">
                        <div className="rv-item"><div className="rv-lbl">Mission</div><div className="rv-val">{cfg.name || "–"}</div></div>
                        <div className="rv-item"><div className="rv-lbl">Ziel</div><div className="rv-val">{cfg.target_url}</div></div>
                        <div className="rv-item"><div className="rv-lbl">Typ</div><div className="rv-val">{cfg.target_type}</div></div>
                        <div className="rv-item"><div className="rv-lbl">Intensitaet</div><div className="rv-val">{INTENSITY.find(i=>i.id===cfg.intensity)?.label}</div></div>
                        <div className="rv-item"><div className="rv-lbl">Scan-Tiefe</div><div className="rv-val">{cfg.scan_depth}</div></div>
                        <div className="rv-item"><div className="rv-lbl">Kill-Chain</div><div className="rv-val">{cfg.kill_chain_phases.length} von 6 Phasen</div></div>
                        <div className="rv-item" style={{gridColumn:"1/-1"}}>
                          <div className="rv-lbl">Agents ({cfg.agent_ids.length})</div>
                          <div className="rv-val">{cfg.agent_ids.map(id => agents.find(a=>a.agent_id===id)?.name || id).join(", ")}</div>
                        </div>
                        {cfg.attack_vectors.length > 0 && (
                          <div className="rv-item" style={{gridColumn:"1/-1"}}>
                            <div className="rv-lbl">Angriffsvektoren ({cfg.attack_vectors.length})</div>
                            <div className="rv-val">{cfg.attack_vectors.map(v => MODULES.find(m=>m.id===v)?.name || v).join(", ")}</div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Kill-Chain Preview */}
                    <div className="card">
                      <div className="ctitle">🔗 Kill-Chain Vorschau</div>
                      <div className="kc-track">
                        {KILL_CHAIN.map(kc => (
                          <div key={kc.id} className={`kc-phase ${cfg.kill_chain_phases.includes(kc.phase)?"active":""}`}>
                            <div className="kc-ic">{kc.icon}</div>
                            <div className="kc-name">{kc.name}</div>
                            <div className="kc-status">{cfg.kill_chain_phases.includes(kc.phase) ? "GEPLANT" : "SKIP"}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="btn-row">
                      <button className="btn btn-s" onClick={()=>setStep(3)}>← Zurueck</button>
                      <button className="btn btn-p" disabled={loading} onClick={startMission}>
                        {loading ? <><div className="spinner" />Starte...</> : "🚀 Mission starten"}
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}

            {/* ═══════════ LIVE MONITOR ═══════════ */}
            {view === "live" && (
              <>
                {!liveMission
                  ? <div className="ph"><div className="ph-icon">📡</div><p style={{fontSize:15,color:"var(--dim)"}}>Keine aktive Mission</p><p style={{fontSize:13,marginTop:6}}>Starte eine Mission oder waehle eine aus dem Verlauf.</p></div>
                  : (
                    <>
                      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:24}}>
                        <div>
                          <div className={`badge ${liveMission.status==="running"?"badge-red":"badge-green"}`}>
                            {liveMission.status==="running" ? "⚡ LAUFEND" : "✓ ABGESCHLOSSEN"}
                          </div>
                          <h1 style={{fontFamily:"Syne",fontSize:24,fontWeight:800,margin:"4px 0 4px"}}>{liveMission.config?.name || liveMission.id}</h1>
                          <p style={{fontSize:12,color:"var(--muted)",fontFamily:"DM Mono"}}>{liveMission.config?.target_url} | {Object.keys(liveMission.agent_states||{}).length} Agents</p>
                        </div>
                        <div style={{display:"flex",gap:8}}>
                          {liveMission.status === "running" && (
                            <button className="btn btn-s" onClick={stopMission}>⏹ Stopp</button>
                          )}
                          <button className="btn btn-s" onClick={() => setView("report")}>📊 Bericht</button>
                        </div>
                      </div>

                      {/* Kill-Chain Live Track */}
                      <div className="kc-track">
                        {KILL_CHAIN.map(kc => {
                          const st = getPhaseStatus(kc.id);
                          return (
                            <div key={kc.id} className={`kc-phase ${st}`}>
                              <div className="kc-ic">{kc.icon}</div>
                              <div className="kc-name">{kc.name}</div>
                              <div className="kc-status">{st === "done" ? "DONE" : st === "active" ? "AKTIV" : "WARTE"}</div>
                            </div>
                          );
                        })}
                      </div>

                      <div className="prog-wrap">
                        <div className="prog-top">
                          <span style={{fontSize:13}}>Gesamtfortschritt</span>
                          <span style={{fontFamily:"DM Mono",fontSize:12}}>{Math.round(overallProgress)}%</span>
                        </div>
                        <div className="prog-track"><div className="prog-fill" style={{width:`${overallProgress}%`}} /></div>
                      </div>

                      <div className="grid4">
                        <div className="stat"><div className="stat-lbl">Findings</div><div className="stat-val" style={{color:"var(--red)"}}>{liveMission.findings?.length || 0}</div><div className="stat-sub">Gesamt</div></div>
                        <div className="stat"><div className="stat-lbl">Kritisch</div><div className="stat-val" style={{color:"var(--yellow)"}}>{liveMission.findings?.filter(f=>["KRITISCH","CRITICAL"].includes(f.severity?.toUpperCase())).length || 0}</div><div className="stat-sub">Sofortiger Handlungsbedarf</div></div>
                        <div className="stat"><div className="stat-lbl">Aktive Agents</div><div className="stat-val" style={{color:"var(--blue)"}}>{Object.values(liveMission.agent_states||{}).filter(a=>a.status==="running").length}</div><div className="stat-sub">laufend</div></div>
                        <div className="stat"><div className="stat-lbl">Risiko-Score</div><div className="stat-val" style={{color:riskScore(liveMission.findings)>60?"var(--red)":riskScore(liveMission.findings)>30?"var(--yellow)":"var(--green)"}}>{riskScore(liveMission.findings)}</div><div className="stat-sub">von 100</div></div>
                      </div>

                      <div className="tabs">
                        {[["agents","🤖 Agents"],["log","📟 Log"],["findings","🔍 Findings"]].map(([t,l]) => (
                          <button key={t} className={`tab ${liveTab===t?"on":""}`} onClick={()=>setLiveTab(t)}>{l}</button>
                        ))}
                      </div>

                      {liveTab === "agents" && (
                        <div className="fi">
                          {Object.entries(liveMission.agent_states || {}).map(([id, s]) => {
                            const agent = agents.find(a => a.agent_id === id);
                            return (
                              <div key={id} className="agent-row">
                                <div className={`adot ${s.status}`} />
                                <span style={{fontSize:18}}>{agent?.icon || "🤖"}</span>
                                <div className="ainfo">
                                  <div className="aname">{agent?.name || id}</div>
                                  <div className="atask">{s.current_task || s.status}</div>
                                </div>
                                <div className="abar"><div className={`afill ${s.status}`} style={{width:`${s.progress||0}%`}} /></div>
                                <div className="apct">{Math.round(s.progress||0)}%</div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {liveTab === "log" && (
                        <div className="logbox fi" ref={logRef}>
                          {logs.length === 0 && <div style={{color:"var(--muted)"}}>Warte auf Events...</div>}
                          {logs.map((l, i) => (
                            <div key={i} style={{display:"flex",gap:12}}>
                              <span className="ltime">{l.time}</span>
                              <span className={`l${l.level}`}>[{(l.level||"info").toUpperCase().padEnd(5)}]</span>
                              <span style={{color:"var(--blue)",fontSize:10,opacity:.7,alignSelf:"center"}}>{l.agent}</span>
                              <span className="lmsg">{l.msg}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {liveTab === "findings" && (
                        <div className="fi">
                          {(liveMission.findings||[]).length === 0
                            ? <div className="ph" style={{padding:"32px"}}><div className="ph-icon">🔍</div><p>Noch keine Findings</p></div>
                            : (liveMission.findings||[]).map((f,i) => (
                              <div key={i} className="finding">
                                <div className={`fsev s${f.severity?.toUpperCase()}`}>{f.severity}</div>
                                <div style={{flex:1}}>
                                  <div className="ftitle">{f.title}</div>
                                  <div className="fdesc">{f.description}</div>
                                  {f.evidence && <div className="fagent" style={{marginTop:4,fontFamily:"DM Mono",fontSize:10,color:"var(--muted)"}}>{f.evidence}</div>}
                                  <div className="fagent">🤖 {agents.find(a=>a.agent_id===f.agent_id)?.name || f.agent_id}</div>
                                </div>
                              </div>
                            ))
                          }
                        </div>
                      )}
                    </>
                  )
                }
              </>
            )}

            {/* ═══════════ AGENTS ═══════════ */}
            {view === "agents" && (
              <>
                <div style={{marginBottom:28}}>
                  <div className="badge badge-blue">🤖 Agents</div>
                  <h1 style={{fontFamily:"Syne",fontSize:26,fontWeight:800,margin:"4px 0 8px"}}>Agent-Verwaltung</h1>
                  <p style={{fontSize:13,color:"var(--muted)"}}>Registrierte Agents — auto-verbunden via Docker oder manuell eingetragen.</p>
                </div>

                {/* Status-Banner */}
                {regStatus === "ok"    && <div className="success-banner">✅ {regMsg}</div>}
                {regStatus === "error" && <div className="error-banner">❌ {regMsg}</div>}

                {/* Registrierte Agents */}
                <div className="card">
                  <div className="ctitle" style={{justifyContent:"space-between"}}>
                    <span>Registrierte Agents ({agents.length})</span>
                    <div style={{display:"flex",gap:8}}>
                      <button className="btn btn-s" style={{padding:"6px 12px",fontSize:12}} onClick={fetchAgents}>🔄 Aktualisieren</button>
                      <button className="btn btn-p" style={{padding:"6px 14px",fontSize:12}} onClick={() => { setShowRegForm(s=>!s); setRegStatus(null); }}>
                        {showRegForm ? "✕ Abbrechen" : "+ Manuell registrieren"}
                      </button>
                    </div>
                  </div>

                  {agents.length === 0 ? (
                    <div className="no-agents">
                      ⚠️ Keine Agents registriert. Starte die Docker-Container oder registriere einen Agent manuell.
                    </div>
                  ) : (
                    agents.map(a => (
                      <div key={a.agent_id} className="agent-card">
                        <div className="agent-card-ic">{a.icon || "🤖"}</div>
                        <div style={{width:8,height:8,borderRadius:"50%",background:"var(--green)",boxShadow:"0 0 8px var(--green)",flexShrink:0}} />
                        <div className="agent-card-info">
                          <div className="agent-card-name">{a.name}</div>
                          <div style={{fontSize:12,color:"var(--muted)",marginBottom:4}}>{a.description}</div>
                          <div className="agent-card-url">{a.base_url || a.callback_url || "–"}</div>
                          <div className="agent-card-caps">
                            {(a.capabilities||[]).map(c => <span key={c} className="cap">{c}</span>)}
                            {(a.target_types||[]).map(t => <span key={t} className="mod-tag mod-tag-type">{t}</span>)}
                          </div>
                        </div>
                        <div style={{display:"flex",gap:8,flexShrink:0}}>
                          <button
                            className={`btn btn-s`}
                            style={{
                              padding:"5px 12px", fontSize:11,
                              color: pingStatus[a.agent_id]==="ok" ? "var(--green)" : pingStatus[a.agent_id]==="error" ? "var(--red)" : undefined
                            }}
                            onClick={() => pingAgent(a)}
                          >
                            {pingStatus[a.agent_id]==="checking" ? "⏳" : pingStatus[a.agent_id]==="ok" ? "✅ Online" : pingStatus[a.agent_id]==="error" ? "❌ Offline" : "📡 Ping"}
                          </button>
                          <button className="btn btn-danger" style={{padding:"5px 12px",fontSize:11}} onClick={() => unregisterAgent(a.agent_id)}>
                            🗑 Entfernen
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* Manuelles Registrierungsformular */}
                {showRegForm && (
                  <div className="reg-form fi">
                    <div className="ctitle">➕ Agent manuell registrieren</div>
                    <p style={{fontSize:12,color:"var(--muted)",marginBottom:20}}>
                      Nutze dies wenn ein Agent läuft aber sich nicht automatisch verbunden hat — z.B. ein lokaler Agent oder ein Agent auf einem anderen Server.
                    </p>

                    <div className="grid2">
                      <div className="fg">
                        <label className="flabel">Agent-ID <span style={{color:"var(--red)"}}>*</span></label>
                        <input className="finput" placeholder="z.B. recon oder mein-custom-agent"
                          value={regForm.agent_id}
                          onChange={e => setRegForm(f=>({...f, agent_id: e.target.value.toLowerCase().replace(/\s+/g,"-")}))} />
                        <div style={{fontSize:11,color:"var(--muted)",marginTop:4}}>Nur Kleinbuchstaben, Zahlen, Bindestriche</div>
                      </div>
                      <div className="fg">
                        <label className="flabel">Name <span style={{color:"var(--red)"}}>*</span></label>
                        <input className="finput" placeholder="z.B. Recon Agent" value={regForm.name}
                          onChange={e => setRegForm(f=>({...f, name: e.target.value}))} />
                      </div>
                    </div>

                    <div className="fg">
                      <label className="flabel">Beschreibung</label>
                      <input className="finput" placeholder="Kurze Beschreibung was dieser Agent tut"
                        value={regForm.description}
                        onChange={e => setRegForm(f=>({...f, description: e.target.value}))} />
                    </div>

                    <div className="fg">
                      <label className="flabel">Base-URL <span style={{color:"var(--red)"}}>*</span></label>
                      <input className="finput" placeholder="http://localhost:8100 oder http://mein-server:8100"
                        value={regForm.base_url}
                        onChange={e => setRegForm(f=>({...f, base_url: e.target.value}))} />
                      <div style={{fontSize:11,color:"var(--muted)",marginTop:4}}>Die URL unter der der Agent-HTTP-Service erreichbar ist</div>
                    </div>

                    <div className="fg">
                      <label className="flabel">Icon</label>
                      <div className="icon-picker">
                        {ICON_PRESETS.map(ic => (
                          <button key={ic} className={`icon-opt ${regForm.icon===ic?"on":""}`}
                            onClick={() => setRegForm(f=>({...f, icon: ic}))}>
                            {ic}
                          </button>
                        ))}
                        <input className="finput" style={{width:80,padding:"6px 10px",textAlign:"center",fontSize:20}}
                          value={regForm.icon}
                          onChange={e => setRegForm(f=>({...f, icon: e.target.value}))}
                          placeholder="🤖" maxLength={4} />
                      </div>
                    </div>

                    <div className="grid2">
                      <div className="fg" style={{marginBottom:0}}>
                        <label className="flabel">Fähigkeiten (Capabilities)</label>
                        <div className="tag-input-wrap" onClick={e => e.currentTarget.querySelector("input")?.focus()}>
                          {regForm.capabilities.map(c => (
                            <span key={c} className="tag-chip">
                              {c}
                              <button onClick={() => setRegForm(f=>({...f, capabilities: f.capabilities.filter(x=>x!==c)}))}>×</button>
                            </span>
                          ))}
                          <input className="tag-bare-input"
                            placeholder={regForm.capabilities.length ? "" : "z.B. scanning, fingerprinting..."}
                            value={regCapInput}
                            onChange={e => setRegCapInput(e.target.value)}
                            onKeyDown={e => {
                              if (e.key==="Enter"||e.key===","||e.key===" ") { e.preventDefault(); addTag("capabilities", regCapInput, setRegCapInput); }
                              if (e.key==="Backspace"&&!regCapInput&&regForm.capabilities.length) setRegForm(f=>({...f, capabilities: f.capabilities.slice(0,-1)}));
                            }}
                            onBlur={() => addTag("capabilities", regCapInput, setRegCapInput)}
                          />
                        </div>
                        <div style={{fontSize:11,color:"var(--muted)",marginTop:4}}>Enter oder Komma zum Hinzufügen</div>
                      </div>

                      <div className="fg" style={{marginBottom:0}}>
                        <label className="flabel">Zieltypen (Target Types)</label>
                        <div className="tag-input-wrap" onClick={e => e.currentTarget.querySelector("input")?.focus()}>
                          {regForm.target_types.map(t => (
                            <span key={t} className="tag-chip" style={{background:"rgba(168,85,247,.1)",color:"var(--purple)"}}>
                              {t}
                              <button style={{color:"var(--purple)"}} onClick={() => setRegForm(f=>({...f, target_types: f.target_types.filter(x=>x!==t)}))}>×</button>
                            </span>
                          ))}
                          <input className="tag-bare-input"
                            placeholder={regForm.target_types.length ? "" : "z.B. webapp, api, chatbot..."}
                            value={regTgtInput}
                            onChange={e => setRegTgtInput(e.target.value)}
                            onKeyDown={e => {
                              if (e.key==="Enter"||e.key===","||e.key===" ") { e.preventDefault(); addTag("target_types", regTgtInput, setRegTgtInput); }
                              if (e.key==="Backspace"&&!regTgtInput&&regForm.target_types.length) setRegForm(f=>({...f, target_types: f.target_types.slice(0,-1)}));
                            }}
                            onBlur={() => addTag("target_types", regTgtInput, setRegTgtInput)}
                          />
                        </div>
                        <div style={{fontSize:11,color:"var(--muted)",marginTop:4}}>Welche Ziele kann dieser Agent angreifen?</div>
                      </div>
                    </div>

                    {/* Schnell-Vorlagen */}
                    <div style={{marginTop:20,marginBottom:20}}>
                      <div style={{fontSize:11,color:"var(--muted)",marginBottom:8,textTransform:"uppercase",letterSpacing:"0.8px"}}>Schnell-Vorlage</div>
                      <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                        {[
                          {id:"recon",    name:"Recon Agent",      icon:"🔭", desc:"Reconnaissance & Fingerprinting",  caps:["scanning","fingerprinting","osint"],             tgts:["webapp","api","chatbot"], url:"http://localhost:8100"},
                          {id:"exploit",  name:"Exploit Agent",    icon:"💉", desc:"Exploit-Entwicklung & Poisoning",   caps:["payload-dev","rag-poisoning"],                    tgts:["webapp","api"],           url:"http://localhost:8101"},
                          {id:"execution",name:"Execution Agent",  icon:"⚔️", desc:"Browser-Exploitation & Angriffe",   caps:["browser-exploitation","api-attacks"],             tgts:["webapp","chatbot"],        url:"http://localhost:8102"},
                          {id:"c4",       name:"C4 — C&C",         icon:"🎯", desc:"Strategie, Koordination & Reports", caps:["strategy-planning","report-generation"],           tgts:["webapp","api","chatbot"], url:"http://localhost:8103"},
                        ].map(t => (
                          <button key={t.id} className="btn btn-s" style={{fontSize:12,padding:"7px 14px"}}
                            onClick={() => setRegForm({ agent_id:t.id, name:t.name, icon:t.icon, description:t.desc, base_url:t.url, capabilities:t.caps, target_types:t.tgts })}>
                            {t.icon} {t.name}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="btn-row" style={{marginTop:0}}>
                      <button className="btn btn-s" onClick={() => { setShowRegForm(false); setRegStatus(null); setRegForm(emptyReg); }}>Abbrechen</button>
                      <button className="btn btn-p"
                        disabled={!regForm.agent_id || !regForm.name || !regForm.base_url}
                        onClick={registerAgent}>
                        ✅ Agent registrieren
                      </button>
                    </div>
                  </div>
                )}

                {/* Hilfe-Box */}
                <div className="card" style={{marginTop:8}}>
                  <div className="ctitle">💡 Wann manuell registrieren?</div>
                  <div style={{fontSize:13,color:"var(--muted)",lineHeight:1.8}}>
                    <p style={{marginBottom:8}}>Agents registrieren sich <strong style={{color:"var(--text)"}}>automatisch</strong> sobald ihre Docker-Container starten. Manuelle Registrierung ist nötig wenn:</p>
                    <p>• Der Agent auf einem <strong style={{color:"var(--text)"}}>anderen Server</strong> oder lokal läuft (nicht im gleichen Docker-Netz)</p>
                    <p>• Der Container gestartet ist aber die <strong style={{color:"var(--text)"}}>Auto-Registrierung fehlgeschlagen</strong> ist (Backend war noch nicht bereit)</p>
                    <p>• Du einen <strong style={{color:"var(--text)"}}>eigenen Custom-Agent</strong> entwickelt hast der die REDSWARM API implementiert</p>
                    <p style={{marginTop:8}}>Custom Agents müssen <code style={{background:"var(--bg3)",padding:"1px 6px",borderRadius:4,fontFamily:"DM Mono",fontSize:11}}>POST /run</code> und <code style={{background:"var(--bg3)",padding:"1px 6px",borderRadius:4,fontFamily:"DM Mono",fontSize:11}}>GET /health</code> implementieren.</p>
                  </div>
                </div>
              </>
            )}

            {/* ═══════════ MODULES ═══════════ */}
            {view === "modules" && (
              <>
                <div style={{marginBottom:28}}>
                  <div className="badge badge-purple">🧩 Module</div>
                  <h1 style={{fontFamily:"Syne",fontSize:26,fontWeight:800,margin:"4px 0 8px"}}>Attack-Module</h1>
                  <p style={{fontSize:13,color:"var(--muted)"}}>Verfuegbare Angriffs-Module im REDSWARM Framework. Jedes Modul deckt eine bestimmte Angriffsphase ab.</p>
                </div>

                {/* Kill-Chain Overview */}
                <div className="card">
                  <div className="ctitle">🔗 Kill-Chain Uebersicht</div>
                  <div className="kc-track">
                    {KILL_CHAIN.map(kc => {
                      const modCount = MODULES.filter(m => m.phase === kc.name).length;
                      return (
                        <div key={kc.id} className={`kc-phase ${modCount > 0 ? "active" : ""}`}>
                          <div className="kc-ic">{kc.icon}</div>
                          <div className="kc-name">{kc.name}</div>
                          <div className="kc-status">{modCount} Module</div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Module Grid */}
                <div className="grid3" style={{marginBottom:24}}>
                  {MODULES.map(m => (
                    <div key={m.id} className="mod-card">
                      <div className="mod-ic">{m.icon}</div>
                      <div className="mod-name">{m.name}</div>
                      <div className="mod-desc">{m.desc}</div>
                      <div>
                        <span className="mod-tag mod-tag-phase">{m.phase}</span>
                        <span className="mod-tag mod-tag-type">{m.type}</span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* KB Stats */}
                <div className="card">
                  <div className="ctitle">📚 Knowledge Base Stats</div>
                  <div className="kpi-grid">
                    <div className="kpi"><div className="kvi" style={{color:"var(--blue)"}}>{MODULES.length}</div><div className="kvl">Module</div></div>
                    <div className="kpi"><div className="kvi" style={{color:"var(--purple)"}}>{KILL_CHAIN.length}</div><div className="kvl">Kill-Chain Phasen</div></div>
                    <div className="kpi"><div className="kvi" style={{color:"var(--green)"}}>{agents.length}</div><div className="kvl">Aktive Agents</div></div>
                  </div>
                  <p style={{fontSize:12,color:"var(--muted)",marginTop:14}}>
                    Die Knowledge Base wird durch jede Mission erweitert. Erfolgreiche Angriffsmuster werden automatisch gespeichert und fuer zukuenftige Missionen optimiert.
                  </p>
                </div>
              </>
            )}

            {/* ═══════════ REPORT ═══════════ */}
            {view === "report" && (
              <>
                {!liveMission
                  ? <div className="ph"><div className="ph-icon">📊</div><p style={{fontSize:15,color:"var(--dim)"}}>Kein Bericht verfuegbar</p><p style={{fontSize:13,marginTop:6}}>Schliesse zuerst eine Mission ab.</p></div>
                  : (
                    <>
                      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:24}}>
                        <div>
                          <div className="badge badge-green">✓ Bericht</div>
                          <h1 style={{fontFamily:"Syne",fontSize:24,fontWeight:800,margin:"4px 0 4px"}}>{liveMission.config?.name || "Bericht"}</h1>
                          <p style={{fontSize:12,color:"var(--muted)"}}>Ziel: {liveMission.config?.target_url}</p>
                        </div>
                        <button className="btn btn-p" onClick={exportReport}>📥 Report exportieren</button>
                      </div>

                      <div className="risk-box">
                        <div className="risk-circle">
                          <div className="risk-num">{riskScore(liveMission.findings)}</div>
                          <div className="risk-lbl">Risiko</div>
                        </div>
                        <div>
                          <h3 style={{fontFamily:"Syne",fontSize:17,fontWeight:700,marginBottom:6}}>
                            {riskScore(liveMission.findings) > 70 ? "Kritisches Sicherheitsrisiko"
                              : riskScore(liveMission.findings) > 40 ? "Erhoehtes Sicherheitsrisiko"
                              : riskScore(liveMission.findings) > 10 ? "Moderates Risiko"
                              : "Geringes Risiko"}
                          </h3>
                          <p style={{fontSize:13,color:"var(--muted)",lineHeight:1.6}}>
                            {liveMission.findings?.length || 0} Sicherheitsprobleme gefunden ueber {Object.keys(liveMission.agent_states||{}).length} Agents.
                            {riskScore(liveMission.findings) > 40 ? " Sofortige Massnahmen empfohlen." : " Behebe die gefundenen Probleme nach Prioritaet."}
                          </p>
                        </div>
                      </div>

                      {/* Kill-Chain Summary */}
                      <div className="card" style={{marginBottom:20}}>
                        <div className="ctitle">🔗 Kill-Chain Ergebnisse</div>
                        <div className="kc-track">
                          {KILL_CHAIN.map(kc => {
                            const st = getPhaseStatus(kc.id);
                            return (
                              <div key={kc.id} className={`kc-phase ${st}`}>
                                <div className="kc-ic">{kc.icon}</div>
                                <div className="kc-name">{kc.name}</div>
                                <div className="kc-status">{st === "done" ? "GEFUNDEN" : "SICHER"}</div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      <div style={{marginBottom:24}}>
                        <div className="section-title">📊 Uebersicht</div>
                        <div className="kpi-grid">
                          {[
                            ["Kritisch", (liveMission.findings||[]).filter(f=>["KRITISCH","CRITICAL"].includes(f.severity?.toUpperCase())).length, "var(--red)"],
                            ["Hoch",     (liveMission.findings||[]).filter(f=>["HOCH","HIGH"].includes(f.severity?.toUpperCase())).length, "var(--orange)"],
                            ["Mittel/Info",(liveMission.findings||[]).filter(f=>!["KRITISCH","CRITICAL","HOCH","HIGH"].includes(f.severity?.toUpperCase())).length, "var(--yellow)"],
                          ].map(([l,v,c]) => (
                            <div key={l} className="kpi"><div className="kvi" style={{color:c}}>{v}</div><div className="kvl">{l}</div></div>
                          ))}
                        </div>
                      </div>

                      <div style={{marginBottom:24}}>
                        <div className="section-title">🔍 Alle Findings</div>
                        {(liveMission.findings||[]).length === 0
                          ? <div style={{color:"var(--muted)",fontSize:13}}>Keine Findings gefunden.</div>
                          : (liveMission.findings||[]).sort((a,b) => {
                              const o = {KRITISCH:0,CRITICAL:0,HOCH:1,HIGH:1,MITTEL:2,MEDIUM:2,INFO:3,LOW:3};
                              return (o[a.severity?.toUpperCase()]??9) - (o[b.severity?.toUpperCase()]??9);
                            }).map((f,i) => (
                            <div key={i} className="finding">
                              <div className={`fsev s${f.severity?.toUpperCase()}`}>{f.severity}</div>
                              <div style={{flex:1}}>
                                <div className="ftitle">{f.title}</div>
                                <div className="fdesc">{f.description}</div>
                                {f.remediation && <div style={{fontSize:12,color:"var(--green)",marginTop:6}}>✅ {f.remediation}</div>}
                                {f.cvss_score && <div style={{fontSize:11,color:"var(--muted)",marginTop:4,fontFamily:"DM Mono"}}>CVSS: {f.cvss_score}</div>}
                                <div className="fagent">🤖 {agents.find(a=>a.agent_id===f.agent_id)?.name || f.agent_id}</div>
                              </div>
                            </div>
                          ))
                        }
                      </div>

                      <div className="btn-row">
                        <button className="btn btn-s" onClick={exportReport}>📥 Markdown exportieren</button>
                        <button className="btn btn-s" onClick={() => { setView("wizard"); setStep(1); setCfg({name:"",target_url:"",target_type:"",intensity:"medium",agent_ids:[],options:{},kill_chain_phases:[1,2,3,4,5,6],scan_depth:"standard",attack_vectors:[],objective:""}); }}>
                          🎯 Neue Mission
                        </button>
                      </div>
                    </>
                  )
                }
              </>
            )}

          </main>
        </div>
      </div>
    </>
  );
}
