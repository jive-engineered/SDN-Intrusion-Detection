#!/usr/bin/env python3
"""Local, dependency-free live telemetry dashboard for the SDN-IDS project.

Run from any directory:
    python3 tools/telemetry_panel.py

The dashboard binds to 127.0.0.1 by default and reads the project's logs and
controller/ids_rules.json. It polls the local Open vSwitch CLI without a shell.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
EVENT_LOG = LOG_DIR / "ids_events.jsonl"
STATS_CSV = LOG_DIR / "flow_stats.csv"
STATUS_JSON = LOG_DIR / "status.json"
RULES_JSON = ROOT / "controller" / "ids_rules.json"
KNOWN_RULES = {
    "conn_flood", "port_scan", "invalid_flags", "concurrent_flows",
    "packet_rate", "multi_ip_spoof", "port_flood",
}
MAX_BODY_BYTES = 64 * 1024

HTML_PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>SDN-IDS · Live Telemetry</title>
<style>
:root{--bg:#080d18;--panel:#101827;--panel2:#0d1422;--line:#243248;--muted:#91a0b8;--text:#e8eef8;--cyan:#57d7f3;--blue:#6ea8fe;--green:#50e3a4;--red:#ff667b;--amber:#ffc86b;--radius:17px}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:radial-gradient(ellipse at 12% -10%,#172b4b 0,transparent 34%),radial-gradient(ellipse at 100% 0,#102f39 0,transparent 25%),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
button,input{font:inherit}button{cursor:pointer}button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}.shell{max-width:1500px;margin:auto;padding:26px clamp(14px,3vw,38px) 40px}.topbar{display:flex;gap:18px;align-items:center;justify-content:space-between;margin-bottom:24px}.brand{display:flex;gap:13px;align-items:center}.brand-mark{width:46px;height:46px;display:grid;place-items:center;border:1px solid #2a5167;border-radius:14px;background:linear-gradient(135deg,#14374a,#132038);color:var(--cyan);box-shadow:0 8px 30px #0004}.eyebrow{color:var(--cyan);font-size:10px;font-weight:800;letter-spacing:.17em;text-transform:uppercase}.brand h1{font-size:clamp(22px,3vw,30px);letter-spacing:-.035em;margin:2px 0 0}.subhead{color:var(--muted);font-size:12px;margin-top:3px}.top-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:flex-end}.live-pill,.status-pill{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 11px;background:#132a27;border:1px solid #235548;color:var(--green);font-size:11px;font-weight:800;letter-spacing:.04em}.live-dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor}.small-muted{font-size:11px;color:var(--muted)}.section{margin-top:20px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-head h2{font-size:13px;text-transform:uppercase;letter-spacing:.11em;color:#c8d4e7;margin:0}.section-note{color:var(--muted);font-size:11px}.grid{display:grid;gap:14px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.card{background:linear-gradient(145deg,rgba(17,26,42,.97),rgba(12,19,32,.97));border:1px solid var(--line);border-radius:var(--radius);box-shadow:0 12px 32px #0002;min-width:0}.metric-card{padding:17px 18px;position:relative;overflow:hidden}.metric-top{display:flex;justify-content:space-between;align-items:center;gap:8px;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}.metric-icon{display:grid;place-items:center;width:30px;height:30px;border:1px solid var(--line);border-radius:10px;color:var(--cyan);font-size:15px}.metric-value{font-size:clamp(22px,2.5vw,32px);font-weight:750;letter-spacing:-.04em;margin-top:17px;line-height:1.05;overflow-wrap:anywhere}.metric-foot{font-size:11px;color:var(--muted);margin-top:9px}.accent-green{color:var(--green)}.accent-red{color:var(--red)}.accent-blue{color:var(--blue)}.accent-cyan{color:var(--cyan)}.accent-amber{color:var(--amber)}
.layout-two{grid-template-columns:minmax(0,1.35fr) minmax(330px,1fr)}.topology-card{padding:20px}.topology{position:relative;display:grid;grid-template-columns:minmax(0,1fr) minmax(115px,.72fr) minmax(0,1fr);grid-template-rows:repeat(2,minmax(96px,auto));gap:18px 28px;padding:10px 4px 14px;isolation:isolate}.topology-lines{position:absolute;z-index:-1;inset:0;width:100%;height:100%;pointer-events:none}.topology-lines line{stroke:#40516b;stroke-width:2;stroke-dasharray:6 6}.topology-lines line.quarantined{stroke:var(--red);stroke-width:3;stroke-dasharray:3 4}.node{min-width:0;display:flex;flex-direction:column;justify-content:center;gap:4px;padding:13px 14px;border:1px solid var(--line);border-radius:14px;background:#111c2e;box-shadow:0 6px 22px #0003}.node.h1{grid-column:1;grid-row:1/3;border-color:#773443;background:linear-gradient(135deg,#291722,#151b2b)}.node.s1{grid-column:2;grid-row:1/3;text-align:center;border-color:#345875;background:linear-gradient(135deg,#13293d,#101827)}.node.h2{grid-column:3;grid-row:1;border-color:#2d4c78;background:linear-gradient(135deg,#142640,#101827)}.node.h3{grid-column:3;grid-row:2;border-color:#235b4b;background:linear-gradient(135deg,#122d2a,#101827)}.node-role{font-size:9px;text-transform:uppercase;letter-spacing:.13em;font-weight:800;color:var(--muted)}.node-name{font-weight:800;font-size:18px;letter-spacing:-.025em}.node-desc{font-size:11px;color:#a5b3c9;overflow-wrap:anywhere}.node-foot{margin-top:3px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}.chip{display:inline-flex;gap:5px;align-items:center;border-radius:6px;padding:3px 7px;font-size:9px;font-weight:800;letter-spacing:.03em;border:1px solid var(--line);color:#b4c1d4;background:#101827}.chip.red{color:var(--red);border-color:#703346;background:#321b27}.chip.green{color:var(--green);border-color:#235c4c;background:#142d2a}.chip.blue{color:var(--blue);border-color:#30547b;background:#17263d}.chip.cyan{color:var(--cyan);border-color:#285665;background:#122832}.chip.amber{color:var(--amber);border-color:#6b522b;background:#2c2519}.topology-legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:10px;border-top:1px solid var(--line);padding-top:12px}.legend-item{display:flex;gap:7px;align-items:center}.legend-dot{width:7px;height:7px;border-radius:50%}
.side-stack{display:grid;gap:14px;grid-template-rows:auto 1fr}.status-card{padding:17px 18px}.card-title{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:13px}.card-title h3{font-size:12px;margin:0;text-transform:uppercase;letter-spacing:.09em}.state-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid #1c293d}.state-row:last-child{border-bottom:0}.state-name{font-size:12px;color:#c8d4e7}.state-value{font-weight:750;font-size:11px;text-align:right}.state-online{color:var(--green)}.state-offline{color:var(--red)}.state-warn{color:var(--amber)}.status-sub{font-size:10px;color:var(--muted);margin-top:12px;overflow-wrap:anywhere}
.charts{grid-template-columns:repeat(3,minmax(0,1fr))}.chart-card{padding:16px 17px 10px;min-width:0}.chart-title{display:flex;justify-content:space-between;gap:8px;align-items:start}.chart-title h3{margin:0;font-size:12px;font-weight:700}.chart-unit{color:var(--muted);font-size:10px}.chart-kpi{font-size:19px;font-weight:750;letter-spacing:-.03em;margin-top:7px}.chart-canvas{width:100%;height:130px;display:block;margin-top:7px}.chart-foot{font-size:10px;color:var(--muted);padding:0 0 4px}
.alerts-card,.flows-card{overflow:hidden}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:650px}thead{background:#0b1220}th{padding:11px 15px;text-align:left;color:#8fa0ba;text-transform:uppercase;letter-spacing:.08em;font-size:9px;font-weight:800;white-space:nowrap}td{padding:12px 15px;border-top:1px solid #202c40;vertical-align:top;font-size:11px;color:#cdd8e8}tbody tr:hover{background:#172236}td.mono, .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px}.event-type{display:inline-block;border-radius:6px;padding:4px 7px;font-size:9px;font-weight:850;letter-spacing:.06em;white-space:nowrap}.event-alert{background:#351b27;color:var(--red);border:1px solid #713444}.event-block{background:#132f2a;color:var(--green);border:1px solid #275d4c}.event-recovery{background:#172941;color:var(--blue);border:1px solid #335c8a}.event-other{background:#28251e;color:var(--amber);border:1px solid #66512d}.event-detail{color:#e2eaf5;min-width:200px}.event-meta{color:var(--muted);font-size:10px;margin-top:4px;line-height:1.6}.rule-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.rule-row{display:grid;grid-template-columns:minmax(130px,1fr) minmax(72px,.5fr) minmax(72px,.5fr);gap:9px;align-items:center;border:1px solid #26344a;border-radius:12px;padding:12px;background:#0d1524}.rule-name{font-weight:750;font-size:11px;overflow-wrap:anywhere}.rule-enabled{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:10px;margin-top:5px}.rule-field label{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}.rule-field input[type=number]{width:100%;min-width:0;border:1px solid #34435a;border-radius:7px;background:#0a111e;color:var(--text);padding:7px 8px}.rule-enabled input{accent-color:var(--green)}.rules-card{padding:19px}.rule-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:15px}.btn{border:1px solid #34445d;border-radius:9px;background:#152136;color:#e5edf9;padding:9px 12px;font-size:11px;font-weight:750;transition:filter .15s}.btn:hover{filter:brightness(1.17)}.btn.primary{background:#123645;border-color:#28647a;color:#8de9fb}.btn:disabled{opacity:.5;cursor:wait}.rules-summary{color:var(--muted);font-size:11px;margin:0 0 13px}.rules-status{color:var(--muted);font-size:11px;margin-top:10px;min-height:18px}.footer{display:flex;gap:12px;justify-content:space-between;flex-wrap:wrap;margin-top:22px;color:#74839b;font-size:10px}.empty{padding:27px 16px;text-align:center;color:var(--muted);font-size:12px}.error-banner{display:none;margin-bottom:14px;padding:11px 13px;border-radius:9px;border:1px solid #704c29;background:#2c2318;color:#ffd695;font-size:11px}.error-banner.show{display:block}.pill-neutral{display:inline-block;padding:4px 7px;border-radius:6px;color:#b4c1d4;border:1px solid #34445b;background:#172236;font-size:9px;font-weight:800}.toolbar-button{background:transparent;border:1px solid var(--line);border-radius:8px;padding:7px 10px;color:#cdd8e8;font-size:10px;font-weight:750}.toolbar-button:hover{border-color:#4e7a91;color:var(--cyan)}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.layout-two{grid-template-columns:1fr}.side-stack{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:auto}.charts{grid-template-columns:repeat(2,minmax(0,1fr))}.charts .chart-card:last-child{grid-column:1/-1}}
@media(max-width:680px){.shell{padding:18px 12px 28px}.topbar{align-items:flex-start}.top-actions{gap:6px}.subhead{max-width:250px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.metric-card{padding:13px}.metric-value{margin-top:13px;font-size:23px}.side-stack{grid-template-columns:1fr}.charts{grid-template-columns:1fr}.charts .chart-card:last-child{grid-column:auto}.rule-list{grid-template-columns:1fr}.topology{grid-template-columns:1fr;grid-template-rows:auto;gap:10px}.node.h1,.node.s1,.node.h2,.node.h3{grid-column:1;grid-row:auto;text-align:left}.topology-lines{display:none}.node{min-height:91px}.brand-mark{width:39px;height:39px}.live-pill{padding:6px 8px}.top-actions .small-muted{display:none}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}
</style>
</head>
<body>
<div class="shell">
<header class="topbar">
  <div class="brand"><div class="brand-mark" aria-hidden="true">◈</div><div><div class="eyebrow">Network Defense / Telemetry</div><h1>SDN-IDS <span style="color:var(--cyan)">Live Panel</span></h1><div class="subhead">OpenFlow 1.3 · Ryu controller · hardware-level flow mitigation</div></div></div>
  <div class="top-actions"><span class="live-pill"><span class="live-dot"></span> LIVE POLLING</span><span class="small-muted">Updated <strong id="updatedAt">—</strong></span><button id="refreshNow" class="toolbar-button" type="button">Refresh now ↻</button></div>
</header>
<div id="errorBanner" class="error-banner" role="status"></div>
<section class="grid metrics" aria-label="Network summary">
  <article class="card metric-card"><div class="metric-top"><span>Controller</span><span class="metric-icon">⌘</span></div><div id="controllerMetric" class="metric-value">Checking…</div><div id="controllerFoot" class="metric-foot">Waiting for status telemetry</div></article>
  <article class="card metric-card"><div class="metric-top"><span>Packet throughput</span><span class="metric-icon">⇢</span></div><div id="ppsMetric" class="metric-value accent-cyan">— <small style="font-size:12px">pps</small></div><div id="ppsFoot" class="metric-foot">Packets per second across monitored sources</div></article>
  <article class="card metric-card"><div class="metric-top"><span>Network throughput</span><span class="metric-icon">⌁</span></div><div id="bpsMetric" class="metric-value accent-blue">—</div><div id="bpsFoot" class="metric-foot">Estimated from interval byte counters</div></article>
  <article class="card metric-card"><div class="metric-top"><span>Active flows</span><span class="metric-icon">⤨</span></div><div id="flowsMetric" class="metric-value">—</div><div id="flowsFoot" class="metric-foot">Quarantined ingress ports: —</div></article>
</section>

<section class="section">
 <div class="section-head"><h2>Topology & ingress defense</h2><span id="switchBadge" class="pill-neutral">s1 · checking</span></div>
 <div class="grid layout-two">
  <article class="card topology-card">
   <div class="topology" id="topology">
    <svg class="topology-lines" viewBox="0 0 1000 260" preserveAspectRatio="none" aria-hidden="true"><line id="lineH1" x1="275" y1="130" x2="410" y2="130"/><line id="lineH2" x1="590" y1="104" x2="730" y2="64"/><line id="lineH3" x1="590" y1="156" x2="730" y2="196"/></svg>
    <div class="node h1" id="nodeH1"><div class="node-role">Untrusted edge</div><div class="node-name" style="color:var(--red)">h1 · Attacker</div><div class="node-desc">10.0.0.1 · MAC 00:00:00:00:00:01</div><div class="node-foot"><span id="attackerState" class="chip red">ATTACKER ROLE</span><span id="attackerPort" class="chip">Ingress —</span></div></div>
    <div class="node s1" id="nodeS1"><div class="node-role">OpenFlow 1.3</div><div class="node-name" style="color:var(--cyan)">s1</div><div class="node-desc">Open vSwitch · Flow table</div><div class="node-foot" style="justify-content:center"><span id="switchState" class="chip cyan">CONNECTING</span></div></div>
    <div class="node h2" id="nodeH2"><div class="node-role">Protected endpoint</div><div class="node-name" style="color:var(--blue)">h2 · Server</div><div class="node-desc">10.0.0.2 · Protected host</div><div class="node-foot"><span class="chip blue">PROTECTED</span><span id="serverPort" class="chip">Port —</span></div></div>
    <div class="node h3" id="nodeH3"><div class="node-role">Trusted endpoint</div><div class="node-name" style="color:var(--green)">h3 · Legitimate host</div><div class="node-desc">10.0.0.3 · Normal traffic</div><div class="node-foot"><span class="chip green">LEGITIMATE</span><span id="clientPort" class="chip">Port —</span></div></div>
   </div>
   <div class="topology-legend"><span class="legend-item"><i class="legend-dot" style="background:var(--red)"></i>Attacker / quarantined</span><span class="legend-item"><i class="legend-dot" style="background:var(--blue)"></i>Protected server</span><span class="legend-item"><i class="legend-dot" style="background:var(--green)"></i>Legitimate host</span><span class="legend-item"><i class="legend-dot" style="background:#526781"></i>Observed switch link</span></div>
  </article>
  <div class="side-stack">
   <article class="card status-card"><div class="card-title"><h3>Defense status</h3><span class="chip green" id="defenseChip">MONITORING</span></div>
    <div class="state-row"><span class="state-name">Controller telemetry</span><strong class="state-value" id="controllerState">—</strong></div>
    <div class="state-row"><span class="state-name">Switch s1 connection</span><strong class="state-value" id="switchConnection">—</strong></div>
    <div class="state-row"><span class="state-name">Ingress quarantine</span><strong class="state-value" id="quarantineState">—</strong></div>
    <div class="state-row"><span class="state-name">Blocked source records</span><strong class="state-value" id="blockedSources">—</strong></div>
    <div class="status-sub" id="statusDetails">Status is read from logs/status.json and live OVS flow output.</div>
   </article>
   <article class="card status-card"><div class="card-title"><h3>Last mitigation</h3><span class="chip amber">BARRIER CONFIRMATION</span></div>
    <div id="lastMitigationTitle" style="font-size:17px;font-weight:800;letter-spacing:-.025em">Waiting for an IDS event</div>
    <div id="lastMitigationBody" class="status-sub" style="margin-top:7px">When a rule fires, its requested action and switch confirmation appear here.</div>
   </article>
  </div>
 </div>
</section>

<section class="section">
 <div class="section-head"><h2>Live traffic telemetry</h2><span class="section-note">Derived from logs/flow_stats.csv · updates automatically</span></div>
 <div class="grid charts">
  <article class="card chart-card"><div class="chart-title"><div><h3>Packets per second</h3><div class="chart-unit">pps · interval deltas</div></div><span class="chip cyan">RATE</span></div><div id="chartPpsKpi" class="chart-kpi">—</div><canvas id="chartPps" class="chart-canvas" aria-label="Packets per second over time"></canvas><div class="chart-foot">Aggregate rate for tracked source IPs</div></article>
  <article class="card chart-card"><div class="chart-title"><div><h3>Byte throughput</h3><div class="chart-unit">bytes/sec · estimated</div></div><span class="chip blue">BANDWIDTH</span></div><div id="chartBpsKpi" class="chart-kpi">—</div><canvas id="chartBps" class="chart-canvas" aria-label="Bytes per second over time"></canvas><div class="chart-foot">Interval byte deltas divided by sample interval</div></article>
  <article class="card chart-card"><div class="chart-title"><div><h3>Tracked flows</h3><div class="chart-unit">active flow entries</div></div><span class="chip green">FLOW TABLE</span></div><div id="chartFlowsKpi" class="chart-kpi">—</div><canvas id="chartFlows" class="chart-canvas" aria-label="Active flows over time"></canvas><div class="chart-foot">Sum of the controller's per-source flow counts</div></article>
 </div>
</section>

<section class="section">
 <div class="section-head"><h2>Live attack alert feed</h2><span id="eventCount" class="section-note">Waiting for logs/ids_events.jsonl</span></div>
 <article class="card alerts-card"><div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Rule / source</th><th>Detection & mitigation details</th><th>Ingress</th></tr></thead><tbody id="eventsBody"><tr><td colspan="5" class="empty">Waiting for IDS events…</td></tr></tbody></table></div></article>
</section>

<section class="section">
 <div class="section-head"><h2>Active OpenFlow 1.3 flow table</h2><span id="flowCount" class="section-note">Reading ovs-ofctl…</span></div>
 <article class="card flows-card"><div class="table-wrap"><table><thead><tr><th>Priority</th><th>Rule type</th><th>Match conditions</th><th>Actions</th><th>Packets</th><th>Bytes</th></tr></thead><tbody id="flowsBody"><tr><td colspan="6" class="empty">Waiting for ovs-ofctl dump-flows…</td></tr></tbody></table></div></article>
</section>

<section class="section">
 <div class="section-head"><h2>System defense controls</h2><button id="toggleRules" class="toolbar-button" type="button" aria-expanded="false" aria-controls="rulesPanel">Show thresholds ▾</button></div>
 <div class="card rules-card" id="rulesPanel" hidden>
  <p class="rules-summary">These controls read <code>controller/ids_rules.json</code>. Saving writes the JSON configuration atomically; the Ryu controller detects the updated file on its next monitoring cycle. Reload touches the file timestamp to request a controller reload without changing values.</p>
  <div id="ruleList" class="rule-list"><div class="empty">Loading rule configuration…</div></div>
  <div class="rule-actions"><button id="saveRules" class="btn primary" type="button">Save thresholds</button><button id="reloadRules" class="btn" type="button">Reload from JSON / notify controller</button><button id="resetRuleForm" class="btn" type="button">Discard unsaved edits</button></div>
  <div id="rulesStatus" class="rules-status" role="status"></div>
 </div>
</section>
<footer class="footer"><span>SDN-IDS · Local telemetry only · No external JavaScript or CDN dependencies</span><span>API refresh interval: <strong id="pollLabel">2.5 s</strong> · <span id="apiHealth">API checking</span></span></footer>
</div>
<script>
'use strict';
const POLL_MS = 2500;
let currentRules = null;
let latestPayload = null;
let lastRefresh = 0;
let refreshInFlight = false;
const $ = id => document.getElementById(id);
const fmtInt = n => Number.isFinite(Number(n)) ? Math.round(Number(n)).toLocaleString() : '—';
function fmtRate(n){ n=Number(n)||0; if(n>=1e9)return (n/1e9).toFixed(2)+' GB/s'; if(n>=1e6)return (n/1e6).toFixed(2)+' MB/s'; if(n>=1e3)return (n/1e3).toFixed(2)+' kB/s'; return n.toFixed(n<10?1:0)+' B/s'; }
function fmtTime(ts, fallback='—'){ const n=Number(ts); if(!Number.isFinite(n)||n<=0)return fallback; return new Date(n*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }
function setState(id,text,kind){ const el=$(id); el.textContent=text; el.className='state-value '+(kind==='ok'?'state-online':kind==='bad'?'state-offline':kind==='warn'?'state-warn':''); }
function textCell(tr, text, cls=''){ const td=document.createElement('td'); td.textContent=text ?? '—'; if(cls)td.className=cls; tr.appendChild(td); return td; }
function chipClass(event){ if(event==='ALERT')return 'event-type event-alert'; if(event==='BLOCK_INSTALLED')return 'event-type event-block'; if(event==='UNBLOCKED')return 'event-type event-recovery'; return 'event-type event-other'; }
function eventLabel(e){return ({ALERT:'ATTACK DETECTED',BLOCK_INSTALLED:'MITIGATION ACTIVE',UNBLOCKED:'RECOVERED',RULES_RELOADED:'RULES RELOADED'})[e] || String(e||'EVENT').replaceAll('_',' ');}
function renderEvents(events){ const body=$('eventsBody'); body.replaceChildren(); $('eventCount').textContent=`${events.length} recent records · ids_events.jsonl`;
 if(!events.length){const tr=document.createElement('tr');const td=textCell(tr,'No IDS events have been recorded yet. Trigger a controlled lab attack to populate this feed.');td.colSpan=5;td.className='empty';body.appendChild(tr);return;}
 for(const ev of events.slice(0,30)){const tr=document.createElement('tr');textCell(tr,ev.time || fmtTime(ev.ts),'mono');const evtd=document.createElement('td');const b=document.createElement('span');b.className=chipClass(ev.event);b.textContent=eventLabel(ev.event);evtd.appendChild(b);tr.appendChild(evtd);
 const rules=Array.isArray(ev.rules)?ev.rules.join(', '):(ev.rule||'—');const src=[ev.ip||ev.src_ip||'',ev.mac||''].filter(Boolean).join(' · ');const sourceCell=textCell(tr,[rules,src].filter(Boolean).join('\n'),'mono');sourceCell.style.whiteSpace='pre-line';
 const detailCell=document.createElement('td');detailCell.className='event-detail';const title=document.createElement('div');title.textContent=ev.detail||ev.mitigation_action||'—';detailCell.appendChild(title);const meta=document.createElement('div');meta.className='event-meta';const extras=[];if(ev.detect_latency_ms!==undefined)extras.push(`detect ${Number(ev.detect_latency_ms).toFixed(1)} ms`);if(ev.response_ms!==undefined)extras.push(`response ${Number(ev.response_ms).toFixed(2)} ms`);if(ev.total_ms!==undefined)extras.push(`total ${Number(ev.total_ms).toFixed(1)} ms`);if(ev.mitigation_action)extras.push(ev.mitigation_action);if(ev.reason)extras.push(`recovery: ${ev.reason}`);meta.textContent=extras.join(' · ');detailCell.appendChild(meta);tr.appendChild(detailCell);
 const ingress=[ev.in_port!==undefined&&ev.in_port!==null?`port ${ev.in_port}`:'',ev.action_target||''].filter(Boolean).join(' · ');textCell(tr,ingress||'—','mono');body.appendChild(tr);}
}
function renderFlows(flows, error){const body=$('flowsBody');body.replaceChildren();$('flowCount').textContent=error?`Unavailable · ${error}`:`${flows.length} rules parsed from s1`;
 if(!flows.length){const tr=document.createElement('tr');const td=textCell(tr,error||'No active flows were returned. Confirm that s1 is running and OpenFlow 1.3 is enabled.');td.colSpan=6;td.className='empty';body.appendChild(tr);return;}
 for(const f of flows.slice(0,200)){const tr=document.createElement('tr');textCell(tr,String(f.priority),'mono');let kind=f.action_kind==='DROP'?'DROP':f.action_kind==='CONTROLLER'?'CONTROLLER':f.action_kind==='OUTPUT'?'FORWARD':'OTHER';const kd=document.createElement('td');const k=document.createElement('span');k.className='event-type '+(kind==='DROP'?'event-alert':kind==='CONTROLLER'?'event-other':kind==='FORWARD'?'event-block':'');k.textContent=kind;kd.appendChild(k);tr.appendChild(kd);textCell(tr,f.match||'all packets','mono');textCell(tr,f.actions||'DROP (no actions)','mono');textCell(tr,fmtInt(f.packets),'mono');textCell(tr,fmtInt(f.bytes),'mono');body.appendChild(tr);}
}
function drawChart(id, points, field, lineColor, formatter){ const c=$(id); const rect=c.getBoundingClientRect(); const cssW=Math.max(220,rect.width||280), cssH=130, dpr=window.devicePixelRatio||1; c.width=Math.round(cssW*dpr);c.height=Math.round(cssH*dpr);c.style.height=cssH+'px';const ctx=c.getContext('2d');ctx.scale(dpr,dpr);ctx.clearRect(0,0,cssW,cssH);const left=35,right=7,top=8,bottom=22,w=cssW-left-right,h=cssH-top-bottom;
 const values=points.map(p=>Number(p[field])||0);const maxValue=Math.max(1,...values)*1.12;ctx.font='9px system-ui';ctx.textBaseline='middle';
 for(let i=0;i<=3;i++){const y=top+h*i/3;ctx.strokeStyle='#253349';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(cssW-right,y);ctx.stroke();ctx.fillStyle='#8090a8';const val=maxValue*(1-i/3);let label=formatter(val);ctx.fillText(label,1,y);}
 if(values.length<1){ctx.fillStyle='#8090a8';ctx.textAlign='center';ctx.fillText('Waiting for flow statistics…',left+w/2,top+h/2);ctx.textAlign='left';return;}
 const xy=values.map((v,i)=>({x:left+(values.length===1?w/2:i*w/(values.length-1)),y:top+h-(v/maxValue)*h}));ctx.beginPath();xy.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.lineTo(xy[xy.length-1].x,top+h);ctx.lineTo(xy[0].x,top+h);ctx.closePath();ctx.fillStyle=lineColor+'22';ctx.fill();ctx.beginPath();xy.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.strokeStyle=lineColor;ctx.lineWidth=2;ctx.lineJoin='round';ctx.stroke();const last=xy[xy.length-1];ctx.beginPath();ctx.arc(last.x,last.y,3,0,Math.PI*2);ctx.fillStyle=lineColor;ctx.fill();
 const idxs=[0,Math.floor((points.length-1)/3),Math.floor(2*(points.length-1)/3),points.length-1].filter((v,i,a)=>a.indexOf(v)===i);ctx.fillStyle='#8090a8';ctx.textBaseline='top';for(const ix of idxs){const label=fmtTime(points[ix].timestamp,'');let x=xy[ix].x;const tw=ctx.measureText(label).width;if(ix===0)x=left;else if(ix===points.length-1)x=Math.max(left,Math.min(cssW-right-tw,x-tw));else x=Math.max(left,Math.min(cssW-right-tw,x-tw/2));ctx.fillText(label,x,top+h+7);}
}
function renderTelemetry(payload){latestPayload=payload;const status=payload.status||{};const online=Boolean(payload.controller_online);const swOnline=Boolean(payload.switch_online);const series=payload.series||[];const current=series.length?series[series.length-1]:{packets_per_sec:0,bytes_per_sec:0,active_flows:0};const activePorts=payload.quarantined_ports||[];const blocked=payload.controller_online?(status.blocked||{}):{};
 $('controllerMetric').textContent=online?'ONLINE':'OFFLINE';$('controllerMetric').className='metric-value '+(online?'accent-green':'accent-red');$('controllerFoot').textContent=online?`Status age ${Math.max(0,Math.round(payload.status_age_seconds||0))} s`:'No fresh controller status';$('ppsMetric').innerHTML=`${fmtInt(current.packets_per_sec)} <small style="font-size:12px">pps</small>`;$('bpsMetric').textContent=fmtRate(current.bytes_per_sec);$('flowsMetric').textContent=fmtInt(current.active_flows);$('flowsFoot').textContent=`Quarantined ingress ports: ${activePorts.length?activePorts.join(', '):'none detected'}`;
 setState('controllerState',online?'ONLINE':'OFFLINE',online?'ok':'bad');setState('switchConnection',swOnline?'CONNECTED':'DISCONNECTED',swOnline?'ok':'bad');setState('quarantineState',activePorts.length?`ACTIVE · ${activePorts.join(', ')}`:'NONE DETECTED',activePorts.length?'bad':'ok');setState('blockedSources',online?String(Object.keys(blocked).length):'STALE',online&&Object.keys(blocked).length?'warn':online?'ok':'warn');
 $('switchBadge').textContent=swOnline?'s1 · connected':'s1 · disconnected';$('switchState').textContent=swOnline?'CONNECTED':'OFFLINE';$('switchState').className='chip '+(swOnline?'cyan':'red');$('attackerPort').textContent=`Ingress ${payload.port_map?.h1 ?? '—'}`;$('serverPort').textContent=`Port ${payload.port_map?.h2 ?? '—'}`;$('clientPort').textContent=`Port ${payload.port_map?.h3 ?? '—'}`;
 const h1port=payload.port_map?.h1;const quarantineMatch=h1port!==null&&h1port!==undefined&&activePorts.map(Number).includes(Number(h1port));$('attackerState').textContent=quarantineMatch?'QUARANTINED':'ATTACKER ROLE';$('attackerState').className='chip '+(quarantineMatch?'red':'red');$('lineH1').classList.toggle('quarantined',quarantineMatch);$('statusDetails').textContent=payload.ovs_error?`Open vSwitch telemetry: ${payload.ovs_error}`:`Rule reload timestamp: ${fmtTime(status.rules_loaded_at)} · Stats interval: ${status.stats_interval??'—'} s`;
 $('defenseChip').textContent=activePorts.length?'QUARANTINE ACTIVE':'MONITORING';$('defenseChip').className='chip '+(activePorts.length?'red':'green');
 const lastMit=(payload.events||[]).find(e=>e.event==='BLOCK_INSTALLED'||e.event==='UNBLOCKED'||e.event==='ALERT');if(lastMit){const r=Array.isArray(lastMit.rules)?lastMit.rules.join(', '):(lastMit.rule||'IDS event');$('lastMitigationTitle').textContent=`${lastMit.event==='UNBLOCKED'?'Recovered':lastMit.event==='BLOCK_INSTALLED'?'Mitigation confirmed':'Alert'} · ${r}`;$('lastMitigationBody').textContent=[lastMit.ip,lastMit.mac,lastMit.in_port!==undefined&&lastMit.in_port!==null?`ingress port ${lastMit.in_port}`:'',lastMit.mitigation_action||lastMit.detail||'',lastMit.response_ms!==undefined?`switch response ${lastMit.response_ms} ms`:''].filter(Boolean).join(' · ');}else{$('lastMitigationTitle').textContent='Waiting for an IDS event';$('lastMitigationBody').textContent='When a rule fires, its requested action and switch confirmation appear here.';}
 $('updatedAt').textContent=new Date().toLocaleTimeString();$('apiHealth').textContent='API healthy';$('apiHealth').style.color='var(--green)';$('pollLabel').textContent=(POLL_MS/1000).toFixed(1)+' s';$('chartPpsKpi').textContent=fmtInt(current.packets_per_sec)+' pps';$('chartBpsKpi').textContent=fmtRate(current.bytes_per_sec);$('chartFlowsKpi').textContent=fmtInt(current.active_flows);
 drawChart('chartPps',series,'packets_per_sec','#57d7f3',n=>fmtInt(n));drawChart('chartBps',series,'bytes_per_sec','#6ea8fe',n=>n>=1000?fmtRate(n):fmtInt(n));drawChart('chartFlows',series,'active_flows','#50e3a4',n=>fmtInt(n));renderEvents(payload.events||[]);renderFlows(payload.flows||[],payload.ovs_error);
 const errors=[];if(!online)errors.push('No fresh controller status found. Start Ryu and confirm logs/status.json is being updated.');if(payload.ovs_error)errors.push('OpenFlow table unavailable: '+payload.ovs_error);if(payload.telemetry_error)errors.push(payload.telemetry_error);const banner=$('errorBanner');banner.textContent=errors.join(' ');banner.classList.toggle('show',errors.length>0);
}
async function refresh(){if(refreshInFlight)return;refreshInFlight=true;try{const r=await fetch('/api/telemetry',{cache:'no-store'});if(!r.ok)throw new Error(`Telemetry API returned HTTP ${r.status}`);const data=await r.json();renderTelemetry(data);lastRefresh=Date.now();}catch(err){$('apiHealth').textContent='API error';$('apiHealth').style.color='var(--red)';$('errorBanner').textContent='Unable to read telemetry: '+err.message;$('errorBanner').classList.add('show');}finally{refreshInFlight=false;}}
async function fetchRules(){const status=$('rulesStatus');try{const r=await fetch('/api/rules',{cache:'no-store'});const data=await r.json();if(!r.ok)throw new Error(data.error||'Could not read rules');currentRules=data.rules;renderRules(currentRules);status.textContent=`Loaded ${Object.keys(currentRules).filter(k=>currentRules[k]&&typeof currentRules[k]==='object'&&'enabled'in currentRules[k]).length} detection rules from controller/ids_rules.json.`;}catch(err){status.textContent='Rules load failed: '+err.message;}}
function renderRules(rules){const host=$('ruleList');host.replaceChildren();for(const [name,cfg] of Object.entries(rules||{})){if(!KNOWN_RULE_NAMES.has(name)||!cfg||typeof cfg!=='object')continue;const row=document.createElement('div');row.className='rule-row';const info=document.createElement('div');const n=document.createElement('div');n.className='rule-name';n.textContent=name;n.title=name;info.appendChild(n);const enabled=document.createElement('label');enabled.className='rule-enabled';const cb=document.createElement('input');cb.type='checkbox';cb.checked=Boolean(cfg.enabled);cb.dataset.rule=name;cb.dataset.field='enabled';enabled.append(cb,document.createTextNode('Enabled'));info.appendChild(enabled);row.appendChild(info);
 const threshold=document.createElement('div');threshold.className='rule-field';const tl=document.createElement('label');tl.textContent='Threshold';tl.htmlFor=`rule-${name}-threshold`;const ti=document.createElement('input');ti.type='number';ti.min='1';ti.max='1000000000';ti.step='1';ti.id=`rule-${name}-threshold`;ti.value=cfg.threshold??1;ti.dataset.rule=name;ti.dataset.field='threshold';threshold.append(tl,ti);row.appendChild(threshold);
 const win=document.createElement('div');win.className='rule-field';const wl=document.createElement('label');wl.textContent='Window (s)';wl.htmlFor=`rule-${name}-window`;const wi=document.createElement('input');wi.type='number';wi.min='0.01';wi.max='3600';wi.step='0.1';wi.id=`rule-${name}-window`;wi.value=cfg.window??'';wi.disabled=cfg.window===undefined;wi.dataset.rule=name;wi.dataset.field='window';win.append(wl,wi);row.appendChild(win);host.appendChild(row);}}
const KNOWN_RULE_NAMES=new Set(['conn_flood','port_scan','invalid_flags','concurrent_flows','packet_rate','multi_ip_spoof','port_flood']);
async function saveRules(){const btn=$('saveRules');btn.disabled=true;try{const rules=JSON.parse(JSON.stringify(currentRules||{}));document.querySelectorAll('#ruleList [data-rule]').forEach(el=>{const name=el.dataset.rule,field=el.dataset.field;if(!rules[name])return;if(field==='enabled')rules[name].enabled=el.checked;else if(field==='threshold'){const v=Number(el.value);if(!Number.isFinite(v)||v<=0)throw new Error(`${name}: threshold must be greater than zero`);rules[name].threshold=v;}else if(field==='window'&&!el.disabled){const v=Number(el.value);if(!Number.isFinite(v)||v<=0)throw new Error(`${name}: window must be greater than zero`);rules[name].window=v;}});const r=await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rules})});const data=await r.json();if(!r.ok)throw new Error(data.error||'Save failed');currentRules=data.rules;renderRules(currentRules);$('rulesStatus').textContent='Saved. Ryu will detect the modified file on its next rules polling cycle.';await refresh();}catch(err){$('rulesStatus').textContent='Save failed: '+err.message;}finally{btn.disabled=false;}}
async function reloadRules(){const btn=$('reloadRules');btn.disabled=true;try{const r=await fetch('/api/rules/reload',{method:'POST'});const data=await r.json();if(!r.ok)throw new Error(data.error||'Reload request failed');currentRules=data.rules;renderRules(currentRules);$('rulesStatus').textContent='Rules re-read from JSON. The file timestamp was updated; Ryu will re-load it on the next monitoring cycle (check Controller console/status timestamp).';await refresh();}catch(err){$('rulesStatus').textContent='Reload failed: '+err.message;}finally{btn.disabled=false;}}
$('toggleRules').addEventListener('click',()=>{const hidden=!$('rulesPanel').hidden;$('rulesPanel').hidden=hidden;$('toggleRules').setAttribute('aria-expanded',String(!hidden));$('toggleRules').textContent=hidden?'Show thresholds ▾':'Hide thresholds ▴';if(!hidden&&!currentRules)fetchRules();});
$('saveRules').addEventListener('click',saveRules);$('reloadRules').addEventListener('click',reloadRules);$('resetRuleForm').addEventListener('click',()=>{renderRules(currentRules||{});$('rulesStatus').textContent='Unsaved edits discarded.';});$('refreshNow').addEventListener('click',refresh);window.addEventListener('resize',()=>{if(latestPayload)renderTelemetry(latestPayload);});
refresh();setInterval(refresh,POLL_MS);
</script>
</body></html>'''


def _read_json(path: Path, fallback: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return fallback


def _tail_jsonl(path: Path, limit: int = 100) -> list[dict[str, Any]]:
    rows: deque[str] = deque(maxlen=limit)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            rows.extend(f)
    except OSError:
        return []
    parsed: list[dict[str, Any]] = []
    for line in rows:
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                parsed.append(item)
        except json.JSONDecodeError:
            continue
    parsed.sort(key=lambda item: float(item.get("ts") or 0), reverse=True)
    return parsed


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if result == result and abs(result) != float("inf") else default
    except (TypeError, ValueError):
        return default


def load_series(path: Path, default_interval: float = 3.0, limit: int = 90) -> list[dict[str, float]]:
    """Aggregate per-source CSV rows into one time-series point per sample."""
    grouped: dict[float, dict[str, float]] = defaultdict(lambda: {
        "packets_per_sec": 0.0, "bytes_in_interval": 0.0, "active_flows": 0.0
    })
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts = _safe_float(row.get("timestamp"), -1)
                if ts < 0:
                    continue
                # Controller timestamps are written to milliseconds. Group small
                # representation differences into the same poll sample.
                key = round(ts, 3)
                grouped[key]["packets_per_sec"] += max(0, _safe_float(row.get("packets_per_sec")))
                grouped[key]["bytes_in_interval"] += max(0, _safe_float(row.get("bytes_in_interval")))
                grouped[key]["active_flows"] += max(0, _safe_float(row.get("active_flows")))
    except OSError:
        return []
    timestamps = sorted(grouped)
    out: list[dict[str, float]] = []
    for i, ts in enumerate(timestamps):
        if i:
            dt = max(0.05, ts - timestamps[i - 1])
        else:
            dt = max(0.05, default_interval)
        item = grouped[ts]
        out.append({
            "timestamp": ts,
            "packets_per_sec": round(item["packets_per_sec"], 2),
            "bytes_per_sec": round(item["bytes_in_interval"] / dt, 2),
            "active_flows": round(item["active_flows"], 2),
        })
    return out[-limit:]


def _run_ovs(args: list[str], timeout: float = 1.5, remote_host: str | None = None) -> str:
    """Run a fixed OVS query locally or through batch-mode SSH to the switch host."""
    command = ["ovs-ofctl", "-O", "OpenFlow13", *args]
    if remote_host:
        # Each remote command token is quoted; no shell interpolation of caller input.
        remote_command = "sudo -n " + " ".join(shlex.quote(part) for part in command)
        ssh_command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
                       remote_host, remote_command]
        try:
            res = subprocess.run(ssh_command, capture_output=True, text=True,
                                 timeout=max(timeout, 2.5), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"SSH to {remote_host} failed: {exc}") from exc
        if res.returncode == 0:
            return res.stdout
        message = (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
        raise RuntimeError(f"Remote OVS query via {remote_host} failed: {message}")

    try:
        res = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        first_error = str(exc)
    else:
        if res.returncode == 0:
            return res.stdout
        first_error = (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        try:
            res = subprocess.run(["sudo", "-n", *command], capture_output=True, text=True,
                                 timeout=timeout, check=False)
            if res.returncode == 0:
                return res.stdout
            second_error = (res.stderr or res.stdout or f"exit code {res.returncode}").strip()
            raise RuntimeError(f"{first_error}; sudo -n: {second_error}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"{first_error}; sudo -n: {exc}") from exc
    raise RuntimeError(first_error)


def parse_flows(dump: str) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    for raw in dump.splitlines():
        line = raw.strip()
        if not line or "actions=" not in line:
            continue
        left, actions = line.split("actions=", 1)
        p_match = re.search(r"(?:^|,)\s*priority=(\d+)", left)
        p_count = re.search(r"(?:^|,)\s*n_packets=(\d+)", left)
        b_count = re.search(r"(?:^|,)\s*n_bytes=(\d+)", left)
        if not p_match:
            continue
        match_parts = []
        for part in left.split(","):
            part = part.strip()
            if not part:
                continue
            if re.match(r"^(cookie|duration|table|n_packets|n_bytes|idle_age|hard_age|priority)=", part):
                continue
            match_parts.append(part)
        actions = actions.strip()
        upper = actions.upper()
        if not actions or actions.lower() == "drop":
            kind = "DROP"
        elif "CONTROLLER" in upper:
            kind = "CONTROLLER"
        elif "OUTPUT:" in upper or "OUTPUT(" in upper:
            kind = "OUTPUT"
        else:
            kind = "OTHER"
        flows.append({
            "priority": int(p_match.group(1)),
            "match": ", ".join(match_parts) or "all packets",
            "actions": actions or "DROP (no actions)",
            "action_kind": kind,
            "packets": int(p_count.group(1)) if p_count else 0,
            "bytes": int(b_count.group(1)) if b_count else 0,
            "raw": line,
        })
    flows.sort(key=lambda item: (item["priority"], item["packets"]), reverse=True)
    return flows


def parse_ports(show_output: str) -> dict[str, int]:
    ports: dict[str, int] = {}
    for line in show_output.splitlines():
        match = re.match(r"\s*(\d+)\(([^)]+)\):", line)
        if match:
            ports[match.group(2)] = int(match.group(1))
    return ports


def map_host_ports(ports: dict[str, int]) -> dict[str, int | None]:
    """Map topology roles for this repository's single and distributed modes."""
    if "vxlan0" in ports:
        return {
            "h1": ports.get("vxlan0"),
            "h2": ports.get("s1-eth1"),
            "h3": ports.get("s1-eth2"),
        }
    return {
        "h1": ports.get("s1-eth1"),
        "h2": ports.get("s1-eth2"),
        "h3": ports.get("s1-eth3"),
    }


def _file_age_seconds(path: Path, timestamp: Any = None) -> float | None:
    stamp = _safe_float(timestamp, -1) if timestamp is not None else -1
    if stamp < 0:
        try:
            stamp = path.stat().st_mtime
        except OSError:
            return None
    return max(0.0, time.time() - stamp)


def telemetry_snapshot(switch: str = "s1", ovs_ssh: str | None = None) -> dict[str, Any]:
    status = _read_json(STATUS_JSON, {})
    if not isinstance(status, dict):
        status = {}
    stats_interval = max(0.1, _safe_float(status.get("stats_interval"), 3.0))
    series = load_series(STATS_CSV, default_interval=stats_interval)
    events = _tail_jsonl(EVENT_LOG, limit=120)
    ovs_error = None
    flow_output = ""
    port_output = ""
    try:
        flow_output = _run_ovs(["dump-flows", switch], remote_host=ovs_ssh)
    except RuntimeError as exc:
        ovs_error = str(exc)
    try:
        port_output = _run_ovs(["show", switch], remote_host=ovs_ssh)
    except RuntimeError as exc:
        if not ovs_error:
            ovs_error = str(exc)
    flows = parse_flows(flow_output)
    raw_ports = parse_ports(port_output)
    host_ports = map_host_ports(raw_ports)

    status_age = _file_age_seconds(STATUS_JSON, status.get("ts"))
    fresh_limit = max(15.0, stats_interval * 4.0)
    controller_online = status_age is not None and status_age <= fresh_limit
    switch_ids = status.get("switches", [])
    switch_online = controller_online and (1 in switch_ids or "1" in switch_ids)

    blocked = status.get("blocked", {}) if isinstance(status.get("blocked", {}), dict) else {}
    quarantined_ports = set()
    # Status is only trusted for current state while its heartbeat is fresh;
    # current OVS flow rules below can independently confirm an installed DROP.
    if controller_online:
        for value in status.get("blocked_ports", []) if isinstance(status.get("blocked_ports", []), list) else []:
            try:
                quarantined_ports.add(int(value))
            except (ValueError, TypeError):
                pass
        for item in blocked.values():
            if isinstance(item, dict) and item.get("action_target") == "port" and item.get("in_port") is not None:
                try:
                    quarantined_ports.add(int(item["in_port"]))
                except (ValueError, TypeError):
                    pass
    # The flow table is authoritative for currently installed priority-200 port drops.
    for flow in flows:
        if flow["priority"] >= 200 and flow["action_kind"] == "DROP":
            port_match = re.search(r"(?:^|,\s*)in_port=(\d+)", flow["match"])
            if port_match:
                quarantined_ports.add(int(port_match.group(1)))

    recent_attack_ports = []
    for event in events:
        if event.get("event") in ("ALERT", "BLOCK_INSTALLED") and event.get("in_port") is not None:
            try:
                recent_attack_ports.append(int(event["in_port"]))
            except (ValueError, TypeError):
                pass
    current = series[-1] if series else {"timestamp": 0, "packets_per_sec": 0, "bytes_per_sec": 0, "active_flows": 0}
    errors = []
    if not status:
        errors.append("status.json is missing or unreadable")
    if not series:
        errors.append("flow_stats.csv has no readable telemetry rows yet")
    return {
        "generated_at": time.time(),
        "status": status,
        "status_age_seconds": round(status_age, 2) if status_age is not None else None,
        "controller_online": controller_online,
        "switch_online": switch_online,
        "series": series,
        "current": current,
        "events": events,
        "flows": flows,
        "ovs_error": ovs_error,
        "telemetry_error": "; ".join(errors) if errors else None,
        "port_map": host_ports,
        "ports": raw_ports,
        "quarantined_ports": sorted(quarantined_ports),
        "recent_attack_ports": recent_attack_ports,
        "switch": switch,
        "ovs_remote_host": ovs_ssh,
    }


def _validate_and_write_rules(candidate: Any) -> dict[str, Any]:
    current = _read_json(RULES_JSON, None)
    if not isinstance(current, dict):
        raise ValueError("Controller rules JSON is missing or invalid")
    if not isinstance(candidate, dict):
        raise ValueError("Request must contain a rules object")
    updated = json.loads(json.dumps(current))
    for name, values in candidate.items():
        if name not in KNOWN_RULES:
            continue
        if not isinstance(values, dict):
            raise ValueError(f"{name}: rule values must be an object")
        if name not in updated or not isinstance(updated[name], dict):
            raise ValueError(f"{name}: configured rule is not an object")
        if "enabled" in values:
            if not isinstance(values["enabled"], bool):
                raise ValueError(f"{name}: enabled must be true or false")
            updated[name]["enabled"] = values["enabled"]
        if "threshold" in values:
            val = values["threshold"]
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not (0 < float(val) <= 1_000_000_000):
                raise ValueError(f"{name}: threshold must be a positive number")
            updated[name]["threshold"] = int(val) if float(val).is_integer() else float(val)
        if "window" in values and "window" in updated[name]:
            val = values["window"]
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not (0 < float(val) <= 3600):
                raise ValueError(f"{name}: window must be in the range (0, 3600]")
            updated[name]["window"] = float(val)
    # Write and fsync a sibling temporary file before atomically replacing the config.
    mode = 0o644
    original_stat = None
    try:
        original_stat = RULES_JSON.stat()
        mode = original_stat.st_mode & 0o777
    except OSError:
        pass
    tmp = RULES_JSON.with_name(RULES_JSON.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(updated, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    # If the dashboard runs under sudo for OVS access, preserve the original
    # config owner so the normal controller account can continue editing it.
    if original_stat is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(tmp, original_stat.st_uid, original_stat.st_gid)
    os.replace(tmp, RULES_JSON)
    return updated


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SDNIDSTelemetry/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Compact local request log; the telemetry event feed remains authoritative.
        print(f"[telemetry] {self.address_string()} - {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, obj: Any) -> None:
        self._send(status, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    def _read_body_json(self) -> Any:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON") from exc

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._send(200, HTML_PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/healthz":
            self._send_json(200, {"ok": True, "root": str(ROOT)})
        elif path == "/api/telemetry":
            switch = getattr(self.server, "switch_name", "s1")
            ovs_ssh = getattr(self.server, "ovs_ssh", None)
            self._send_json(200, telemetry_snapshot(switch, ovs_ssh))
        elif path == "/api/rules":
            rules = _read_json(RULES_JSON, None)
            if not isinstance(rules, dict):
                self._send_json(500, {"error": "Could not read controller/ids_rules.json"})
            else:
                self._send_json(200, {"rules": rules, "path": str(RULES_JSON)})
        elif path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/rules":
                body = self._read_body_json()
                if not isinstance(body, dict) or "rules" not in body:
                    raise ValueError("Request must contain a rules object")
                rules = _validate_and_write_rules(body["rules"])
                self._send_json(200, {"ok": True, "rules": rules, "saved_at": time.time(),
                                      "message": "Saved; the controller polls the file modification time."})
            elif path == "/api/rules/reload":
                rules = _read_json(RULES_JSON, None)
                if not isinstance(rules, dict):
                    raise ValueError("Controller rules JSON is missing or invalid")
                now = time.time()
                os.utime(RULES_JSON, (now, now))
                self._send_json(200, {"ok": True, "rules": rules, "requested_at": now,
                                      "message": "Rules re-read; file timestamp touched to trigger Ryu reload."})
            else:
                self._send_json(404, {"error": "Not found"})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except OSError as exc:
            self._send_json(500, {"error": f"File operation failed: {exc}"})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--switch", default="s1", help="OVS bridge name (default: s1)")
    parser.add_argument("--ovs-ssh", default=os.environ.get("IDS_OVS_SSH"),
                        help="Optional SSH destination user@switch-host for distributed mode; requires SSH keys and sudo -n ovs-ofctl there")
    args = parser.parse_args()
    if not (1 <= args.port <= 65535):
        parser.error("--port must be in range 1..65535")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    server.daemon_threads = True
    server.switch_name = args.switch
    server.ovs_ssh = args.ovs_ssh
    print(f"[telemetry] SDN-IDS dashboard: http://{args.host}:{args.port}")
    print(f"[telemetry] Project root: {ROOT}")
    print(f"[telemetry] Rules file:   {RULES_JSON}")
    if args.ovs_ssh:
        print(f"[telemetry] Open vSwitch queries via SSH: {args.ovs_ssh}")
    print("[telemetry] Press Ctrl+C to stop. No third-party Python packages required.")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\n[telemetry] Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
