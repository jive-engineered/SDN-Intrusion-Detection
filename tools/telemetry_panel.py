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
<title>sdn-ids monitor</title>
<style>
  :root{
    --bg:#0b0e13; --panel:#11151c; --panel2:#0e1218; --bd:#232b36; --bd2:#1a212b;
    --fg:#c2ccd6; --mut:#6b7684; --dim:#49525e;
    --grn:#3fb950; --red:#f0504a; --amb:#d6a426; --blu:#4c93f0; --cyn:#3fb6c2; --vio:#9a7cf0;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:var(--bg);color:var(--fg);
    font:12.5px/1.45 ui-monospace,"DejaVu Sans Mono","SF Mono",Menlo,Consolas,monospace}
  .wrap{max-width:1560px;margin:0 auto;padding:10px 14px 30px}

  /* top bar */
  .bar{display:flex;align-items:center;justify-content:space-between;
    border:1px solid var(--bd);background:var(--panel);padding:8px 12px}
  .bar .l{display:flex;align-items:baseline;gap:10px}
  .logo{color:var(--fg);font-weight:700;letter-spacing:.5px}
  .logo b{color:var(--cyn)}
  .tag{color:var(--mut);font-size:11px}
  .bar .r{display:flex;align-items:center;gap:16px;font-size:11px}
  .stat-ctrl{display:flex;align-items:center;gap:6px}
  .dot{width:7px;height:7px;border-radius:1px;display:inline-block;background:var(--dim)}
  .dot.on{background:var(--grn)} .dot.off{background:var(--red)}
  .blink{animation:bl 1.2s steps(2,start) infinite}
  @keyframes bl{0%,50%{opacity:1}51%,100%{opacity:.25}}
  .clock{color:var(--mut)}

  /* threat line */
  .threat{display:none;border:1px solid #5a2422;border-left:3px solid var(--red);
    background:#1a0f10;color:var(--red);padding:6px 12px;margin-top:8px;font-size:12px}
  .threat.show{display:block}
  .threat b{color:#ff756f}

  /* stat strip */
  .strip{display:grid;grid-template-columns:repeat(6,1fr);margin-top:8px;
    border:1px solid var(--bd);border-right:0;background:var(--panel)}
  .cell{border-right:1px solid var(--bd);padding:9px 12px;min-width:0}
  .cell .k{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.6px}
  .cell .v{font-size:22px;font-weight:700;margin-top:3px;letter-spacing:-.5px;white-space:nowrap}
  .cell .v small{font-size:11px;color:var(--mut);font-weight:400}
  .cell .s{color:var(--dim);font-size:10px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .vred{color:var(--red)} .vgrn{color:var(--grn)} .vamb{color:var(--amb)} .vblu{color:var(--blu)} .vcyn{color:var(--cyn)} .vvio{color:var(--vio)}

  /* layout */
  .grid{display:grid;grid-template-columns:1fr 430px;gap:8px;margin-top:8px}
  .col{display:flex;flex-direction:column;gap:8px;min-width:0}
  .box{border:1px solid var(--bd);background:var(--panel);min-width:0}
  .box>h2{font-size:11px;font-weight:700;color:var(--fg);text-transform:uppercase;letter-spacing:.8px;
    padding:7px 11px;border-bottom:1px solid var(--bd);background:var(--panel2);
    display:flex;justify-content:flex-start;align-items:center;gap:8px}
  .box>h2::before{content:"";width:3px;height:11px;background:var(--cyn);display:inline-block;margin-right:-1px}
  .box>h2 .note{color:var(--dim);font-weight:400;text-transform:none;letter-spacing:0;font-size:10px;margin-left:auto}
  .box.grow{display:flex;flex-direction:column}
  .col>.box.grow{flex:1}
  .box.grow .log{flex:1;max-height:470px}
  .pad{padding:10px 11px}
  .full{margin-top:8px}

  /* charts */
  #chart{width:100%;height:180px;display:block}
  .cgrid{stroke:var(--bd2);stroke-width:1}
  .cthr{stroke:var(--amb);stroke-width:1;stroke-dasharray:3 3;opacity:.55}
  .clab{fill:var(--dim);font-size:9.5px}
  .legend{display:flex;flex-wrap:wrap;gap:3px 14px;padding:8px 11px;border-top:1px solid var(--bd);font-size:10.5px}
  .lg{display:flex;align-items:center;gap:5px;color:var(--mut)}
  .sw{width:9px;height:2px;display:inline-block}
  .minis{display:grid;grid-template-columns:repeat(3,1fr)}
  .mini{padding:8px 11px 6px;border-right:1px solid var(--bd)}
  .mini:last-child{border-right:0}
  .mini .mk{color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:.5px;display:flex;justify-content:space-between}
  .mini .mv{font-size:15px;font-weight:700;margin:2px 0 4px}
  .mini svg{width:100%;height:56px;display:block}

  /* tables */
  table{width:100%;border-collapse:collapse}
  th{text-align:left;color:var(--mut);font-weight:400;font-size:10px;text-transform:uppercase;letter-spacing:.5px;
    padding:6px 11px;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--panel)}
  td{padding:5px 11px;border-bottom:1px solid var(--bd2);font-size:11.5px;white-space:nowrap}
  tr:last-child td{border-bottom:0}
  .t-state{font-size:10px;padding:1px 5px;border:1px solid var(--bd);color:var(--mut)}
  .st-up{color:var(--grn);border-color:#204a2a}
  .st-blk{color:var(--red);border-color:#5a2422;background:#1a0f10}
  .st-prot{color:var(--blu);border-color:#1e3a5a}
  .st-idle{color:var(--dim)}
  .st-att{color:var(--red)}
  td.num{color:var(--fg);text-align:right} td.mut{color:var(--mut)}
  th.num{text-align:right}
  .hrow-blk td{background:#140c0d}

  /* flow table */
  .ftools{display:flex;gap:6px;align-items:center;padding:7px 11px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
  .fbtn{background:var(--panel2);border:1px solid var(--bd);color:var(--mut);font:inherit;font-size:10.5px;
    padding:2px 8px;cursor:pointer}
  .fbtn:hover{color:var(--fg)}
  .fbtn.on{color:var(--bg);background:var(--cyn);border-color:var(--cyn)}
  .fsum{margin-left:auto;color:var(--dim);font-size:10.5px}
  .fwrap{max-height:420px;overflow:auto}
  .fwrap::-webkit-scrollbar,.log::-webkit-scrollbar{width:8px;height:8px}
  .fwrap::-webkit-scrollbar-track,.log::-webkit-scrollbar-track{background:var(--panel2)}
  .fwrap::-webkit-scrollbar-thumb,.log::-webkit-scrollbar-thumb{background:var(--bd)}
  .k-fwd{color:var(--grn)} .k-drop{color:var(--red)} .k-ctrl{color:var(--amb)} .k-oth{color:var(--mut)}
  .frow-drop td{background:#140c0d}
  td.match{color:var(--fg);max-width:520px;overflow:hidden;text-overflow:ellipsis}
  td.role{color:var(--dim);font-size:10.5px}
  td.act{color:var(--mut)}

  /* event log */
  .log{font-size:11px;max-height:300px;overflow-y:auto}
  .ln{display:flex;gap:8px;padding:4px 11px;border-bottom:1px solid var(--bd2);white-space:nowrap;overflow:hidden}
  .ln:hover{background:var(--panel2)}
  .ln .ts{color:var(--dim)}
  .ln .ev{width:54px;flex:none}
  .ev-alert{color:var(--red)} .ev-block{color:var(--amb)} .ev-recov{color:var(--grn)}
  .ln .ip{color:var(--fg);width:76px;flex:none}
  .ln .rl{color:var(--cyn);flex:none}
  .ln .ms{color:var(--mut)}
  .ln .dt{color:var(--dim);overflow:hidden;text-overflow:ellipsis}

  /* blocks */
  .blk{padding:7px 11px;border-bottom:1px solid var(--bd2);font-size:11.5px}
  .blk:last-child{border-bottom:0}
  .blk .ip{color:var(--red);font-weight:700}
  .blk .meta{color:var(--mut);font-size:10.5px;margin-top:2px}
  .blk .ttl{float:right;color:var(--amb);font-size:10.5px}
  .empty{padding:16px 11px;color:var(--dim);font-size:11px;text-align:center}

  /* rules */
  .rules{display:flex;flex-wrap:wrap;gap:6px 18px;padding:9px 11px;font-size:11px}
  .ru{color:var(--mut)}
  .ru b{color:var(--fg);font-weight:700}
  .ru i{color:var(--dim);font-style:normal}
  .ru.off{color:var(--dim);text-decoration:line-through}

  .foot{display:flex;gap:18px;flex-wrap:wrap;color:var(--dim);font-size:10.5px;margin-top:8px;padding:0 2px}

  /* full-traffic additions */
  .tw{overflow-x:auto}
  .cwrap{max-height:400px;overflow:auto}
  .cwrap::-webkit-scrollbar,.tw::-webkit-scrollbar{width:8px;height:8px}
  .cwrap::-webkit-scrollbar-track,.tw::-webkit-scrollbar-track{background:var(--panel2)}
  .cwrap::-webkit-scrollbar-thumb,.tw::-webkit-scrollbar-thumb{background:var(--bd)}
  .box>h2 .tabs{margin-left:auto;display:flex;gap:4px}
  .box>h2 .tabs .fbtn{text-transform:none;letter-spacing:0}
  .svc{display:grid;grid-template-columns:96px 1fr 92px;gap:8px;align-items:center;padding:4px 11px;border-bottom:1px solid var(--bd2);font-size:11px}
  .svc:last-child{border-bottom:0}
  .svc .nm{color:var(--fg);white-space:nowrap} .svc .nm i{color:var(--dim);font-style:normal}
  .svc .tr{height:7px;background:var(--panel2);border:1px solid var(--bd2)}
  .svc .tr span{display:block;height:100%;background:var(--cyn)}
  .svc .vl{text-align:right;color:var(--mut);white-space:nowrap}
  .ev-open{color:var(--grn)} .ev-close{color:var(--dim)}
  .crow-blk td{background:#140c0d}
  .t-ok{color:var(--grn);border-color:#204a2a}
  td.sv{color:var(--cyn)}
  td.hot{color:var(--amb)}
  .zero{color:var(--dim)}

  @media(max-width:1100px){.grid{grid-template-columns:1fr}.strip{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:620px){.strip{grid-template-columns:repeat(2,1fr)}.minis{grid-template-columns:1fr}.mini{border-right:0;border-bottom:1px solid var(--bd)}}
  @media(prefers-reduced-motion:reduce){.blink{animation:none}}
</style>
</head>
<body>
<div class="wrap">

  <div class="bar">
    <div class="l">
      <span class="logo">sdn-ids<b>//</b>monitor</span>
      <span class="tag">ryu openflow1.3 · ovs s1 · 13-host lan</span>
    </div>
    <div class="r">
      <span class="stat-ctrl"><span id="dot" class="dot"></span><span id="ctrlTxt">controller: ...</span></span>
      <span class="stat-ctrl"><span id="swDot" class="dot"></span><span id="swTxt">switch: ...</span></span>
      <span id="clock" class="clock">--:--:--</span>
    </div>
  </div>

  <div id="threat" class="threat"></div>

  <div class="strip">
    <div class="cell"><div class="k">alerts</div><div id="sAlerts" class="v">0</div><div class="s">since log clear</div></div>
    <div class="cell"><div class="k">blocked</div><div id="sBlocks" class="v vamb">0</div><div id="sBlocksS" class="s">no drop rules</div></div>
    <div class="cell"><div class="k">network packets/s</div><div id="sPps" class="v vcyn">0 <small>pps</small></div><div id="sPpsS" class="s">every port on the switch</div></div>
    <div class="cell"><div class="k">throughput</div><div id="sBps" class="v vvio">0 <small>B/s</small></div><div class="s">sent by all hosts</div></div>
    <div class="cell"><div class="k">live connections</div><div id="sFlows" class="v vgrn">0</div><div id="sFlowsS" class="s">allowed tcp flows</div></div>
    <div class="cell"><div class="k">dropped by ips</div><div id="sDrop" class="v vred">0 <small>pkts</small></div><div id="sRulesS" class="s">-</div></div>
  </div>

  <div class="grid">
    <div class="col">

      <div class="box">
        <h2>traffic — packets/s sent by every host<span class="note">live from switch port counters · dashed = packet_rate threshold</span>
          <span class="tabs"><button class="fbtn on" id="scLin">linear</button><button class="fbtn" id="scLog">log</button></span></h2>
        <div class="pad" style="padding-bottom:0"><svg id="chart" viewBox="0 0 1000 180" preserveAspectRatio="none"></svg></div>
        <div class="legend" id="legend"></div>
      </div>

      <div class="box">
        <h2>hosts — every node, every packet<span class="note">13 nodes · counters read from each switch port (allowed + dropped)</span></h2>
        <div class="tw"><table>
          <thead><tr><th style="width:44px">node</th><th>addr</th><th>role</th><th>port</th>
            <th class="num">sent/s</th><th class="num">recv/s</th><th class="num">pkts sent</th><th class="num">pkts recv</th>
            <th class="num">conns</th><th class="num">dropped</th><th style="width:88px">state</th></tr></thead>
          <tbody id="hosts"></tbody>
        </table></div>
      </div>

      <div class="box">
        <h2>live connections — who is talking to whom<span class="note" id="connNote">grouped by client → server:service</span></h2>
        <div class="cwrap tw"><table>
          <thead><tr><th>client</th><th>server</th><th>service</th><th class="num">conns</th>
            <th class="num">pkts/s</th><th class="num">packets</th><th class="num">bytes</th><th class="num">idle</th><th style="width:80px">status</th></tr></thead>
          <tbody id="conns"><tr><td colspan="9" class="empty">waiting for traffic...</td></tr></tbody>
        </table></div>
      </div>

      <div class="box">
        <h2>network totals — history<span class="note" id="seriesNote">from logs/flow_stats.csv</span></h2>
        <div class="minis">
          <div class="mini"><div class="mk"><span>packets / s</span><span id="mPpsMax"></span></div><div id="mPps" class="mv vcyn">0</div><svg id="sparkPps" viewBox="0 0 300 56" preserveAspectRatio="none"></svg></div>
          <div class="mini"><div class="mk"><span>bytes / s</span><span id="mBpsMax"></span></div><div id="mBps" class="mv vvio">0</div><svg id="sparkBps" viewBox="0 0 300 56" preserveAspectRatio="none"></svg></div>
          <div class="mini"><div class="mk"><span>active tcp flows</span><span id="mFlMax"></span></div><div id="mFl" class="mv vgrn">0</div><svg id="sparkFl" viewBox="0 0 300 56" preserveAspectRatio="none"></svg></div>
        </div>
      </div>

    </div>

    <div class="col">
      <div class="box">
        <h2>active blocks<span class="note">ips drops in ovs</span></h2>
        <div id="blocks"><div class="empty">no active blocks — traffic nominal</div></div>
      </div>
      <div class="box">
        <h2>traffic by service<span class="note">packets/s per destination port</span></h2>
        <div id="svcs"><div class="empty">no traffic yet</div></div>
      </div>
      <div class="box grow">
        <h2>activity feed<span class="note" id="evCount">0</span>
          <span class="tabs"><button class="fbtn on" data-tab="all">all traffic</button><button class="fbtn" data-tab="ids">ids events</button></span></h2>
        <div class="log" id="log"><div class="empty">waiting for events...</div></div>
      </div>
    </div>
  </div>

  <div class="box full">
    <h2>ovs flow table — s1<span class="note">every rule installed in the switch, highest priority first</span></h2>
    <div class="ftools">
      <button class="fbtn on" data-f="all">all <span id="cAll">0</span></button>
      <button class="fbtn" data-f="OUTPUT">forward <span id="cFwd">0</span></button>
      <button class="fbtn" data-f="DROP">drop <span id="cDrop">0</span></button>
      <button class="fbtn" data-f="CONTROLLER">to controller <span id="cCtrl">0</span></button>
      <span class="fsum" id="fsum"></span>
    </div>
    <div class="fwrap">
      <table>
        <thead><tr><th style="width:52px" class="num">prio</th><th style="width:64px">type</th><th style="width:150px">role</th>
          <th>match</th><th>actions</th><th class="num">packets</th><th class="num">bytes</th></tr></thead>
        <tbody id="flows"><tr><td colspan="7" class="empty">reading flow table...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="box full">
    <h2>detection rules<span class="note" id="rulesNote">controller/ids_rules.json</span></h2>
    <div class="rules" id="rules"></div>
  </div>

  <div class="foot">
    <span>updated <span id="upd">--</span></span>
    <span>telemetry age <span id="age">--</span>s</span>
    <span id="err" style="color:var(--amb)"></span>
  </div>

</div>

<script>
const HOSTS=[
 {n:"h1",ip:"10.0.0.1", role:"attacker",   kind:"att"},
 {n:"h2",ip:"10.0.0.2", role:"app server", kind:"srv"},
 {n:"srv2",ip:"10.0.0.10",role:"file server",kind:"srv"},
 {n:"srv3",ip:"10.0.0.11",role:"database",  kind:"srv"},
 {n:"srv4",ip:"10.0.0.12",role:"mail/dns",  kind:"srv"},
 {n:"h3",ip:"10.0.0.3", role:"heartbeat",  kind:"cli"},
 {n:"h4",ip:"10.0.0.4", role:"workstation",kind:"cli"},
 {n:"h5",ip:"10.0.0.5", role:"workstation",kind:"cli"},
 {n:"h6",ip:"10.0.0.6", role:"workstation",kind:"cli"},
 {n:"h7",ip:"10.0.0.7", role:"workstation",kind:"cli"},
 {n:"h8",ip:"10.0.0.8", role:"workstation",kind:"cli"},
 {n:"h9",ip:"10.0.0.9", role:"workstation",kind:"cli"},
 {n:"h10",ip:"10.0.0.13",role:"attacker-2", kind:"att"},
];
const COL=["#f0504a","#3fb950","#3fb6c2","#4c93f0","#9a7cf0","#d6a426","#e07a5f","#5fd0c0","#c79bf0","#8fd18f","#e0c060","#70a0e0","#d08080"];
const RLAB={conn_flood:"conn_flood",port_scan:"port_scan",invalid_flags:"invalid_flags",
  concurrent_flows:"concurrent_flows",packet_rate:"packet_rate",multi_ip_spoof:"multi_ip_spoof",port_flood:"port_flood"};
const RUNIT={conn_flood:"conns",port_scan:"ports",invalid_flags:"pkts",concurrent_flows:"flows",packet_rate:"pps",multi_ip_spoof:"ips",port_flood:"syns"};
const PRIO_ROLE={200:"ips: port quarantine",100:"ips: block (ip / mac)",20:"tcp connection (fast path)",5:"new tcp -> ids inspect",1:"l2 forwarding",0:"table-miss -> controller"};
const BYIP={}; HOSTS.forEach(h=>BYIP[h.ip]=h);
let hist={};          // ip -> [{t,pps}]  (per-source, live)
let flowFilter="all";
let lastFlows=[], portToHost={};
let rulesCfg={};      // from /api/rules
let logScale=false, logTab="all";
const SVC={22:"ssh",80:"http",443:"https",5000:"app",21:"ftp",445:"smb",8080:"http-alt",3306:"mysql",5432:"postgres",25:"smtp",53:"dns",143:"imap"};
let prevPort=null, prevPortT=0, portRate={};     // switch port counters -> per-host rates
let prevFlow=null, prevFlowT=0;                  // 5-tuple flow packet counters (for pkts/s + open/close)
let feed=[], seenEv=new Set(), lastEv=[];        // "all traffic" activity feed
let connGroups=[], svcGroups=[];
let qHosts=new Set();   // hosts whose whole switch port is quarantined (spoof / port_flood)
let dropTrack={}, dropBank=0;   // dropped-by-IPS bookkeeping: per blocked host, plus total from earlier (released) blocks
function who(ip,b){     // a port quarantine is keyed by the (possibly fake) source IP: show the real host
  if(b&&b.action_target==="port"){const h=portToHost[b.in_port]; return (h||("port "+b.in_port))+" [src "+ip+"]";}
  return hn(ip)+" "+ip;
}

function clk(){document.getElementById("clock").textContent=new Date().toLocaleTimeString("en-GB");}
setInterval(clk,1000);clk();
function ci(n){return Number(n||0).toLocaleString("en-US");}
function fb(b){b=Number(b||0); if(b<1024)return Math.round(b)+" B"; if(b<1048576)return (b/1024).toFixed(1)+" KB"; if(b<1073741824)return (b/1048576).toFixed(1)+" MB"; return (b/1073741824).toFixed(2)+" GB";}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function hn(ip){return BYIP[ip]?BYIP[ip].n:ip;}

document.querySelectorAll(".fbtn[data-f]").forEach(b=>b.addEventListener("click",()=>{
  flowFilter=b.dataset.f;
  document.querySelectorAll(".fbtn[data-f]").forEach(x=>x.classList.toggle("on",x===b));
  flowTable(lastFlows);
}));
document.querySelectorAll(".fbtn[data-tab]").forEach(b=>b.addEventListener("click",()=>{
  logTab=b.dataset.tab;
  document.querySelectorAll(".fbtn[data-tab]").forEach(x=>x.classList.toggle("on",x===b));
  drawLog();
}));
function setScale(v){
  logScale=v;
  document.getElementById("scLin").classList.toggle("on",!v);
  document.getElementById("scLog").classList.toggle("on",v);
  chart();
}
document.getElementById("scLin").addEventListener("click",()=>setScale(false));
document.getElementById("scLog").addEventListener("click",()=>setScale(true));

async function loadRules(){
  try{ const r=await (await fetch("/api/rules",{cache:"no-store"})).json(); if(r&&r.rules) rulesCfg=r.rules; }catch(e){}
}

async function tick(){
  let s;
  try{ s=await (await fetch("/api/telemetry",{cache:"no-store"})).json(); }
  catch(e){ setDot("dot","ctrlTxt",false,"controller: unreachable"); return; }
  render(s);
}
function setDot(dotId,txtId,up,txt){
  const d=document.getElementById(dotId), t=document.getElementById(txtId);
  d.className="dot "+(up?"on blink":"off");
  t.textContent=txt; t.style.color=up?"var(--grn)":"var(--red)";
}

function render(s){
  const now=s.generated_at||Date.now()/1000;
  const st=(s.status&&s.status.stats)||{};
  const blocked=(s.status&&s.status.blocked)||{};
  const bips=Object.keys(blocked);
  const cfg=Object.assign({},rulesCfg,s.status||{});
  const flows=s.flows||[];
  lastFlows=flows;
  portToHost={}; Object.entries(s.port_map||{}).forEach(([h,p])=>{if(p!=null)portToHost[p]=h;});
  qHosts=new Set(); (s.quarantined_ports||[]).forEach(p=>{if(portToHost[p])qHosts.add(portToHost[p]);});

  setDot("dot","ctrlTxt",!!s.controller_online,"controller: "+(s.controller_online?"up":"down"));
  setDot("swDot","swTxt",!!s.switch_online,"switch s1: "+(s.switch_online?"connected":"down"));

  document.getElementById("upd").textContent=new Date(now*1000).toLocaleTimeString("en-GB");
  document.getElementById("age").textContent=(s.status_age_seconds!=null)?s.status_age_seconds:"--";
  document.getElementById("err").textContent=s.telemetry_error||s.ovs_error||"";

  // threat line
  const th=document.getElementById("threat");
  if(bips.length){
    th.classList.add("show");
    th.innerHTML="! INTRUSION — IPS engaged :: "+bips.map(ip=>{
      const b=blocked[ip]||{}, r=(b.rules||[b.rule]).filter(Boolean).map(x=>RLAB[x]||x).join(",");
      return "<b>"+who(ip,b)+"</b> &rarr; "+r+(b.action_target==="port"?" (port "+b.in_port+" quarantined)":"");
    }).join("   ");
  } else th.classList.remove("show");

  // ---- true per-host rates from the switch's own port counters ----
  ratesFrom(s.port_stats||{},now);
  const portMap=s.port_map||{}, ps=s.port_stats||{};
  const rate=h=>{const p=portMap[h.n]; return (p!=null&&portRate[p])?portRate[p]:null;};
  const havePorts=Object.keys(portRate).length>0;

  // ---- flows -> grouped live connections (+ open/close feed) ----
  const cg=buildConns(flows,now);
  let dropPk=0, dropRules=0; const dropBySrc={};
  flows.forEach(f=>{
    if(f.action_kind!=="DROP")return;
    dropPk+=f.packets||0; dropRules++;
    const m=/nw_src=([\d.]+)/.exec(f.match), p=/in_port=(\d+)/.exec(f.match);
    let ip=null;
    if(m) ip=m[1]; else if(p&&portToHost[p[1]]){const hh=HOSTS.find(x=>x.n===portToHost[p[1]]); if(hh) ip=hh.ip;}
    if(ip) dropBySrc[ip]=(dropBySrc[ip]||0)+(f.packets||0);
  });
  // The per-rule OVS counter only shows packets that hit the rule while it exists, and it vanishes when the
  // rule is removed (timeout / sdn-unblock). So also count what the blocked host's own switch port keeps
  // receiving after the block (every such packet is dropped), and keep the total after the block is released.
  const blockedHosts=new Set(qHosts);
  bips.forEach(ip=>{const hh=HOSTS.find(x=>x.ip===ip); if(hh)blockedHosts.add(hh.n);});
  const _pm=s.port_map||{}, _ps=s.port_stats||{};
  let dropExtra=0;
  HOSTS.forEach(h=>{
    const p=_pm[h.n], rx=(p!=null&&_ps[p])?_ps[p].rx_pkts:null, live=dropBySrc[h.ip]||0;
    if(blockedHosts.has(h.n)){
      const tr=dropTrack[h.n]||(dropTrack[h.n]={base:rx,last:0});
      const est=(rx!=null&&tr.base!=null)?Math.max(0,rx-tr.base):0;
      tr.last=Math.max(tr.last,est,live);
      dropExtra+=Math.max(0,tr.last-live);
      dropBySrc[h.ip]=tr.last;
    } else if(dropTrack[h.n]){ dropBank+=dropTrack[h.n].last; delete dropTrack[h.n]; }
  });
  dropPk+=dropExtra+dropBank;

  // ---- stat strip ----
  const ev=s.events||[];
  const nAlert=ev.filter(e=>e.event==="ALERT").length;
  const ctrlPps=Object.values(st).reduce((a,x)=>a+(x.pps||0),0);
  const interval=(cfg.stats_interval||3);
  const ser=s.series||[];
  let netPps=ctrlPps, netBps=ser.length?ser[ser.length-1].bytes_per_sec:Object.values(st).reduce((a,x)=>a+(x.bytes||0),0)/interval;
  if(havePorts){netPps=0;netBps=0; HOSTS.forEach(h=>{const r=rate(h); if(r){netPps+=r.sent; netBps+=r.sentB;}});}
  const kc={OUTPUT:0,DROP:0,CONTROLLER:0,OTHER:0}; flows.forEach(f=>kc[f.action_kind]=(kc[f.action_kind]||0)+1);
  document.getElementById("sAlerts").textContent=ci(nAlert);
  document.getElementById("sBlocks").textContent=bips.length;
  document.getElementById("sBlocksS").textContent=bips.length?bips.map(ip=>{const b=blocked[ip]; return (b&&b.action_target==="port")?(portToHost[b.in_port]||("port "+b.in_port)):hn(ip);}).join(", "):"no drop rules";
  document.getElementById("sPps").innerHTML=ci(Math.round(netPps))+' <small>pps</small>';
  document.getElementById("sPpsS").textContent=havePorts?"sum over all 13 switch ports":"from controller polls (waiting for port counters)";
  document.getElementById("sBps").innerHTML=fb(netBps)+'<small>/s</small>';
  document.getElementById("sFlows").textContent=ci(cg.total);
  document.getElementById("sFlowsS").textContent=cg.groups+" client→service pairs";
  document.getElementById("sDrop").innerHTML=ci(dropPk)+' <small>pkts</small>';
  document.getElementById("sRulesS").textContent=dropRules+" drop rules · "+flows.length+" rules total · kept after unblock";

  // ---- per-host live history (chart) ----
  HOSTS.forEach(h=>{
    const r=rate(h); let v=null;
    if(r) v=r.sent; else if(st[h.ip]) v=st[h.ip].pps||0;
    if(v==null) return;
    const arr=(hist[h.ip]=hist[h.ip]||[]), last=arr[arr.length-1];
    if(!last||Math.abs(last.t-now)>0.4){arr.push({t:now,pps:v}); if(arr.length>90)arr.shift();}
  });
  for(const ip in hist){const h=hist[ip]; if(h.length&&now-h[h.length-1].t>30)delete hist[ip];}
  chart();
  minis(ser);

  hostsTable(rate,st,blocked,dropBySrc,ps,portMap,cg.byHost);
  connsTable(cg,blocked,dropBySrc);
  svcBars(cg);
  blocksList(blocked,now,cfg);
  lastEv=ev; ingestEvents(ev); drawLog();
  flowTable(flows);
  rulesLine(cfg);
}

/* ---- helpers for the full-traffic view ---- */
function rt(v){v=Number(v||0); if(v<0.05)return '<span class="zero">0</span>'; if(v<10)return v.toFixed(1); return ci(Math.round(v));}

function ratesFrom(ps,now){
  const snap={}; for(const p in ps) snap[p]=ps[p];
  if(prevPort && now-prevPortT>0.3){
    const dt=now-prevPortT, out={};
    for(const p in snap){
      const a=snap[p], b=prevPort[p]; if(!b) continue;
      const d=(x,y)=>Math.max(0,(x||0)-(y||0))/dt;     // counter reset -> 0, never negative
      out[p]={sent:d(a.rx_pkts,b.rx_pkts), recv:d(a.tx_pkts,b.tx_pkts), sentB:d(a.rx_bytes,b.rx_bytes), recvB:d(a.tx_bytes,b.tx_bytes)};
    }
    portRate=out; prevPort=snap; prevPortT=now;
  } else if(!prevPort){ prevPort=snap; prevPortT=now; }
}

function kvOf(m){const kv={}; (m||"").split(",").forEach(p=>{p=p.trim(); const i=p.indexOf("="); if(i>0) kv[p.slice(0,i)]=p.slice(i+1);}); return kv;}

function buildConns(flows,now){
  /* priority-20 rules are the per-connection fast path (one per direction).
     Normalise each to client -> server:service, merge both directions, then group. */
  const groups={}, keys={}, flowPk={};
  const fresh=!prevFlow || now-prevFlowT>0.3;
  const dt=prevFlow?Math.max(0.3,now-prevFlowT):1;
  flows.forEach(f=>{
    if(f.priority!==20||f.action_kind!=="OUTPUT") return;
    const k=kvOf(f.match); if(!k.nw_src||!k.tp_src||!k.tp_dst) return;
    const sp=+k.tp_src, dp=+k.tp_dst;
    const cIsSrc=(SVC[dp]!==undefined)?true:((SVC[sp]!==undefined)?false:(sp>=dp));
    const c=cIsSrc?k.nw_src:k.nw_dst, cp=cIsSrc?sp:dp, sv=cIsSrc?k.nw_dst:k.nw_src, svp=cIsSrc?dp:sp;
    const key=c+":"+cp+">"+sv+":"+svp, gid=c+"|"+sv+"|"+svp;
    const g=groups[gid]||(groups[gid]={c:c,s:sv,svp:svp,conns:0,pk:0,by:0,rate:0,idle:1e9});
    if(!keys[key]){keys[key]=gid; g.conns++;}
    g.pk+=f.packets||0; g.by+=f.bytes||0; g.idle=Math.min(g.idle,f.idle||0);
    flowPk[f.match]=f.packets||0;
    if(prevFlow){
      const prev=prevFlow[f.match];
      const delta=(prev===undefined)?(f.packets||0):Math.max(0,(f.packets||0)-prev);
      g.rate+=delta/dt;
    }
  });
  if(fresh){
    if(prevFlow){
      const pk=prevFlow.__keys||{}, opens={}, closes={};
      for(const k in keys){ if(!pk[k]) opens[keys[k]]=(opens[keys[k]]||0)+1; }
      for(const k in pk){ if(!keys[k]) closes[pk[k]]=(closes[pk[k]]||0)+1; }
      const push=(gid,n,ev)=>{const [c,sv,svp]=gid.split("|");
        feed.push({ts:now*1000,ev:ev,a:hn(c),b:"→ "+hn(sv)+":"+(SVC[svp]||svp),c:n>1?("×"+n):"",d:ev==="OPEN"?(n+" new tcp connection"+(n>1?"s":"")):(n+" connection"+(n>1?"s":"")+" ended (idle)")});};
      for(const g in opens) push(g,opens[g],"OPEN");
      for(const g in closes) push(g,closes[g],"CLOSE");
    }
    flowPk.__keys=keys; prevFlow=flowPk; prevFlowT=now;
  }
  const list=Object.values(groups).sort((a,b)=>(b.rate-a.rate)||(b.pk-a.pk));
  const byHost={}, bySvc={}; let total=0;
  list.forEach(g=>{
    total+=g.conns; byHost[g.c]=(byHost[g.c]||0)+g.conns; byHost[g.s]=(byHost[g.s]||0)+g.conns;
    const x=bySvc[g.svp]||(bySvc[g.svp]={svp:g.svp,rate:0,pk:0,conns:0}); x.rate+=g.rate; x.pk+=g.pk; x.conns+=g.conns;
  });
  connGroups=list; svcGroups=Object.values(bySvc).sort((a,b)=>(b.rate-a.rate)||(b.pk-a.pk));
  return {list:list,svc:svcGroups,total:total,groups:list.length,byHost:byHost};
}

function connsTable(cg,blocked,dropBySrc){
  const body=document.getElementById("conns"), rows=[];
  const thr=(rulesCfg.packet_rate&&rulesCfg.packet_rate.threshold)||3000;
  const blk=new Set(Object.keys(blocked)); Object.keys(dropBySrc).forEach(ip=>blk.add(ip)); HOSTS.forEach(h=>{if(qHosts.has(h.n))blk.add(h.ip);});
  blk.forEach(ip=>{
    rows.push(`<tr class="crow-blk"><td>${hn(ip)} <span class="zero">${ip}</span></td><td class="mut">* (everything)</td><td class="sv">any</td>
      <td class="num">-</td><td class="num">-</td><td class="num">${ci(dropBySrc[ip]||0)} <span class="zero">dropped</span></td><td class="num">-</td><td class="num">-</td>
      <td><span class="t-state st-blk">BLOCKED</span></td></tr>`);
  });
  cg.list.slice(0,60).forEach(g=>{
    const isB=blk.has(g.c);
    rows.push(`<tr class="${isB?'crow-blk':''}"><td>${hn(g.c)}</td><td>${hn(g.s)}</td><td class="sv">${g.svp} <span class="zero">${SVC[g.svp]||""}</span></td>
      <td class="num">${ci(g.conns)}</td><td class="num ${g.rate>thr/3?'hot':''}">${rt(g.rate)}</td><td class="num">${ci(g.pk)}</td><td class="num">${fb(g.by)}</td>
      <td class="num">${g.idle>=1e9?"-":g.idle+"s"}</td><td><span class="t-state ${isB?'st-blk':'t-ok'}">${isB?"BLOCKED":"ALLOWED"}</span></td></tr>`);
  });
  document.getElementById("connNote").textContent=cg.total+" connections · "+cg.groups+" client→service pairs"+(cg.list.length>60?" · top 60 shown":"");
  body.innerHTML=rows.length?rows.join(""):'<tr><td colspan="9" class="empty">no connections in the flow table yet</td></tr>';
}

function svcBars(cg){
  const el=document.getElementById("svcs"), list=cg.svc.slice(0,10);
  if(!list.length){el.innerHTML='<div class="empty">no traffic yet</div>';return;}
  const useRate=list.some(x=>x.rate>0.05);
  const max=Math.max(1,...list.map(x=>useRate?x.rate:x.pk));
  el.innerHTML=list.map(x=>{
    const v=useRate?x.rate:x.pk;
    return `<div class="svc"><span class="nm">${x.svp} <i>${SVC[x.svp]||""}</i></span>
      <span class="tr"><span style="width:${Math.max(1,Math.round(100*v/max))}%"></span></span>
      <span class="vl">${useRate?rt(x.rate)+" pps":ci(x.pk)+" pkts"} · ${x.conns}c</span></div>`;
  }).join("");
}

function ingestEvents(ev){
  ev.forEach(e=>{
    const rl=(e.rules||[e.rule]).filter(Boolean).join(",");
    const key=[e.ts||e.time||"",e.event||"",e.ip||"",rl,e.detail||""].join("|");
    if(seenEv.has(key)) return; seenEv.add(key);
    const ty=e.event||"", lab=ty==="BLOCK_INSTALLED"?"BLOCK":(ty==="UNBLOCKED"?"RECOVER":ty);
    const ms=(e.response_ms!=null)?e.response_ms+"ms":(e.detect_latency_ms!=null?e.detect_latency_ms+"ms":"");
    feed.push({ts:e.ts?e.ts*1000:Date.now(),ev:lab,a:e.ip||"-",b:RLAB[rl]||rl||"-",c:ms,d:e.detail||e.mitigation_action||""});
  });
  feed.sort((x,y)=>y.ts-x.ts);
  if(feed.length>400) feed.length=400;
}
const FEEDCLS={OPEN:"open",CLOSE:"close",ALERT:"alert",BLOCK:"block",RECOVER:"recov"};
function drawLog(){
  if(logTab==="ids"){ eventLog(lastEv); return; }
  const el=document.getElementById("log");
  document.getElementById("evCount").textContent=feed.length+" entries";
  if(!feed.length){el.innerHTML='<div class="empty">waiting for traffic...</div>';return;}
  el.innerHTML=feed.slice(0,120).map(f=>{
    const ts=new Date(f.ts).toLocaleTimeString("en-GB");
    return `<div class="ln" title="${esc(f.d)}"><span class="ts">${ts}</span><span class="ev ev-${FEEDCLS[f.ev]||'alert'}">${f.ev}</span>`+
      `<span class="ip">${esc(f.a)}</span><span class="rl">${esc(f.b)}</span><span class="ms">${esc(f.c)}</span><span class="dt">${esc(f.d)}</span></div>`;
  }).join("");
}

function chart(){
  const svg=document.getElementById("chart"), lg=document.getElementById("legend");
  const W=1000,H=180,L=40,R=6,T=8,B=18, pw=W-L-R, ph=H-T-B;
  const ips=Object.keys(hist).sort((a,b)=>HOSTS.findIndex(h=>h.ip===a)-HOSTS.findIndex(h=>h.ip===b));
  let max=100; ips.forEach(ip=>hist[ip].forEach(p=>{if(p.pps>max)max=p.pps;}));
  for(const v of [100,200,500,1000,2000,3000,5000,10000,20000,50000,100000,200000,500000,1000000]){if(v>=max){max=v;break;}}
  const N=90, xs=pw/(N-1);
  let o="";
  /* linear or log10(1+x) vertical scale; log keeps quiet legit hosts visible next to a 100k pps flood */
  const f=v=>logScale?Math.log10(1+v):v, fm=f(max);
  for(let i=0;i<=4;i++){const y=T+ph*i/4, fv=fm*(1-i/4), v=Math.round(logScale?Math.pow(10,fv)-1:fv);
    o+=`<line class="cgrid" x1="${L}" y1="${y}" x2="${W-R}" y2="${y}"/><text class="clab" x="${L-5}" y="${y+3}" text-anchor="end">${ci(v)}</text>`;}
  const thr=(rulesCfg.packet_rate&&rulesCfg.packet_rate.threshold)||3000;
  if(thr<=max){const y=T+ph*(1-f(thr)/fm); o+=`<line class="cthr" x1="${L}" y1="${y}" x2="${W-R}" y2="${y}"/>`;}
  o+=`<text class="clab" x="${L}" y="${H-5}">last ${N} polls</text><text class="clab" x="${W-R}" y="${H-5}" text-anchor="end">now</text>`;
  const items=[];
  ips.forEach(ip=>{
    const idx=Math.max(0,HOSTS.findIndex(h=>h.ip===ip)), c=COL[idx%COL.length], h=hist[ip], used=Math.min(h.length,N), sx=L+(N-used)*xs;
    let pts="";
    for(let i=0;i<used;i++){const p=h[h.length-used+i];pts+=`${(sx+i*xs).toFixed(1)},${(T+ph*(1-f(p.pps)/fm)).toFixed(1)} `;}
    const att=BYIP[ip]&&BYIP[ip].kind==="att";
    o+=`<polyline fill="none" stroke="${c}" stroke-width="${att?2:1.4}" points="${pts}"/>`;
    const lp=h.length?Math.round(h[h.length-1].pps):0;
    items.push(`<span class="lg"><span class="sw" style="background:${c}"></span>${hn(ip)} ${ci(lp)}</span>`);
  });
  svg.innerHTML=o;
  lg.innerHTML=items.length?items.join(""):'<span class="lg" style="color:var(--dim)">no traffic yet</span>';
}

function spark(id,vals,color){
  const svg=document.getElementById(id), W=300,H=56,T=4,B=4;
  if(!vals.length){svg.innerHTML=`<text class="clab" x="4" y="30">no samples yet</text>`;return 0;}
  const max=Math.max(1,...vals), n=vals.length, xs=n>1?W/(n-1):0;
  let pts="", area=`0,${H-B} `;
  vals.forEach((v,i)=>{const x=(i*xs).toFixed(1), y=(T+(H-T-B)*(1-v/max)).toFixed(1); pts+=`${x},${y} `; area+=`${x},${y} `;});
  area+=`${((n-1)*xs).toFixed(1)},${H-B}`;
  svg.innerHTML=`<line class="cgrid" x1="0" y1="${H-B}" x2="${W}" y2="${H-B}"/>`+
    `<polygon points="${area}" fill="${color}" opacity=".12"/>`+
    `<polyline fill="none" stroke="${color}" stroke-width="1.5" points="${pts}"/>`;
  return max;
}
function minis(ser){
  const p=ser.map(x=>x.packets_per_sec||0), b=ser.map(x=>x.bytes_per_sec||0), f=ser.map(x=>x.active_flows||0);
  const mp=spark("sparkPps",p,"#3fb6c2"), mb=spark("sparkBps",b,"#9a7cf0"), mf=spark("sparkFl",f,"#3fb950");
  const last=a=>a.length?a[a.length-1]:0;
  document.getElementById("mPps").textContent=ci(Math.round(last(p)));
  document.getElementById("mBps").textContent=fb(last(b))+"/s";
  document.getElementById("mFl").textContent=ci(Math.round(last(f)));
  document.getElementById("mPpsMax").textContent=ser.length?"peak "+ci(Math.round(mp)):"";
  document.getElementById("mBpsMax").textContent=ser.length?"peak "+fb(mb)+"/s":"";
  document.getElementById("mFlMax").textContent=ser.length?"peak "+ci(Math.round(mf)):"";
  document.getElementById("seriesNote").textContent=ser.length?(ser.length+" polls from logs/flow_stats.csv"):"waiting for flow_stats.csv";
}

function hostsTable(rate,st,blocked,dropBySrc,ps,portMap,connsByHost){
  document.getElementById("hosts").innerHTML=HOSTS.map(h=>{
    const r=rate(h)||{sent:(st[h.ip]||{}).pps||0,recv:0};
    const p=portMap[h.n], c=(p!=null&&ps[p])?ps[p]:null;
    const blk=!!blocked[h.ip]||qHosts.has(h.n), act=(r.sent+r.recv)>0.5||((st[h.ip]||{}).flows||0)>0;
    let tag,cls;
    if(blk){tag="BLOCKED";cls="st-blk";}
    else if(h.kind==="att"){tag=act?"ACTIVE":"attacker";cls="st-att";}
    else if(h.kind==="srv"){tag=act?"SERVING":"PROT";cls="st-prot";}
    else if(act){tag="UP";cls="st-up";}
    else {tag="idle";cls="st-idle";}
    const dr=dropBySrc[h.ip]||0;
    return `<tr class="${blk?'hrow-blk':''}">
      <td>${h.n}</td><td class="mut">${h.ip}</td><td class="mut">${h.role}</td><td class="mut">${p!=null?p:"-"}</td>
      <td class="num">${rt(r.sent)}</td><td class="num">${rt(r.recv)}</td>
      <td class="num">${c?ci(c.rx_pkts):"-"}</td><td class="num">${c?ci(c.tx_pkts):"-"}</td>
      <td class="num">${ci(connsByHost[h.ip]||0)}</td><td class="num ${dr?'vred':''}">${dr?ci(dr):'<span class="zero">0</span>'}</td>
      <td><span class="t-state ${cls}">${tag}</span></td></tr>`;
  }).join("");
}

function fmtMatch(m){
  if(!m||m==="all packets") return "* (any packet)";
  const kv={}, flags=[];
  m.split(",").forEach(p=>{p=p.trim(); if(!p)return; const i=p.indexOf("="); if(i>0) kv[p.slice(0,i)]=p.slice(i+1); else flags.push(p);});
  const proto=flags.find(f=>["tcp","udp","icmp","arp","ip","ipv6","tcp6","udp6"].includes(f))||"";
  if(kv.nw_src||kv.nw_dst){
    const s=kv.nw_src?(hn(kv.nw_src)+(kv.tp_src?":"+kv.tp_src:"")):"*";
    const d=kv.nw_dst?(hn(kv.nw_dst)+(kv.tp_dst?":"+kv.tp_dst:"")):"*";
    return `${proto||"ip"}  ${s} → ${d}`;
  }
  const parts=[];
  if(proto) parts.push(proto);
  if(kv.in_port){const ph=portToHost[kv.in_port]; parts.push("in_port="+kv.in_port+(ph?" ("+ph+")":""));}
  if(kv.dl_src) parts.push("src_mac="+kv.dl_src);
  if(kv.dl_dst) parts.push("dst_mac="+kv.dl_dst);
  return parts.length?parts.join("  "):m;
}
function fmtActions(a,kind){
  if(kind==="DROP") return "drop";
  return a.replace(/output:(\d+)/gi,(x,p)=>"output:"+p+(portToHost[p]?" ("+portToHost[p]+")":""))
          .replace(/CONTROLLER:65535/,"CONTROLLER");
}
function flowTable(flows){
  const kc={OUTPUT:0,DROP:0,CONTROLLER:0,OTHER:0}; let pk=0, by=0;
  flows.forEach(f=>{kc[f.action_kind]=(kc[f.action_kind]||0)+1; pk+=f.packets||0; by+=f.bytes||0;});
  document.getElementById("cAll").textContent=flows.length;
  document.getElementById("cFwd").textContent=kc.OUTPUT;
  document.getElementById("cDrop").textContent=kc.DROP;
  document.getElementById("cCtrl").textContent=kc.CONTROLLER;
  document.getElementById("fsum").textContent=ci(pk)+" packets · "+fb(by)+" matched in total";
  const list=flowFilter==="all"?flows:flows.filter(f=>f.action_kind===flowFilter);
  const body=document.getElementById("flows");
  if(!list.length){body.innerHTML=`<tr><td colspan="7" class="empty">${flows.length?"no rules of this type":"flow table not readable (is the switch up?)"}</td></tr>`;return;}
  const KN={OUTPUT:["FWD","k-fwd"],DROP:["DROP","k-drop"],CONTROLLER:["CTRL","k-ctrl"],OTHER:["OTHER","k-oth"]};
  body.innerHTML=list.slice(0,400).map(f=>{
    const [kl,kcls]=KN[f.action_kind]||KN.OTHER;
    return `<tr class="${f.action_kind==='DROP'?'frow-drop':''}">
      <td class="num">${f.priority}</td><td class="${kcls}">${kl}</td><td class="role">${PRIO_ROLE[f.priority]||""}</td>
      <td class="match" title="${esc(f.match)}">${esc(fmtMatch(f.match))}</td>
      <td class="act" title="${esc(f.actions)}">${esc(fmtActions(f.actions,f.action_kind))}</td>
      <td class="num">${ci(f.packets)}</td><td class="num">${fb(f.bytes)}</td></tr>`;
  }).join("")+(list.length>400?`<tr><td colspan="7" class="empty">+${list.length-400} more rules not shown</td></tr>`:"");
}

function blocksList(blocked,now,cfg){
  const el=document.getElementById("blocks"), ips=Object.keys(blocked);
  if(!ips.length){el.innerHTML='<div class="empty">no active blocks — traffic nominal</div>';return;}
  const idle=(cfg&&cfg.block_idle_timeout)||30;
  el.innerHTML=ips.map(ip=>{
    const b=blocked[ip], r=(b.rules||[b.rule]).filter(Boolean).map(x=>RLAB[x]||x).join(","),
      ttl=Math.max(0,Math.round(idle-(now-(b.since||0)))),
      act=b.action_target==="port"?("prio-200 in_port="+b.in_port+" drop"):"prio-100 ipv4_src drop";
    return `<div class="blk"><span class="ttl">idle ttl ~${ttl}s</span><span class="ip">${who(ip,b)}</span>
      <div class="meta">${r} :: ${act}</div>${b.detail?`<div class="meta">${esc(b.detail)}</div>`:""}</div>`;
  }).join("");
}

function eventLog(ev){
  document.getElementById("evCount").textContent=ev.length+" events";
  const el=document.getElementById("log");
  if(!ev.length){el.innerHTML='<div class="empty">waiting for events...</div>';return;}
  /* backend returns newest-first: show the newest 80 at the top */
  el.innerHTML=ev.slice(0,80).map(e=>{
    const ty=e.event||"", kind=ty==="ALERT"?"alert":(ty==="BLOCK_INSTALLED"?"block":(ty==="UNBLOCKED"?"recov":"alert"));
    const lab=ty==="BLOCK_INSTALLED"?"BLOCK":(ty==="UNBLOCKED"?"RECOVER":ty);
    const ts=e.time||(e.ts?new Date(e.ts*1000).toLocaleTimeString("en-GB"):"--");
    const ip=e.ip||"-", rl=(e.rules||[e.rule]).filter(Boolean).map(x=>RLAB[x]||x).join(",");
    const ms=(e.response_ms!=null)?e.response_ms+"ms":(e.detect_latency_ms!=null?e.detect_latency_ms+"ms":"");
    const dt=e.detail||e.mitigation_action||"";
    return `<div class="ln" title="${esc(dt)}"><span class="ts">${ts}</span><span class="ev ev-${kind}">${lab}</span>`+
      `<span class="ip">${ip}</span><span class="rl">${rl||"-"}</span><span class="ms">${ms}</span><span class="dt">${esc(dt)}</span></div>`;
  }).join("");
}

function rulesLine(cfg){
  const names=["conn_flood","port_scan","invalid_flags","concurrent_flows","packet_rate","multi_ip_spoof","port_flood"];
  document.getElementById("rules").innerHTML=names.map(n=>{
    const r=cfg[n]||{}, on=(r.enabled!==false), thr=(r.threshold!=null?r.threshold:"?");
    const win=r.window!=null?` <i>/ ${r.window}s</i>`:"";
    return `<span class="ru ${on?'':'off'}">${RLAB[n]}=<b>${thr}</b> <i>${RUNIT[n]}</i>${win}</span>`;
  }).join("");
  const prot=(cfg.protected_hosts||[]).length;
  document.getElementById("rulesNote").textContent=
    "block idle timeout "+(cfg.block_idle_timeout||30)+"s · stats poll "+(cfg.stats_interval||3)+"s"+(prot?" · "+prot+" whitelisted hosts":"");
}

loadRules().then(tick); setInterval(tick,1500); setInterval(loadRules,15000);
</script>
</body>
</html>
'''



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
        dur = re.search(r"(?:^|,)\s*duration=([\d.]+)s", left)
        idle = re.search(r"(?:^|,)\s*idle_age=(\d+)", left)
        if not p_match:
            continue
        match_parts = []
        for part in left.split(","):
            part = part.strip()
            # OVS prints flags inline, e.g. "send_flow_rem idle_timeout=30"
            part = re.sub(r"^((send_flow_rem|check_overlap|reset_counts|no_packet_counts|no_byte_counts)\s+)+", "", part)
            if not part or part in ("send_flow_rem", "check_overlap", "reset_counts"):
                continue
            if re.match(r"^(cookie|duration|table|n_packets|n_bytes|idle_timeout|hard_timeout|idle_age|hard_age|importance|priority)=", part):
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
            "age": float(dur.group(1)) if dur else 0.0,
            "idle": int(idle.group(1)) if idle else 0,
            "raw": line,
        })
    flows.sort(key=lambda item: (item["priority"], item["packets"]), reverse=True)
    return flows


def parse_port_stats(dump: str) -> dict[str, dict[str, int]]:
    """Parse `ovs-ofctl dump-ports`: true per-port packet/byte counters.

    These come straight from the switch, so they count EVERY packet of every host
    (allowed, dropped, legit or attacker) - independent of what the IDS tracks.
    Keys are OpenFlow port numbers (as strings).
    """
    def num(v: str) -> int:
        return int(v) if v.isdigit() else 0

    out: dict[str, dict[str, int]] = {}
    cur = None
    for raw in dump.splitlines():
        m = re.match(r"\s*port\s+(\S+?):\s+rx pkts=(\S+?),\s*bytes=(\S+?),\s*drop=(\S+?),", raw)
        if m:
            cur = m.group(1)
            if cur.isdigit():
                out[cur] = {"rx_pkts": num(m.group(2)), "rx_bytes": num(m.group(3)), "rx_drop": num(m.group(4)),
                            "tx_pkts": 0, "tx_bytes": 0, "tx_drop": 0}
            else:
                cur = None
            continue
        m = re.match(r"\s*tx pkts=(\S+?),\s*bytes=(\S+?),\s*drop=(\S+?),", raw)
        if m and cur and cur in out:
            out[cur].update({"tx_pkts": num(m.group(1)), "tx_bytes": num(m.group(2)), "tx_drop": num(m.group(3))})
    return out


def parse_ports(show_output: str) -> dict[str, int]:
    ports: dict[str, int] = {}
    for line in show_output.splitlines():
        match = re.match(r"\s*(\d+)\(([^)]+)\):", line)
        if match:
            ports[match.group(2)] = int(match.group(1))
    return ports


def map_host_ports(ports: dict[str, int]) -> dict[str, int | None]:
    """Map topology roles. The twelve-host single-mode topology adds servers
    (srv2/srv3/srv4) and extra legit clients (h4-h9) around the original three.
    OVS numbers the OpenFlow ports in the order the hosts were added in
    topology/topo.py: h1, then four servers, then seven legit clients.
    """
    if "vxlan0" in ports:
        return {
            "h1": ports.get("vxlan0"),
            "h2": ports.get("s1-eth1"),
            "srv2": ports.get("s1-eth2"),
            "srv3": ports.get("s1-eth3"),
            "srv4": ports.get("s1-eth4"),
            "h3": ports.get("s1-eth5"),
            "h4": ports.get("s1-eth6"),
            "h5": ports.get("s1-eth7"),
            "h6": ports.get("s1-eth8"),
            "h7": ports.get("s1-eth9"),
            "h8": ports.get("s1-eth10"),
            "h9": ports.get("s1-eth11"),
            "h10": ports.get("s1-eth12"),
        }
    return {
        "h1": ports.get("s1-eth1"),
        "h2": ports.get("s1-eth2"),
        "srv2": ports.get("s1-eth3"),
        "srv3": ports.get("s1-eth4"),
        "srv4": ports.get("s1-eth5"),
        "h3": ports.get("s1-eth6"),
        "h4": ports.get("s1-eth7"),
        "h5": ports.get("s1-eth8"),
        "h6": ports.get("s1-eth9"),
        "h7": ports.get("s1-eth10"),
        "h8": ports.get("s1-eth11"),
        "h9": ports.get("s1-eth12"),
        "h10": ports.get("s1-eth13"),
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
    port_stats_output = ""
    try:
        port_stats_output = _run_ovs(["dump-ports", switch], remote_host=ovs_ssh)
    except RuntimeError as exc:
        if not ovs_error:
            ovs_error = str(exc)
    flows = parse_flows(flow_output)
    port_stats = parse_port_stats(port_stats_output)
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
        "port_stats": port_stats,
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
