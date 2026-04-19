'use strict';

const API = 'api.php';
const App = { reqs: 0, logPage: 1, refreshTimer: null };

// ─── TOOLS ───────────────────────────────────────────────────────────────────
const TOOLS = [
  { id:'ping',       name:'PING',           icon:'⬡', desc:'TCP · DNS · port probe',              placeholder:'example.com',         action:'ping' },
  { id:'dns',        name:'DNS LOOKUP',     icon:'◈', desc:'A·AAAA·MX·NS·TXT·CNAME·SOA·SRV·CAA', placeholder:'example.com',         action:'dns' },
  { id:'traceroute', name:'TRACEROUTE',     icon:'⇢', desc:'Hop-by-hop path analysis',            placeholder:'1.1.1.1',             action:'traceroute' },
  { id:'whois',      name:'WHOIS',          icon:'⋄', desc:'Registrar · expiry · DNSSEC',         placeholder:'example.com',         action:'whois' },
  { id:'ssl',        name:'SSL CHECK',      icon:'🔒', desc:'Cert · expiry · SANs · chain depth',  placeholder:'example.com',         action:'ssl' },
  { id:'headers',    name:'HTTP HEADERS',   icon:'≋', desc:'Response headers · security grade',   placeholder:'example.com',         action:'headers' },
  { id:'uptime',     name:'UPTIME CHECK',   icon:'◎', desc:'HTTP · HTTPS · DNS · SSH probes',     placeholder:'example.com',         action:'uptime' },
  { id:'latency',    name:'LATENCY TEST',   icon:'⏱', desc:'5 samples · p95 · jitter · grade',   placeholder:'example.com',         action:'latency' },
  { id:'ipinfo',     name:'IP INFO',        icon:'◌', desc:'Geo · ASN · org · timezone',          placeholder:'8.8.8.8',             action:'ipinfo' },
  { id:'subdomains', name:'SUBDOMAINS',     icon:'⊞', desc:'DNS brute-force + SSL cert SANs',     placeholder:'example.com',         action:'subdomains' },
  { id:'status',     name:'STATUS CHECK',   icon:'⊕', desc:'HTTP status · TLS · redirects',       placeholder:'https://example.com', action:'status' },
  { id:'portscan',   name:'PORT SCAN',      icon:'⚡', desc:'19 common ports (FTP·SSH·DB…)',       placeholder:'example.com',         action:'portscan' },
  { id:'redirect',   name:'REDIRECT CHAIN', icon:'↪', desc:'Full redirect trace · TLS upgrade',   placeholder:'http://example.com',  action:'redirect' },
];

// ─── DOM ─────────────────────────────────────────────────────────────────────
const $id     = id => document.getElementById(id);
const esc     = s  => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const setText = (id,t) => { const e=$id(id); if(e) e.textContent=t; };
const setHTML = (id,h) => { const e=$id(id); if(e) e.innerHTML=h; };

// ─── TOAST ───────────────────────────────────────────────────────────────────
let _tw = null;
function toast(msg, type='info', ms=3500) {
  if (!_tw) { _tw=document.createElement('div'); _tw.className='toast-wrap'; document.body.appendChild(_tw); }
  const el=document.createElement('div');
  el.className=`toast ${type}`; el.textContent=msg; _tw.appendChild(el);
  setTimeout(()=>el.remove(), ms);
}

// ─── CLOCK ───────────────────────────────────────────────────────────────────
function initClock() {
  const el=$id('js-clock'); if(!el) return;
  const tick=()=>el.textContent=new Date().toTimeString().slice(0,8);
  tick(); setInterval(tick,1000);
}

// ─── API ─────────────────────────────────────────────────────────────────────
async function apiGet(params) {
  let r;
  try {
    r = await fetch(API+'?'+new URLSearchParams(params));
  } catch(e) { throw new Error('Network error: '+e.message); }
  const text = await r.text();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { throw new Error(`HTTP ${r.status} — bad response: ${text.slice(0,120)}`); }
  if (!r.ok) throw new Error((parsed&&parsed.error) ? `Error: ${parsed.error}` : `HTTP ${r.status}`);
  return parsed;
}

async function apiPost(action, body={}) {
  let r;
  try {
    r = await fetch(API, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ action, ...body }),
    });
  } catch(e) { throw new Error('Network error: '+e.message); }
  const text = await r.text();
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { throw new Error(`HTTP ${r.status} — bad response: ${text.slice(0,120)}`); }
  if (!r.ok) throw new Error((parsed&&parsed.error) ? `Error: ${parsed.error}` : `HTTP ${r.status}`);
  return parsed;
}

// ─── NAV ─────────────────────────────────────────────────────────────────────
function showPage(name, btn) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  const page=$id('page-'+name); if(page) page.classList.add('active');
  if(btn) btn.classList.add('active');
  if(name==='logs')      loadLogs(1);
  if(name==='dashboard') refreshDash();
  if(name==='conncheck') runConnCheck();
}

// ─── DASHBOARD ───────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res=await apiGet({action:'stats'});
    if(!res||!res.ok) return;
    const d=res.data;
    setText('s-total',   d.total??0);
    setText('s-success', d.success??0);
    setText('s-errors',  d.errors??0);
    setText('s-today',   d.today??0);
    setText('s-today-sub',(d.today??0)+' ops today');
    const rate=d.total>0?Math.round(d.success/d.total*100):0;
    setText('s-rate', rate+'%');
    renderBars(d.by_tool??{});
  } catch {}
}

function renderBars(byTool) {
  const total=Math.max(1,Object.values(byTool).reduce((a,b)=>a+b,0));
  const sorted=Object.entries(byTool).sort((a,b)=>b[1]-a[1]);
  const html=sorted.map(([tool,cnt])=>{
    const pct=Math.round(cnt/total*100);
    return `<div class="bar-row"><div class="bar-lbl">${esc(tool)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><div class="bar-cnt">${cnt}</div></div>`;
  }).join('');
  setHTML('js-bars','<div class="bar-list">'+(html||'<div class="empty-msg">No data yet</div>')+'</div>');
}

async function loadFeed() {
  try {
    const res=await apiGet({action:'logs',page:1});
    if(!res||!res.ok) return;
    const logs=res.data.logs.slice(0,14);
    if(!logs.length){setHTML('js-feed','<div class="empty-msg">No activity yet.</div>');return;}
    setHTML('js-feed','<div class="feed-list">'+logs.map(l=>`
      <div class="feed-item">
        <span class="lv lv-${esc(l.level)}">${esc(l.level)}</span>
        <span class="feed-tool">${esc(l.tool)}</span>
        <span class="feed-target">${esc(l.target)}</span>
        <span class="feed-time">${fmtTime(l.created_at)}</span>
      </div>`).join('')+'</div>');
  } catch {}
}

const refreshDash = () => { loadStats(); loadFeed(); };

// ─── TOOLS ───────────────────────────────────────────────────────────────────
function buildTools() {
  const grid=$id('js-tools-grid'); if(!grid) return;
  grid.innerHTML=TOOLS.map(t=>`
    <div class="tool-card" id="card-${t.id}">
      <div class="tool-hdr">
        <div class="tool-icon">${t.icon}</div>
        <div><div class="tool-name">${t.name}</div><div class="tool-desc">${t.desc}</div></div>
      </div>
      <div class="tool-body">
        <div class="tool-input-row">
          <input type="text" id="in-${t.id}" class="tool-input" placeholder="${t.placeholder}"
            onkeydown="if(event.key==='Enter')runTool('${t.id}','${t.action}')">
          <button id="btn-${t.id}" class="btn-exec" onclick="runTool('${t.id}','${t.action}')">RUN</button>
        </div>
        <div class="tool-out" id="out-${t.id}"><span class="out-placeholder">Awaiting input...</span></div>
      </div>
    </div>`).join('');
}

async function runTool(id, action) {
  const inp=$id('in-'+id); const out=$id('out-'+id);
  const btn=$id('btn-'+id); const card=$id('card-'+id);
  if(!inp||!out||!btn) return;
  const target=inp.value.trim(); if(!target){inp.focus();return;}
  btn.disabled=true; card.classList.add('running');
  out.innerHTML='<div class="out-loading"><div class="spinner"></div> Executing...</div>';
  App.reqs++; setText('js-reqcount',App.reqs+' REQ');
  try {
    const res=await apiPost(action,{target});
    if(!res||!res.ok){
      out.innerHTML=row('error',esc((res&&res.error)||'Unknown error'),'bad');
      toast((res&&res.error)||'Error','err'); return;
    }
    out.innerHTML=renderResult(action,res.data,res.duration_ms);
    loadFeed();
  } catch(e) {
    out.innerHTML=row('error',esc(e.message),'bad');
    toast('Failed: '+e.message,'err');
  } finally {
    btn.disabled=false; card.classList.remove('running');
  }
}

// ─── RENDERERS ───────────────────────────────────────────────────────────────
function row(key,val,cls){const c=cls?` class="out-val ${cls}"`:' class="out-val"';return `<div class="out-row"><span class="out-key">${key}</span><span${c}>${val}</span></div>`;}
function tag(txt,cls){return `<span class="out-tag ${cls||''}">${esc(String(txt))}</span>`;}

function renderResult(action,d,ms){
  let h='';
  switch(action){
    case 'ping':
      h+=row('host',esc(d.host));h+=row('resolved ip',esc(d.resolved_ip),'cyan');
      h+=row('reachable',d.reachable?'✓ YES':'✗ NO',d.reachable?'good':'bad');
      h+=row('port 80',d.tcp_port80?`open — ${d.tcp_port80_ms}ms`:'closed',d.tcp_port80?'good':'bad');
      h+=row('port 443',d.tcp_port443?`open — ${d.tcp_port443_ms}ms`:'closed',d.tcp_port443?'good':'bad');
      h+=row('dns ms',d.dns_ms+'ms'); break;
    case 'dns':
      h+=row('host',esc(d.host));h+=row('records',d.count+' found',d.count>0?'good':'warn');
      if(d.records?.length){h+='<hr class="out-divider">';d.records.forEach(r=>h+=row(r.type,esc(r.value)+` <small style="color:var(--text-muted)">[ttl ${r.ttl}]</small>`));} break;
    case 'traceroute':
      h+=row('host',esc(d.host));h+=row('dest ip',esc(d.destination_ip),'cyan');h+=row('hops',d.total_hops);
      if(d.hops?.length){h+='<hr class="out-divider">';d.hops.forEach(hop=>h+=row('hop '+hop.hop,esc(hop.ip)+' — '+hop.rtt_ms+'ms',hop.status==='reached'?'good':''));}
      if(d.error)h+=row('error',esc(d.error),'bad'); break;
    case 'whois':
      h+=row('domain',esc(d.domain),'cyan');h+=row('server',esc(d.server));h+=row('found',d.found?'✓ yes':'✗ no',d.found?'good':'bad');
      if(d.data){h+='<hr class="out-divider">';const dd=d.data;
        if(dd.registrar)h+=row('registrar',esc(String(dd.registrar)));
        if(dd.created)h+=row('created',esc(String(dd.created)));
        if(dd.expires)h+=row('expires',esc(String(dd.expires)));
        if(dd.dnssec)h+=row('dnssec',esc(String(dd.dnssec)),'cyan');
        if(dd.nameservers){const ns=Array.isArray(dd.nameservers)?dd.nameservers:[dd.nameservers];h+=row('nameservers',ns.map(n=>esc(n)).join('<br>'));}} break;
    case 'ssl':
      h+=row('host',esc(d.host));h+=row('valid',d.valid?'✓ YES':'✗ NO',d.valid?'good':'bad');
      if(d.valid){h+=row('subject',esc(d.subject),'cyan');h+=row('issuer',esc(d.issuer));
        h+=row('not after',esc(d.not_after));
        h+=row('days left',d.days_left,d.days_left>30?'good':d.days_left>7?'warn':'bad');
        h+=row('chain depth',d.chain_depth);
        if(d.alt_names?.length){h+='<hr class="out-divider">';h+=row('alt names',d.alt_names.slice(0,8).map(n=>tag(esc(n))).join(''));}
        h+=row('handshake ms',d.handshake_ms+'ms');}
      else{h+=row('error',esc(d.error||'unknown'),'bad');} break;
    case 'headers':
      h+=row('host',esc(d.host));h+=row('status',d.status_code,d.status_code<400?'good':'bad');h+=row('latency',d.latency_ms+'ms');
      if(d.security){h+='<hr class="out-divider">';
        const checks=[['HSTS',d.security.hsts],['CSP',d.security.csp],['X-Frame',d.security['x-frame']],
          ['XSS-Prot',d.security.x_xss],['NoSniff',d.security.nosniff],['Referrer',d.security.referrer],
          ['Permissions',d.security.permissions],['COEP',d.security.coep]];
        h+=row('sec score',(d.sec_score??0)+'/'+(d.sec_max??8),(d.sec_score>=6)?'good':(d.sec_score>=3)?'warn':'bad');
        h+='<div class="out-row"><span class="out-key">headers</span><span class="out-val"><div class="sec-grid">';
        checks.forEach(([l,ok])=>h+=`<div class="sec-item ${ok?'sec-ok':'sec-bad'}">${ok?'✓':'✗'} ${l}</div>`);
        h+='</div></span></div>';}
      if(d.error)h+=row('error',esc(d.error),'bad'); break;
    case 'uptime':
      h+=row('host',esc(d.host));h+=row('status',d.up?'✓ UP':'✗ DOWN',d.up?'good':'bad');
      h+=row('score',d.score+'%',d.score>=75?'good':d.score>0?'warn':'bad');
      if(d.checks){h+='<hr class="out-divider">';d.checks.forEach(c=>h+=row(c.service+':'+c.port,c.up?`✓ up — ${c.ms}ms`:'✗ down',c.up?'good':'bad'));} break;
    case 'latency':
      h+=row('host',esc(d.host));h+=row('grade',d.grade,d.grade==='EXCELLENT'?'good':d.grade==='GOOD'?'cyan':d.grade==='FAIR'?'warn':'bad');
      h+=row('min',d.min_ms+'ms','good');h+=row('avg',d.avg_ms+'ms','cyan');h+=row('p95',d.p95_ms+'ms','warn');h+=row('max',d.max_ms+'ms');
      h+=row('jitter',d.jitter+'ms',d.jitter<20?'good':d.jitter<60?'warn':'bad');
      if(d.samples?.length){const mx=Math.max(...d.samples,1);h+=`<div class="out-row"><span class="out-key">samples</span><span class="out-val"><div class="lat-samples">${d.samples.map(s=>`<div class="lat-bar" style="height:${Math.round(s/mx*100)}%" title="${s}ms"></div>`).join('')}</div></span></div>`;} break;
    case 'ipinfo':
      h+=row('host',esc(d.host));h+=row('ip',esc(d.ip),'cyan');h+=row('private',d.is_private?'yes':'no',d.is_private?'warn':'good');
      if(d.city)h+=row('city',esc(d.city));if(d.region)h+=row('region',esc(d.region));if(d.country)h+=row('country',esc(d.country));
      if(d.asn)h+=row('asn',esc(d.asn),'amber');if(d.org)h+=row('org',esc(d.org),'purple');if(d.timezone)h+=row('timezone',esc(d.timezone)); break;
    case 'subdomains':
      h+=row('host',esc(d.host));h+=row('found',d.total,d.total>0?'good':'warn');
      if(d.found?.length){h+='<hr class="out-divider">';h+=row('dns brute',d.found.length+' found');d.found.forEach(s=>h+=row(esc(s.subdomain),esc(s.ip),'cyan'));}
      if(d.cert_found?.length){h+='<hr class="out-divider">';h+=row('ssl cert',d.cert_found.length+' found');d.cert_found.forEach(s=>h+=row(esc(s.subdomain),s.ip?esc(s.ip):'unresolved',s.ip?'cyan':'warn'));} break;
    case 'status':
      h+=row('url',esc(d.url));if(d.final_url&&d.final_url!==d.url)h+=row('final url',esc(d.final_url));
      h+=row('status',d.status_code,d.ok?'good':'bad');h+=row('ok',d.ok?'✓ YES':'✗ NO',d.ok?'good':'bad');
      h+=row('tls',d.tls?'✓ HTTPS':'✗ HTTP',d.tls?'good':'warn');h+=row('latency',d.latency_ms+'ms');
      if(d.content_size)h+=row('content size',(d.content_size/1024).toFixed(1)+' KB');
      if(d.error)h+=row('error',esc(d.error),'bad'); break;
    case 'portscan':
      h+=row('host',esc(d.host));h+=row('scanned',d.scanned+' ports');h+=row('open',d.open_count,d.open_count>0?'good':'warn');
      if(d.open?.length){h+='<hr class="out-divider">';d.open.forEach(p=>h+=row(p.service+':'+p.port,`✓ open — ${p.ms}ms`,'good'));}
      if(d.closed?.length){h+='<hr class="out-divider">';h+=row('closed',d.closed.map(p=>tag(p.port+'/'+p.service,'red')).join(''));} break;
    case 'redirect':
      h+=row('start url',esc(d.start_url));h+=row('final url',esc(d.final_url),'cyan');h+=row('hops',d.hops);
      h+=row('tls upgrade',d.tls_upgrade?'✓ HTTP→HTTPS':'no',d.tls_upgrade?'good':'');
      if(d.chain?.length){h+='<hr class="out-divider">';d.chain.forEach((hop,i)=>h+=row(`hop ${i+1} [${hop.code}]`,esc(hop.url)+` — ${hop.ms}ms ${hop.tls?tag('TLS','green'):tag('plain','red')}`,hop.code<300?'good':hop.code<400?'warn':'bad'));} break;
  }
  h+='<hr class="out-divider">';h+=row('duration',ms+'ms','cyan');
  return h;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION SECURITY SCAN
// ═══════════════════════════════════════════════════════════════════════════
let connCheckRunning = false;

async function runConnCheck() {
  if (connCheckRunning) return;
  connCheckRunning = true;
  const container = $id('cc-container');
  if (!container) { connCheckRunning=false; return; }

  container.innerHTML = `
    <div class="cc-loading">
      <div class="spinner" style="width:20px;height:20px;border-width:3px"></div>
      <span>Scanning your connection...</span>
    </div>`;

  const results = {};

  try {
    results.isHttps  = location.protocol === 'https:';
    results.pageHost = location.hostname;
    results.pagePort = location.port || (results.isHttps ? '443' : '80');

    results.security = {
      https         : results.isHttps,
      secureCtx     : window.isSecureContext,
      doNotTrack    : navigator.doNotTrack === '1',
      cookiesEnabled: navigator.cookieEnabled,
      webRTC        : typeof RTCPeerConnection !== 'undefined',
      mixedContent  : results.isHttps && document.querySelectorAll('[src^="http:"]').length > 0,
    };

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    results.connection = conn ? {
      type         : conn.type          || 'unknown',
      effectiveType: conn.effectiveType || 'unknown',
      downlink     : conn.downlink      || null,
      rtt          : conn.rtt           || null,
      saveData     : conn.saveData      || false,
    } : null;

    // Latency — 3 pings to api
    const latSamples = [];
    for (let i=0; i<3; i++) {
      const t0=performance.now();
      try { await fetch(API+'?action=stats',{cache:'no-store'}); } catch {}
      latSamples.push(Math.round(performance.now()-t0));
    }
    results.latency = {
      samples: latSamples,
      avg    : Math.round(latSamples.reduce((a,b)=>a+b,0)/latSamples.length),
      min    : Math.min(...latSamples),
      max    : Math.max(...latSamples),
    };

    // Public IP via ipinfo
    try {
      const ipRes = await fetch('https://ipinfo.io/json',{signal:AbortSignal.timeout(5000),headers:{Accept:'application/json'}});
      results.ipInfo = ipRes.ok ? await ipRes.json() : null;
    } catch { results.ipInfo=null; }

    // Server-side TLS + header grading
    try {
      const scanRes = await fetch(API+'?'+new URLSearchParams({action:'connection_scan',host:results.pageHost}),{cache:'no-store'});
      if (scanRes.ok) {
        const j = await scanRes.json();
        if (j.ok) {
          results.serverScan = j.data;
          if (!results.ipInfo?.ip && j.data.server_detected_ip) {
            results.ipInfo = results.ipInfo||{};
            results.ipInfo.ip = j.data.server_detected_ip;
          }
        }
      }
    } catch(e) { console.warn('Server scan:',e.message); }

  } catch(e) { console.warn('ConnCheck:',e); }

  connCheckRunning = false;
  renderConnCheck(container, results);
}

function renderConnCheck(container, r) {
  const isHttps  = r.isHttps;
  const ip       = r.ipInfo?.ip || r.serverScan?.server_detected_ip || '—';
  const city     = r.ipInfo?.city    || '';
  const country  = r.ipInfo?.country || '';
  const org      = r.ipInfo?.org     || '—';
  const latAvg   = r.latency?.avg    || 0;
  const latGrade = latAvg<80?['EXCELLENT','good']:latAvg<200?['GOOD','cyan']:latAvg<500?['FAIR','warn']:['POOR','bad'];
  const sec      = r.security   || {};
  const srv      = r.serverScan || {};
  const tls      = srv.tls      || null;
  const hdrs     = srv.headers  || null;

  let riskScore = 0;
  const alerts = [];
  if (!isHttps)         { riskScore+=40; alerts.push({sev:'bad', msg:'Not using HTTPS — traffic may be intercepted'}); }
  if (!sec.secureCtx)   { riskScore+=20; alerts.push({sev:'bad', msg:'Page not in secure context'}); }
  if (sec.mixedContent) { riskScore+=15; alerts.push({sev:'warn',msg:'Mixed content detected'}); }
  if (sec.webRTC)       { riskScore+=10; alerts.push({sev:'warn',msg:'WebRTC enabled — may leak real IP behind VPN'}); }
  if (latAvg>400)       { riskScore+=10; alerts.push({sev:'warn',msg:`High latency (${latAvg}ms avg)`}); }
  if (sec.doNotTrack)   { riskScore-=5; }
  if (hdrs?.grade==='D'){ riskScore+=20; alerts.push({sev:'bad', msg:'Security headers grade D — many missing'}); }
  else if (hdrs?.grade==='C'){ riskScore+=10; alerts.push({sev:'warn',msg:'Security headers grade C — some missing'}); }
  if (tls&&!tls.supported)  { riskScore+=30; alerts.push({sev:'bad',msg:'TLS/SSL not supported on this host'}); }
  if (tls?.days_left>=0&&tls.days_left<14) { riskScore+=25; alerts.push({sev:'bad',msg:`SSL cert expires in ${tls.days_left} days`}); }

  const riskLabel = riskScore<=0?['LOW','good']:riskScore<=25?['MEDIUM','warn']:['HIGH','bad'];
  const gradeColor= g=>g==='A'?'good':g==='B'?'cyan':g==='C'?'warn':'bad';

  container.innerHTML = `
    <div class="cc-grid">

      <div class="cc-card cc-wide">
        <div class="cc-card-hdr">🌐 Connection Overview</div>
        <div class="cc-card-body">
          ${ccRow('Protocol',  isHttps?tag('HTTPS','green'):tag('HTTP','red'))}
          ${ccRow('Your IP',   `<span class="out-val cyan">${esc(ip)}</span>`)}
          ${ccRow('Location',  esc([city,country].filter(Boolean).join(', '))||'—')}
          ${ccRow('ISP / Org', esc(org))}
          ${ccRow('Page Host', esc(r.pageHost))}
          ${ccRow('Port',      esc(r.pagePort))}
          ${srv.server_https!==undefined?ccRow('Server HTTPS',srv.server_https?tag('YES','green'):tag('NO','red')):''}
        </div>
      </div>

      <div class="cc-card">
        <div class="cc-card-hdr">📊 Risk Score</div>
        <div class="cc-card-body" style="text-align:center;padding:20px 16px">
          <div class="risk-score ${riskLabel[1]}">${Math.max(0,riskScore)}</div>
          <div class="risk-label ${riskLabel[1]}">${riskLabel[0]} RISK</div>
          ${alerts.length===0?'<div class="cc-ok-msg">✓ No issues detected</div>':''}
        </div>
      </div>

      <div class="cc-card">
        <div class="cc-card-hdr">⏱ Server Latency</div>
        <div class="cc-card-body">
          ${ccRow('Grade',`<span class="out-val ${latGrade[1]}">${latGrade[0]}</span>`)}
          ${ccRow('Avg',  `<span class="out-val cyan">${latAvg}ms</span>`)}
          ${ccRow('Min',  `<span class="out-val good">${r.latency?.min||0}ms</span>`)}
          ${ccRow('Max',  `${r.latency?.max||0}ms`)}
          <div class="lat-samples" style="margin-top:8px;height:28px">
            ${(r.latency?.samples||[]).map(s=>{const mx=Math.max(...(r.latency?.samples||[1]));return `<div class="lat-bar" style="height:${Math.round(s/mx*100)}%" title="${s}ms"></div>`;}).join('')}
          </div>
        </div>
      </div>

      <div class="cc-card">
        <div class="cc-card-hdr">🔒 Browser Security</div>
        <div class="cc-card-body">
          <div class="sec-grid" style="gap:6px">
            ${ccSecItem('HTTPS',           sec.https)}
            ${ccSecItem('Secure Context',  sec.secureCtx)}
            ${ccSecItem('Cookies On',      sec.cookiesEnabled)}
            ${ccSecItem('Do Not Track',    sec.doNotTrack)}
            ${ccSecItem('No WebRTC Leak',  !sec.webRTC)}
            ${ccSecItem('No Mixed Content',!sec.mixedContent)}
          </div>
        </div>
      </div>

      ${tls?`
      <div class="cc-card">
        <div class="cc-card-hdr">🔐 TLS / SSL Certificate</div>
        <div class="cc-card-body">
          ${ccRow('Supported',tls.supported?tag('YES','green'):tag('NO','red'))}
          ${tls.supported?`
            ${ccRow('Valid',    tls.valid?tag('YES','green'):tag('EXPIRED','red'))}
            ${ccRow('Days Left',tls.days_left>=0?`<span class="out-val ${tls.days_left<14?'bad':tls.days_left<30?'warn':'good'}">${tls.days_left}d</span>`:'—')}
            ${ccRow('Issuer',  esc(tls.issuer||'—'))}
            ${ccRow('Subject', esc(tls.subject||'—'))}
          `:ccRow('Error',esc(tls.error||'Connect failed'),'bad')}
        </div>
      </div>`:''}

      ${hdrs?`
      <div class="cc-card">
        <div class="cc-card-hdr">📋 HTTP Security Headers</div>
        <div class="cc-card-body">
          ${ccRow('Grade',`<span class="out-val ${gradeColor(hdrs.grade)}" style="font-size:1.4em;font-weight:700">${esc(hdrs.grade)}</span>`)}
          ${ccRow('Score',`${hdrs.score} / ${hdrs.max}`)}
          ${ccRow('HTTP', esc(String(hdrs.http_code)))}
          <hr class="out-divider" style="margin:8px 0">
          <div class="sec-grid" style="gap:5px">
            ${Object.entries(hdrs.checks||{}).map(([k,v])=>ccSecItem(k,v)).join('')}
          </div>
        </div>
      </div>`:''}

      ${r.connection?`
      <div class="cc-card">
        <div class="cc-card-hdr">📡 Network Info</div>
        <div class="cc-card-body">
          ${ccRow('Type',      esc(r.connection.type))}
          ${ccRow('Effective', esc(r.connection.effectiveType))}
          ${r.connection.downlink!=null?ccRow('Downlink',r.connection.downlink+' Mbps'):''}
          ${r.connection.rtt!=null?ccRow('RTT',r.connection.rtt+'ms'):''}
          ${ccRow('Save Data', r.connection.saveData?tag('ON','amber'):tag('OFF','green'))}
        </div>
      </div>`:''}

      ${alerts.length?`
      <div class="cc-card cc-wide cc-alerts">
        <div class="cc-card-hdr">⚠ Security Alerts</div>
        <div class="cc-card-body">
          ${alerts.map(a=>`<div class="cc-alert ${a.sev}"><span class="cc-alert-icon">${a.sev==='bad'?'✗':'⚠'}</span><span>${esc(a.msg)}</span></div>`).join('')}
        </div>
      </div>`:`
      <div class="cc-card cc-wide">
        <div class="cc-card-hdr">✓ Security Status</div>
        <div class="cc-card-body"><div class="cc-ok-msg" style="padding:12px 0">✓ No security issues detected</div></div>
      </div>`}

    </div>
    <div style="text-align:right;margin-top:12px">
      <button class="btn-refresh" onclick="runConnCheck()">↻ Re-scan</button>
    </div>`;
}

function ccRow(key,valHtml){return `<div class="out-row"><span class="out-key">${esc(key)}</span><span class="out-val">${valHtml}</span></div>`;}
function ccSecItem(label,ok){return `<div class="sec-item ${ok?'sec-ok':'sec-bad'}">${ok?'✓':'✗'} ${esc(label)}</div>`;}

// ─── LOGS ────────────────────────────────────────────────────────────────────
async function loadLogs(page) {
  page=page||1; App.logPage=page;
  const level =$id('log-level')?.value||'ALL';
  const tool  =$id('log-tool')?.value||'ALL';
  const search=$id('log-search')?.value.trim()||'';
  const tbody =$id('log-tbody');
  if(tbody)tbody.innerHTML='<tr><td colspan="6" class="loading-msg">Loading...</td></tr>';
  try {
    const res=await apiGet({action:'logs',level,tool,page,search});
    if(!res||!res.ok){if(tbody)tbody.innerHTML='<tr><td colspan="6" class="empty-msg">Error loading logs</td></tr>';return;}
    const d=res.data;
    setText('log-count',d.total+' records');
    if(!d.logs.length){if(tbody)tbody.innerHTML='<tr><td colspan="6" class="empty-msg">No logs found</td></tr>';renderPages(d.page,d.pages);return;}
    if(tbody)tbody.innerHTML=d.logs.map(l=>`<tr>
      <td>${fmtDT(l.created_at)}</td>
      <td><span class="lv lv-${esc(l.level)}">${esc(l.level)}</span></td>
      <td>${esc(l.tool)}</td>
      <td title="${esc(l.target)}">${esc(l.target)}</td>
      <td>${esc(l.ip)}</td>
      <td>${esc(l.duration_ms)}ms</td>
      <td><button class="btn-view" onclick='showModal(${JSON.stringify(l)})'>VIEW</button></td>
    </tr>`).join('');
    renderPages(d.page,d.pages);
  } catch(e){if(tbody)tbody.innerHTML=`<tr><td colspan="6" class="empty-msg">${esc(e.message)}</td></tr>`;}
}

function renderPages(cur,total){
  const el=$id('log-pages'); if(!el) return;
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="pg-btn" ${cur<=1?'disabled':''} onclick="loadLogs(${cur-1})">← Prev</button>`;
  for(let i=Math.max(1,cur-2);i<=Math.min(total,cur+2);i++)
    h+=`<button class="pg-btn ${i===cur?'cur':''}" onclick="loadLogs(${i})">${i}</button>`;
  h+=`<button class="pg-btn" ${cur>=total?'disabled':''} onclick="loadLogs(${cur+1})">Next →</button>`;
  h+=`<span class="pg-info">${cur} / ${total}</span>`;
  el.innerHTML=h;
}

async function exportLogs(){
  try {
    toast('Fetching logs…','info');
    const res=await apiGet({action:'logs',page:1,level:'ALL',tool:'ALL'});
    if(!res||!res.ok){toast('Export failed','err');return;}
    const rows=[['id','created_at','level','tool','target','ip','duration_ms']];
    res.data.logs.forEach(l=>rows.push([l.id,l.created_at,l.level,l.tool,l.target,l.ip,l.duration_ms]));
    const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download='nexus-logs-'+new Date().toISOString().slice(0,10)+'.csv'; a.click();
    toast('CSV exported ✓','ok');
  } catch(e){toast('Export error: '+e.message,'err');}
}

// ─── MODAL ───────────────────────────────────────────────────────────────────
function showModal(log){
  const t=$id('modal-title'); const b=$id('modal-body');
  if(t)t.textContent=log.tool.toUpperCase()+' › '+log.target;
  if(b){try{b.textContent=JSON.stringify(JSON.parse(log.result),null,2);}catch{b.textContent=log.result;}}
  $id('js-modal')?.classList.add('open');
}
function closeModal()     {$id('js-modal')?.classList.remove('open');}
function onModalOverlay(e){if(e.target===$id('js-modal'))closeModal();}

// ─── UTILS ───────────────────────────────────────────────────────────────────
function fmtTime(s){try{return new Date(s).toLocaleTimeString();}catch{return s;}}
function fmtDT(s){try{const d=new Date(s);return d.toLocaleDateString('en-GB',{day:'2-digit',month:'2-digit'})+' '+d.toLocaleTimeString();}catch{return s;}}
function fetchMyIP(){fetch('https://api.ipify.org?format=json').then(r=>r.json()).then(d=>setText('js-myip','IP: '+(d.ip||'—'))).catch(()=>{});}

// ─── KEYBOARD ────────────────────────────────────────────────────────────────
document.addEventListener('keydown', e=>{if(e.key==='Escape')closeModal();});

// ─── BOOT — direct access, no auth ───────────────────────────────────────────
(function boot(){
  initClock();
  buildTools();
  fetchMyIP();
  refreshDash();
  App.refreshTimer = setInterval(refreshDash, 20_000);
})();
