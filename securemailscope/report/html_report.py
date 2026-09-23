"""Self-contained interactive HTML report. Data, CSS and JS are inlined into a
single file that opens offline in any browser — the shareable artifact for the
zero-credential demo. Shows overall posture, a risk spectrum, prioritized
remediations and a per-session drill-down with severity filtering and search.
"""
from __future__ import annotations

import json

from ..analysis.engine import full_dict

_CSS = r"""
:root{
--ink:#0a0f1c;--ink2:#0d1424;--panel:#121a2d;--panel2:#182339;
--line:#25314b;--line2:#33425f;--txt:#e9eefb;--mut:#8b98b6;--dim:#5c6a89;
--accent:#5b8cff;--accent2:#37d0d6;
--CRITICAL:#ff5a6a;--HIGH:#ff9f45;--MEDIUM:#f2c94c;--LOW:#4fd18b;--INFO:#7c8cff;
--A:#3fd07f;--B:#28c7b0;--C:#f2c94c;--D:#ff9f45;--F:#ff5a6a;
--mono:ui-monospace,"Cascadia Code","JetBrains Mono","SF Mono",Consolas,monospace;
--sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;font-family:var(--sans);font-size:14px;line-height:1.55;color:var(--txt);
background:radial-gradient(1200px 600px at 15% -10%,rgba(91,140,255,.10),transparent 60%),
radial-gradient(900px 520px at 100% 0%,rgba(55,208,214,.06),transparent 55%),var(--ink);
background-attachment:fixed}
.wrap{max-width:1140px;margin:0 auto;padding:32px 24px 56px}
a{color:var(--accent);text-decoration:none}
h1{font-size:16px;font-weight:700;margin:0 0 5px;letter-spacing:-.01em}
h2{font-size:18px;font-weight:700;margin:40px 0 14px;letter-spacing:-.01em}
.sub{color:var(--dim);font-size:12.5px;font-family:var(--mono)}
.mast{display:grid;grid-template-columns:minmax(190px,260px) 1fr;gap:30px;align-items:center;
padding:26px 30px;border:1px solid var(--line);border-radius:18px;
background:linear-gradient(180deg,var(--panel),var(--ink2));
box-shadow:inset 0 1px 0 rgba(255,255,255,.03),0 24px 60px -30px rgba(0,0,0,.7)}
.mast-grade{display:flex;flex-direction:column;border-right:1px solid var(--line);padding-right:28px}
.verdict{font-size:12px;font-weight:700;color:var(--gc,var(--mut))}
.gradeMon{font-family:var(--mono);font-weight:800;font-size:100px;line-height:.9;
letter-spacing:-.04em;color:var(--gc,var(--txt))}
.scoreLine{font-family:var(--mono);font-size:23px;font-weight:700;margin-top:4px}
.scoreLine .of{color:var(--dim);font-size:15px}
.spectrum{display:flex;height:16px;border-radius:9px;overflow:hidden;background:var(--ink);
border:1px solid var(--line);margin-top:16px}
.spectrum i{height:100%;display:block;transition:width .9s cubic-bezier(.2,.7,.2,1)}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.chip{display:inline-flex;align-items:center;gap:7px;padding:6px 12px;border-radius:10px;
font-size:12.5px;font-weight:600;cursor:pointer;user-select:none;border:1px solid var(--line);
background:var(--ink2);transition:border-color .15s,opacity .15s}
.chip:hover{border-color:var(--line2)}
.chip:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.chip.off{opacity:.34}
.chip .dot{width:9px;height:9px;border-radius:3px}
.chip .n{font-family:var(--mono);font-weight:800}
.rec{position:relative;display:grid;grid-template-columns:auto 1fr auto;gap:14px;
align-items:start;padding:14px 16px;margin:10px 0;border-radius:12px;background:var(--panel);
border:1px solid var(--line);border-left:4px solid var(--sc,var(--line2))}
.rec .sevtick{font-family:var(--mono);font-size:10px;font-weight:800;color:var(--sc);padding-top:2px}
.rec .txt{font-weight:600}
.rec .ids{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:5px}
.rec .count{font-family:var(--mono);font-size:11px;color:var(--mut);white-space:nowrap;
border:1px solid var(--line);border-radius:8px;padding:3px 9px;align-self:center}
.sec-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
input.search{background:var(--ink2);border:1px solid var(--line);color:var(--txt);
border-radius:10px;padding:9px 13px;width:min(340px,100%);font-size:13px;font-family:var(--sans)}
input.search::placeholder{color:var(--dim)}
input.search:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(91,140,255,.18)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;margin:11px 0;
overflow:hidden;transition:border-color .15s}
.card:hover{border-color:var(--line2)}
.chead{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer}
.chead:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.chead .sp{flex:1}
.caret{color:var(--dim);transition:transform .2s;font-family:var(--mono);font-size:18px}
.card.open .caret{transform:rotate(90deg)}
.gbadge{font-family:var(--mono);font-weight:800;font-size:15px;width:34px;height:34px;
display:flex;align-items:center;justify-content:center;border-radius:9px;color:#08101f;
background:var(--gc,#8b98b6)}
.route{font-family:var(--mono);font-weight:700}
.tls{color:var(--mut);font-size:12.5px}
.pill{font-size:11px;color:var(--mut);border:1px solid var(--line);padding:3px 9px;
border-radius:999px;font-family:var(--mono);white-space:nowrap}
.tb{font-size:10px;font-weight:800;padding:3px 9px;border-radius:6px;color:#08101f}
.body{display:none;padding:2px 16px 18px;border-top:1px solid var(--line)}
.card.open .body{display:block}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px 22px;margin:16px 0}
.kv .k{color:var(--dim);font-size:11px}
.kv .v{margin-top:2px;word-break:break-word}
.mono{font-family:var(--mono)}
.find{border-left:3px solid var(--sc,var(--line2));padding:10px 14px;margin:9px 0;
background:var(--ink2);border-radius:0 10px 10px 0}
.find .t{font-weight:700}
.find .id{font-family:var(--mono);font-size:11px;color:var(--dim)}
.find .ev{color:var(--mut);font-size:12.5px;margin-top:4px}
.find .fix{font-size:12.5px;margin-top:6px}
.find .refs{font-family:var(--mono);font-size:11px;color:var(--dim);margin-top:5px}
.sev{font-family:var(--mono);font-size:10px;font-weight:800;padding:2px 7px;border-radius:5px;
color:#08101f;margin-right:8px}
.empty{color:var(--dim)}
footer{color:var(--dim);font-size:11.5px;margin-top:44px;border-top:1px solid var(--line);
padding-top:18px;line-height:1.7}
@media(max-width:720px){
.mast{grid-template-columns:1fr}
.mast-grade{border-right:0;border-bottom:1px solid var(--line);padding:0 0 18px}
.gradeMon{font-size:82px}}
@media(prefers-reduced-motion:reduce){.spectrum i,.caret,.card{transition:none}}
"""

_JS1 = r"""
const SEV=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const active=new Set(SEV);
const $=s=>document.getElementById(s);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const cvar=n=>getComputedStyle(document.documentElement).getPropertyValue('--'+n).trim();
const gradeColor=g=>cvar(g)||'#8b98b6';
const sevBadge=s=>`<span class="sev" style="background:${cvar(s)}">${s}</span>`;
const VERDICT={A:"Strong posture",B:"Minor gaps",C:"Needs hardening",
D:"Weak posture",F:"Critical exposure"};
const TRUST={trusted:'#3fd07f','private-ca':'#28c7b0','self-signed':'#f2c94c',
unanchored:'#ff9f45',broken:'#ff5a6a',unverified:'#8b98b6'};
const trustBadge=st=>st?`<span class="tb" style="background:${TRUST[st]||'#8b98b6'}">${esc(st)}</span>`:'';

function renderHead(){
  const g=DATA.overall_grade,gc=gradeColor(g),mon=$('gradeMon'),vd=$('verdict');
  mon.textContent=g;mon.style.setProperty('--gc',gc);
  vd.textContent=VERDICT[g]||'';vd.style.setProperty('--gc',gc);
  $('scoreNum').textContent=DATA.overall_score;
  $('meta').textContent=`${DATA.source} · ${DATA.session_count} session(s) · v${DATA.tool_version} · ${DATA.generated_at}`;
}

function renderSpectrum(){
  const t=DATA.severity_totals||{},total=SEV.reduce((a,s)=>a+(t[s]||0),0),bar=$('spectrum');
  if(!total){bar.innerHTML='<i style="width:100%;background:var(--LOW)"></i>';return;}
  bar.innerHTML=SEV.map(s=>{const n=t[s]||0;if(!n)return'';
    return `<i data-w="${(n/total*100).toFixed(2)}" style="width:0;background:${cvar(s)}" title="${s}: ${n}"></i>`;}).join('');
  requestAnimationFrame(()=>bar.querySelectorAll('i').forEach(i=>i.style.width=i.dataset.w+'%'));
}
"""

_JS2 = r"""
function certBlock(c){
  if(!c) return '';
  if(!c.parsed) return `<div class="empty" style="margin-top:6px">certificate present but not parsed${c.error?': '+esc(c.error):''}</div>`;
  const w=(c.weaknesses||[]).map(x=>`<span class="pill">${esc(x)}</span>`).join(' ');
  return `<div class="kv">
    <div><div class="k">subject</div><div class="v">${esc(c.subject)}</div></div>
    <div><div class="k">issuer</div><div class="v">${esc(c.issuer)}</div></div>
    <div><div class="k">public key</div><div class="v mono">${esc(c.public_key_algo)} ${c.key_bits||''}</div></div>
    <div><div class="k">signature hash</div><div class="v mono">${esc(c.sig_hash)}${c.self_signed?' · self-signed':''}</div></div>
    <div><div class="k">valid until</div><div class="v mono">${esc(c.not_after)} (${c.days_to_expiry}d)</div></div>
    <div><div class="k">status</div><div class="v">${c.is_expired?'expired':(c.not_yet_valid?'not yet valid':'valid')}</div></div>
  </div>${w?`<div style="margin-top:2px">${w}</div>`:''}`;
}
function findingHtml(f){
  return `<div class="find" style="--sc:${cvar(f.severity)}">
    <div>${sevBadge(f.severity)}<span class="t">${esc(f.title)}</span> <span class="id">${esc(f.id)}</span></div>
    <div class="ev">${esc(f.evidence)}</div>
    <div class="fix">${esc(f.recommendation)}</div>
    ${f.refs&&f.refs.length?`<div class="refs">${f.refs.map(esc).join('  ·  ')}</div>`:''}
  </div>`;
}
"""

_JS3 = r"""
function sessionCard(s,i){
  const su=s.summary||{};
  const fs=s.findings.filter(f=>active.has(f.severity));
  const tls=su.tls_present?(su.negotiated_version_name||'TLS'):'no TLS';
  const anom=s.anomaly?`<span class="pill" style="border-color:var(--HIGH);color:var(--HIGH)">anomaly ${s.anomaly_score}</span>`:'';
  const chain=su.chain_trust_status?`<div><div class="k">certificate chain</div><div class="v">${trustBadge(su.chain_trust_status)} <span style="color:var(--mut)">${esc(su.chain_trust_detail||'')}</span></div></div>`:'';
  return `<div class="card" style="--gc:${gradeColor(s.grade)}">
    <div class="chead" tabindex="0" role="button" aria-expanded="false"
      onclick="toggleCard(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleCard(this);}">
      <span class="gbadge">${s.grade}</span>
      <span class="route">${esc(s.protocol)}:${s.server_port}</span>
      <span class="tls">${tls}${su.cipher_suite_name?'  ·  '+esc(su.cipher_suite_name):''}</span>
      <span class="sp"></span>
      ${su.chain_trust_status?trustBadge(su.chain_trust_status):''}
      <span class="pill">risk ${esc(s.risk_label)}</span>${anom}
      <span class="pill">${s.score}/100</span>
      <span class="pill">${fs.length} finding(s)</span>
      <span class="caret">›</span>
    </div>
    <div class="body">
      <div class="kv">
        <div><div class="k">stream</div><div class="v mono">${esc(s.stream)}</div></div>
        <div><div class="k">starttls</div><div class="v">offered ${su.starttls_offered?'yes':'no'} / used ${su.starttls_used?'yes':'no'}</div></div>
        <div><div class="k">cleartext auth</div><div class="v">${su.cleartext_auth?'yes — credentials exposed':'no'}</div></div>
        <div><div class="k">cipher</div><div class="v">grade ${esc(su.cipher_grade||'—')} · ${su.cipher_bits||0}b · PFS ${su.cipher_pfs?'yes':'no'} · AEAD ${su.cipher_aead?'yes':'no'}</div></div>
        <div><div class="k">SNI</div><div class="v mono">${esc(su.sni||'—')}</div></div>
        <div><div class="k">ML risk</div><div class="v">${esc(su.ml_risk||'—')}${su.ml_confidence!=null?' ('+su.ml_confidence+')':''}</div></div>
        ${chain}
      </div>
      ${certBlock((s.certificates&&s.certificates[0])||null)}
      ${fs.length?fs.map(findingHtml).join(''):'<div class="empty">no findings at the selected severities</div>'}
    </div></div>`;
}
function toggleCard(h){
  const card=h.parentNode,open=card.classList.toggle('open');
  h.setAttribute('aria-expanded',open?'true':'false');
}
function renderSessions(){
  const q=($('q').value||'').toLowerCase();
  const rows=DATA.sessions.map((s,i)=>[s,i]).filter(([s])=>{
    if(!q) return true;
    const hay=(s.protocol+' '+s.server_port+' '+JSON.stringify(s.summary)+' '+
      s.findings.map(f=>f.title+' '+f.id).join(' ')).toLowerCase();
    return hay.includes(q);});
  $('sessions').innerHTML=rows.map(([s,i])=>sessionCard(s,i)).join('')
    ||'<div class="empty">No sessions match the current filter.</div>';
}
function renderRecs(){
  const r=DATA.recommendations||[];
  $('recs').innerHTML=r.length?r.map(x=>`<div class="rec" style="--sc:${cvar(x.severity)}">
      <span class="sevtick">${x.severity}</span>
      <div><div class="txt">${esc(x.recommendation)}</div>
        <div class="ids">${(x.finding_ids||[]).map(esc).join('  ·  ')}</div></div>
      <span class="count">${(x.affected_streams||[]).length} stream(s)</span>
    </div>`).join('')
    :'<div class="empty">No action required — no cryptographic weaknesses were observed.</div>';
}
function renderChips(){
  const t=DATA.severity_totals||{};
  $('chips').innerHTML=SEV.map(s=>`<span class="chip" tabindex="0" role="button" data-s="${s}">
    <span class="dot" style="background:${cvar(s)}"></span>${s} <span class="n">${t[s]||0}</span></span>`).join('');
  $('chips').querySelectorAll('.chip').forEach(c=>{
    const toggle=()=>{const s=c.dataset.s;
      if(active.has(s)){active.delete(s);c.classList.add('off');}
      else{active.add(s);c.classList.remove('off');}
      c.setAttribute('aria-pressed',active.has(s)?'true':'false');renderSessions();};
    c.onclick=toggle;
    c.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}};
  });
}
renderHead();renderSpectrum();renderChips();renderRecs();renderSessions();
$('q').addEventListener('input',renderSessions);
"""

_JS = _JS1 + _JS2 + _JS3

_PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope Report</title>
<style>__CSS__</style></head><body>
<div class="wrap">
  <section class="mast">
    <div class="mast-grade">
      <div class="verdict" id="verdict"></div>
      <div class="gradeMon" id="gradeMon">·</div>
      <div class="scoreLine"><span id="scoreNum">0</span><span class="of">/100</span></div>
    </div>
    <div class="mast-body">
      <h1>Cryptographic posture</h1>
      <div class="sub" id="meta"></div>
      <div class="spectrum" id="spectrum" aria-hidden="true"></div>
      <div class="chips" id="chips"></div>
    </div>
  </section>

  <section>
    <h2>Prioritized remediations</h2>
    <div id="recs"></div>
  </section>

  <section>
    <div class="sec-head">
      <h2>Sessions</h2>
      <input class="search" id="q" type="search" aria-label="Filter sessions"
        placeholder="filter by protocol, cipher or finding">
    </div>
    <div id="sessions"></div>
  </section>

  <footer>
    Passive forensic analysis. No credentials were used and no live host was contacted.<br>
    Generated offline by SecureMailScope.
  </footer>
</div>
<script>const DATA=__SMS_DATA__;
__JS__
</script></body></html>"""

def render(result) -> str:
    """Render a full analysis result into a single self-contained HTML string."""
    data = json.dumps(full_dict(result), default=str).replace("</", "<\\/")
    return (_PAGE.replace("__CSS__", _CSS)
                 .replace("__JS__", _JS)
                 .replace("__SMS_DATA__", data))


def write(result, path: str) -> str:
    """Render the report and write it to `path`. Returns the path."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return path

