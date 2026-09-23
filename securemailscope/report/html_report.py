"""Self-contained interactive HTML report. Data, CSS and JS are inlined into a
single file that opens offline in any browser — the shareable artifact for the
zero-credential demo. Shows overall posture, prioritized recommendations and a
per-session drill-down with client-side severity filtering and search.
"""
from __future__ import annotations

import json

from ..analysis.engine import full_dict

_CSS = r"""
:root{--bg:#0e1117;--panel:#161b22;--panel2:#1c2230;--line:#2b3240;--txt:#e6edf3;
--mut:#8b949e;--CRITICAL:#e5484d;--HIGH:#ff8b3d;--MEDIUM:#f5d90a;--LOW:#4cc38a;
--INFO:#6e79d6;--A:#3fb950;--B:#2dd4bf;--C:#f5d90a;--D:#ff8b3d;--F:#e5484d;}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--txt)}
.wrap{max-width:1120px;margin:0 auto;padding:24px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;
gap:18px;border-bottom:1px solid var(--line);padding-bottom:18px}
h1{font-size:20px;margin:0 0 4px} h2{font-size:16px;margin:26px 0 10px}
.sub{color:var(--mut);font-size:12px}
.gauge{width:98px;height:98px;border-radius:50%;display:flex;align-items:center;
justify-content:center;background:conic-gradient(var(--gc) calc(var(--pct)*1%),#232a36 0)}
.gauge>span{width:76px;height:76px;border-radius:50%;background:var(--panel);display:flex;
flex-direction:column;align-items:center;justify-content:center}
.gnum{font-size:26px;font-weight:800;line-height:1} .glbl{font-size:10px;color:var(--mut)}
.grade{font-size:30px;font-weight:800;padding:8px 18px;border-radius:12px;color:#0b0e14}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.chip{padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;
border:1px solid var(--line);background:var(--panel);user-select:none}
.chip.off{opacity:.35} .chip b{font-weight:800}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
margin:12px 0;overflow:hidden}
.chead{display:flex;align-items:center;gap:12px;padding:13px 16px;cursor:pointer}
.chead:hover{background:var(--panel2)} .chead .sp{flex:1}
.badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:6px;color:#0b0e14}
.pill{font-size:11px;color:var(--mut);border:1px solid var(--line);padding:3px 8px;border-radius:6px}
.body{display:none;padding:0 16px 16px;border-top:1px solid var(--line)}
.card.open .body{display:block}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px 20px;
margin:14px 0;font-size:13px}
.kv div span{color:var(--mut)}
.find{border-left:3px solid var(--line);padding:9px 12px;margin:8px 0;background:var(--panel2);
border-radius:0 8px 8px 0}
.find .t{font-weight:700} .find .ev{color:var(--mut);font-size:12px;margin-top:3px}
.find .rec{font-size:12px;margin-top:5px} .find .refs{font-size:11px;color:var(--mut);margin-top:4px}
.sev{font-size:10px;font-weight:800;padding:2px 7px;border-radius:5px;color:#0b0e14;margin-right:8px}
.tb{font-size:10px;font-weight:800;padding:2px 8px;border-radius:5px;color:#0b0e14;
text-transform:uppercase;letter-spacing:.03em}
.rec-item{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:11px 14px;margin:9px 0}
.mut{color:var(--mut)} .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
input.search{background:var(--panel);border:1px solid var(--line);color:var(--txt);
border-radius:8px;padding:8px 12px;width:260px;font-size:13px}
footer{color:var(--mut);font-size:11px;text-align:center;margin-top:32px;
border-top:1px solid var(--line);padding-top:16px}
"""
_JS1 = r"""
const SEV=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const active=new Set(SEV);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const cvar=n=>getComputedStyle(document.documentElement).getPropertyValue('--'+n).trim();
const gradeColor=g=>cvar(g)||'#8b949e';
const sevBadge=s=>`<span class="sev" style="background:${cvar(s)}">${s}</span>`;
const TRUST={trusted:'#3fb950','private-ca':'#2dd4bf','self-signed':'#f5d90a',
  unanchored:'#ff8b3d',broken:'#e5484d',unverified:'#8b949e'};
const trustBadge=st=>st?`<span class="tb" style="background:${TRUST[st]||'#8b949e'}">${esc(st)}</span>`:'';

function renderHead(){
  const g=DATA.overall_grade, sc=DATA.overall_score, gz=document.getElementById('gauge');
  gz.style.setProperty('--pct',sc); gz.style.setProperty('--gc',gradeColor(g));
  gz.innerHTML=`<span><span class="gnum">${sc}</span><span class="glbl">/ 100</span></span>`;
  const gb=document.getElementById('gradeBadge'); gb.textContent=g; gb.style.background=gradeColor(g);
  document.getElementById('meta').innerHTML=
    `${esc(DATA.source)} &middot; ${DATA.session_count} session(s) &middot; v${esc(DATA.tool_version)} &middot; ${esc(DATA.generated_at)}`;
}

function renderChips(){
  const t=DATA.severity_totals, box=document.getElementById('chips');
  box.innerHTML=SEV.map(s=>`<span class="chip" data-s="${s}"><span class="dot" style="background:${cvar(s)}"></span>${s} <b>${t[s]||0}</b></span>`).join('');
  box.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{
    const s=c.dataset.s;
    if(active.has(s)){active.delete(s);c.classList.add('off');}
    else{active.add(s);c.classList.remove('off');}
    renderSessions();});
}
"""
_JS2 = r"""
function certBlock(c){
  if(!c) return '';
  if(!c.parsed) return `<div class="mut">certificate present but not parsed${c.error?': '+esc(c.error):''}</div>`;
  const w=(c.weaknesses||[]).map(x=>`<span class="pill">${esc(x)}</span>`).join(' ');
  return `<div class="kv">
    <div><span>subject</span><br>${esc(c.subject)}</div>
    <div><span>issuer</span><br>${esc(c.issuer)}</div>
    <div><span>public key</span><br>${esc(c.public_key_algo)} ${c.key_bits||''}</div>
    <div><span>signature</span><br>${esc(c.sig_hash)} ${c.self_signed?'&middot; self-signed':''}</div>
    <div><span>valid until</span><br>${esc(c.not_after)} (${c.days_to_expiry}d)</div>
    <div><span>status</span><br>${c.is_expired?'EXPIRED':(c.not_yet_valid?'not yet valid':'valid')}</div>
  </div>${w?`<div style="margin-top:6px">${w}</div>`:''}`;
}

function findingHtml(f){
  return `<div class="find" style="border-left-color:${cvar(f.severity)}">
    <div>${sevBadge(f.severity)}<span class="t">${esc(f.title)}</span>
      <span class="mut mono">${esc(f.id)}</span></div>
    <div class="ev">${esc(f.evidence)}</div>
    <div class="rec">&rarr; ${esc(f.recommendation)}</div>
    ${f.refs&&f.refs.length?`<div class="refs">${f.refs.map(esc).join(' &middot; ')}</div>`:''}
  </div>`;
}
"""
_JS3 = r"""
function sessionCard(s,i){
  const su=s.summary||{};
  const fs=s.findings.filter(f=>active.has(f.severity));
  const tls=su.tls_present?(su.negotiated_version_name||'TLS'):'no TLS';
  const head=[`${esc(s.protocol)}:${s.server_port}`,tls,esc(su.cipher_suite_name||'')].filter(Boolean).join(' &middot; ');
  const anom=s.anomaly?`<span class="pill" style="border-color:var(--HIGH);color:var(--HIGH)">anomaly ${s.anomaly_score}</span>`:'';
  const tb=su.chain_trust_status?trustBadge(su.chain_trust_status):'';
  return `<div class="card" data-i="${i}">
    <div class="chead" onclick="this.parentNode.classList.toggle('open')">
      <span class="badge" style="background:${gradeColor(s.grade)}">${s.grade}</span>
      <b>${head}</b><span class="sp"></span>
      ${tb}<span class="pill">risk ${esc(s.risk_label)}</span>${anom}
      <span class="pill">${s.score}/100</span>
      <span class="pill">${fs.length} finding(s)</span>
    </div>
    <div class="body">
      <div class="kv">
        <div><span>stream</span><br><span class="mono">${esc(s.stream)}</span></div>
        <div><span>starttls</span><br>offered ${su.starttls_offered?'yes':'no'} / used ${su.starttls_used?'yes':'no'}</div>
        <div><span>cleartext auth</span><br>${su.cleartext_auth?'YES (exposed)':'no'}</div>
        <div><span>cipher</span><br>grade ${esc(su.cipher_grade)} &middot; ${su.cipher_bits||0}b &middot; PFS ${su.cipher_pfs?'yes':'no'} &middot; AEAD ${su.cipher_aead?'yes':'no'}</div>
        <div><span>SNI</span><br>${esc(su.sni||'—')}</div>
        <div><span>ML risk</span><br>${esc(su.ml_risk||'—')} ${su.ml_confidence!=null?'('+su.ml_confidence+')':''}</div>
        ${su.chain_trust_status?`<div><span>certificate chain</span><br>${trustBadge(su.chain_trust_status)} <span class="mut">${esc(su.chain_trust_detail||'')}</span></div>`:''}
      </div>
      ${certBlock((s.certificates&&s.certificates[0])||null)}
      ${fs.length?fs.map(findingHtml).join(''):'<div class="mut">no findings at the selected severities</div>'}
    </div></div>`;
}

function renderSessions(){
  const q=(document.getElementById('q').value||'').toLowerCase();
  const rows=DATA.sessions.map((s,i)=>[s,i]).filter(([s])=>{
    if(!q) return true;
    const hay=(s.protocol+' '+s.server_port+' '+JSON.stringify(s.summary)+' '+
      s.findings.map(f=>f.title+f.id).join(' ')).toLowerCase();
    return hay.includes(q);});
  document.getElementById('sessions').innerHTML=
    rows.map(([s,i])=>sessionCard(s,i)).join('')||'<div class="mut">no sessions match</div>';
}

function renderRecs(){
  const r=DATA.recommendations||[];
  document.getElementById('recs').innerHTML=r.length?r.map(x=>
    `<div class="rec-item">${sevBadge(x.severity)}<b>${esc(x.recommendation)}</b>
     <div class="mut" style="margin-top:5px">${x.affected_streams} stream(s) &middot; ${(x.finding_ids||[]).map(esc).join(', ')}</div></div>`
  ).join(''):'<div class="mut">no remediation required &mdash; posture is clean</div>';
}

renderHead();renderChips();renderRecs();renderSessions();
document.getElementById('q').addEventListener('input',renderSessions);
"""
_JS = _JS1 + _JS2 + _JS3

_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope Report</title>
<style>__CSS__</style></head><body><div class="wrap">
<header>
  <div><h1>SecureMailScope &mdash; Cryptographic Posture Report</h1>
  <div class="sub" id="meta"></div></div>
  <div style="display:flex;gap:18px;align-items:center">
    <div class="gauge" id="gauge"></div>
    <div class="grade" id="gradeBadge"></div></div>
</header>
<div class="chips" id="chips"></div>
<h2>Prioritized recommendations</h2><div id="recs"></div>
<h2>Sessions</h2>
<input class="search" id="q" placeholder="filter sessions by protocol, cipher, finding…">
<div id="sessions"></div>
<footer>Passive forensic analysis &middot; no credentials or live hosts contacted
&middot; generated by SecureMailScope</footer>
</div><script>const DATA=__SMS_DATA__;
__JS__
</script></body></html>"""


def render(result) -> str:
    """Return a complete, standalone interactive HTML report as a string."""
    data = json.dumps(full_dict(result), default=str).replace("</", "<\\/")
    return (_PAGE.replace("__CSS__", _CSS).replace("__JS__", _JS)
            .replace("__SMS_DATA__", data))


def write(result, path: str) -> str:
    """Write the HTML report to `path`; return the path."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return path
