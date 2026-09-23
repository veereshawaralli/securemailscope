"""Interactive analysis dashboard (FastAPI). Binds to localhost only and serves
an offline console: pick a bundled sample or upload a PCAP, view the full
interactive HTML report inline, and download JSON / PDF.

SECURITY: this server has NO authentication and analyzes any PCAP it is given.
It is a local single-user forensic console — keep the bind address on 127.0.0.1
and do not expose it to an untrusted network.
"""
from __future__ import annotations

import os
import tempfile
import uuid

from ..analysis.engine import analyze, full_dict
from ..ml.model import load_default
from ..report import html_report

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    _HAVE_FASTAPI = True
except Exception:                # pragma: no cover
    _HAVE_FASTAPI = False

_MAX_UPLOAD = 64 * 1024 * 1024   # 64 MiB cap on uploaded captures
_ML = None


def _ml():
    global _ML
    if _ML is None:
        _ML = load_default()
    return _ML


def _safe_sample(samples_dir: str, rel: str) -> str:
    """Resolve `rel` under samples_dir, refusing path traversal escapes."""
    base = os.path.realpath(samples_dir)
    p = os.path.realpath(os.path.join(base, rel))
    if p != base and not p.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="invalid path")
    if not os.path.isfile(p):
        raise HTTPException(status_code=404, detail="sample not found")
    return p
def create_app(samples_dir: str = "samples/pcaps"):
    """Build the FastAPI app serving the dashboard and analysis endpoints."""
    if not _HAVE_FASTAPI:
        raise RuntimeError("fastapi/uvicorn not installed; run "
                           "`pip install fastapi uvicorn`")
    app = FastAPI(title="SecureMailScope", docs_url=None, redoc_url=None)
    uploads: dict = {}
    tmp = tempfile.mkdtemp(prefix="sms-dash-")

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _PAGE

    @app.get("/api/samples")
    def samples():
        out = []
        if os.path.isdir(samples_dir):
            for n in sorted(os.listdir(samples_dir)):
                if n.endswith(".pcap"):
                    p = os.path.join(samples_dir, n)
                    out.append({"name": n, "rel": n, "size": os.path.getsize(p)})
        return {"samples": out}

    @app.post("/api/upload")
    async def upload(request: Request):
        data = await request.body()
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="capture too large")
        tok = uuid.uuid4().hex
        path = os.path.join(tmp, tok + ".pcap")
        with open(path, "wb") as fh:
            fh.write(data)
        uploads[tok] = path
        return {"token": tok, "size": len(data)}

    def _resolve(path: str, token: str):
        if token:
            p = uploads.get(token)
            if not p:
                raise HTTPException(status_code=404, detail="unknown upload token")
            return p, "upload:" + token[:8]
        if path:
            return _safe_sample(samples_dir, path), path
        raise HTTPException(status_code=400, detail="path or token required")
    @app.get("/report")
    def report(path: str = "", token: str = "", fmt: str = "html"):
        p, label = _resolve(path, token)
        res = analyze(p, ml=_ml())
        res.source = label
        if fmt == "json":
            return JSONResponse(full_dict(res))
        if fmt == "pdf":
            from ..report import pdf_report
            fd, tp = tempfile.mkstemp(suffix=".pdf")
            os.close(fd)
            try:
                pdf_report.write(res, tp)
                with open(tp, "rb") as fh:
                    blob = fh.read()
            finally:
                os.remove(tp)
            return Response(blob, media_type="application/pdf", headers={
                "Content-Disposition": 'inline; filename="securemailscope.pdf"'})
        return HTMLResponse(html_report.render(res))

    return app


def serve(host: str = "127.0.0.1", port: int = 8000,
          samples_dir: str = "samples/pcaps") -> int:
    """Run the dashboard with uvicorn (blocking). Localhost by default."""
    try:
        import uvicorn
    except Exception:            # pragma: no cover
        print("[dashboard] uvicorn not installed; run `pip install uvicorn`")
        return 1
    app = create_app(samples_dir)
    print(f"SecureMailScope dashboard -> http://{host}:{port}  "
          f"(local only, no authentication)")
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0
_HEAD = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope Dashboard</title><style>
:root{--bg:#0d1117;--bg2:#0a0e14;--panel:#161b22;--panel2:#1c2230;--line:#2b3240;
--txt:#e6edf3;--mut:#8b949e;--brand:#1f6feb;--brand2:#388bfd;--good:#3fb950}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;
background:var(--bg);color:var(--txt)}
header{padding:14px 22px;border-bottom:1px solid var(--line);display:flex;
justify-content:space-between;align-items:center;gap:16px;
background:linear-gradient(90deg,#10151d,#0d1117)}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:34px;height:34px;border-radius:9px;color:#fff;font-weight:800;font-size:16px;
display:flex;align-items:center;justify-content:center;
background:linear-gradient(135deg,var(--brand),#7aa2ff);box-shadow:0 2px 10px rgba(31,111,235,.45)}
h1{font-size:17px;margin:0;letter-spacing:.2px}
.sub{color:var(--mut);font-size:12px;margin-top:1px}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:11px;color:var(--mut);border:1px solid var(--line);background:var(--panel);
padding:3px 9px;border-radius:20px}
.tag b{color:var(--good)}
.layout{display:flex;height:calc(100vh - 66px)}
.side{width:300px;border-right:1px solid var(--line);padding:14px;overflow:auto;background:var(--bg2)}
.main{flex:1;display:flex;flex-direction:column;min-width:0;position:relative}
.bar{padding:9px 16px;border-bottom:1px solid var(--line);display:flex;gap:8px;align-items:center}
.bar .sp{flex:1}
button,.btn{background:var(--brand);border:0;color:#fff;padding:7px 13px;border-radius:8px;
font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;transition:.15s}
button:hover,.btn:hover{background:var(--brand2)}
.btn.ghost{background:var(--panel);border:1px solid var(--line);color:var(--txt)}
.btn.ghost:hover{border-color:var(--brand)}
.btn.dis{opacity:.4;pointer-events:none}
.up{display:block;width:100%;text-align:center;padding:16px 12px;border:1.5px dashed #34405a;
border-radius:11px;background:var(--panel);cursor:pointer;transition:.15s}
.up:hover,.up.drag{border-color:var(--brand);background:var(--panel2)}
.up b{display:block;font-size:13px}.up small{color:var(--mut)}
.hint{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin:16px 4px 8px}
.samp{display:block;width:100%;text-align:left;background:var(--panel);border:1px solid var(--line);
color:var(--txt);padding:10px 12px;border-radius:9px;margin:7px 0;cursor:pointer;transition:.15s}
.samp:hover{border-color:var(--brand);transform:translateX(2px)}
.samp.active{border-color:var(--brand);box-shadow:inset 0 0 0 1px var(--brand)}
.samp b{font-size:13px}.samp small{color:var(--mut);display:block;margin-top:2px}
.stage{flex:1;position:relative;min-height:0}
iframe{position:absolute;inset:0;border:0;background:var(--bg);width:100%;height:100%}
.overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
justify-content:center;text-align:center;padding:30px;background:var(--bg)}
.overlay.hide{display:none}
.spin{width:36px;height:36px;border-radius:50%;border:3px solid var(--line);
border-top-color:var(--brand);animation:sp .8s linear infinite;margin-bottom:14px}
@keyframes sp{to{transform:rotate(360deg)}}
.emphd{font-size:16px;font-weight:700;margin-bottom:6px}
.empsub{color:var(--mut);max-width:440px;line-height:1.6}
.emp-logo{width:56px;height:56px;border-radius:14px;margin-bottom:16px;
background:linear-gradient(135deg,var(--brand),#7aa2ff);display:flex;align-items:center;
justify-content:center;font-weight:800;color:#fff;font-size:24px}
@media(max-width:760px){.side{width:200px}}
</style></head><body>
<header>
  <div class="brand"><div class="logo">S</div>
    <div><h1>SecureMailScope</h1>
    <div class="sub">Passive cryptographic posture assessment for secure email</div></div></div>
  <div class="tags"><span class="tag"><b>&#9679;</b> passive</span>
    <span class="tag">offline</span><span class="tag">no&nbsp;auth &middot; localhost</span></div>
</header>
<div class="layout"><div class="side">
  <label class="up" id="up"><b>Upload a PCAP</b><small>click or drop a .pcap / .pcapng file</small></label>
  <input type="file" id="file" accept=".pcap,.pcapng" style="display:none">
  <div class="hint">Bundled samples</div><div id="list"></div>
</div><div class="main">
  <div class="bar"><b id="cur">No capture selected</b><span class="sp"></span>
  <a class="btn ghost dis" id="dljson" target="_blank" rel="noopener">JSON</a>
  <a class="btn ghost dis" id="dlpdf" target="_blank" rel="noopener">PDF</a></div>
  <div class="stage">
    <iframe id="rep" title="analysis report"></iframe>
    <div class="overlay" id="empty"><div class="emp-logo">S</div>
      <div class="emphd">Select a capture to begin</div>
      <div class="empsub">Pick a bundled scenario from the left, or upload your own PCAP.
      SecureMailScope reconstructs each TLS session, validates certificates and their
      chains, and scores the cryptographic posture &mdash; entirely offline.</div></div>
    <div class="overlay hide" id="loading"><div class="spin"></div>
      <div class="empsub">Analyzing capture&hellip;</div></div>
  </div>
</div></div>"""
_SCRIPT = r"""<script>
const $=s=>document.querySelector(s);
const rep=$('#rep'),empty=$('#empty'),loading=$('#loading');
const pretty=n=>n.replace(/\.pcap[a-z]*$/i,'').replace(/^\d+[_-]?/,'')
  .replace(/[_-]+/g,' ').replace(/\b\w/g,c=>c.toUpperCase())||n;
const busy=on=>loading.classList.toggle('hide',!on);
rep.addEventListener('load',()=>{if(rep.getAttribute('src'))busy(false);});
function setReport(qs,label){
  empty.classList.add('hide');busy(true);
  rep.src='/report?'+qs+'&fmt=html';
  $('#cur').textContent=label;
  const j=$('#dljson'),p=$('#dlpdf');
  j.href='/report?'+qs+'&fmt=json';p.href='/report?'+qs+'&fmt=pdf';
  j.classList.remove('dis');p.classList.remove('dis');
}
async function loadSamples(){
  try{
    const d=await (await fetch('/api/samples')).json();
    $('#list').innerHTML=(d.samples||[]).map(s=>
      `<button class="samp" data-rel="${encodeURIComponent(s.rel)}" data-label="${s.name}">`+
      `<b>${pretty(s.name)}</b><small>${s.name} &middot; ${(s.size/1024).toFixed(1)} KiB</small></button>`).join('')
      ||'<div class="hint">no samples &mdash; run <code>gen-samples</code> first</div>';
    document.querySelectorAll('.samp').forEach(b=>b.onclick=()=>{
      document.querySelectorAll('.samp').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      setReport('path='+b.dataset.rel,b.dataset.label);});
  }catch(e){$('#list').innerHTML='<div class="hint">could not load samples</div>';}
}
async function uploadFile(f){
  if(!f) return;
  document.querySelectorAll('.samp').forEach(x=>x.classList.remove('active'));
  empty.classList.add('hide');busy(true);$('#cur').textContent='Uploading '+f.name+'…';
  try{
    const r=await fetch('/api/upload',{method:'POST',body:await f.arrayBuffer()});
    if(!r.ok){busy(false);$('#cur').textContent='upload failed ('+r.status+')';return;}
    const d=await r.json(); setReport('token='+d.token, f.name+' (uploaded)');
  }catch(e){busy(false);$('#cur').textContent='upload error';}
}
$('#up').onclick=()=>$('#file').click();
$('#file').onchange=e=>uploadFile(e.target.files[0]);
const up=$('#up');
['dragenter','dragover'].forEach(ev=>up.addEventListener(ev,e=>{e.preventDefault();up.classList.add('drag');}));
['dragleave','drop'].forEach(ev=>up.addEventListener(ev,e=>{e.preventDefault();up.classList.remove('drag');}));
up.addEventListener('drop',e=>{if(e.dataTransfer.files.length)uploadFile(e.dataTransfer.files[0]);});
loadSamples();
</script></body></html>"""

_PAGE = _HEAD + _SCRIPT




