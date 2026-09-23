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
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0e1117;color:#e6edf3}
header{padding:14px 20px;border-bottom:1px solid #2b3240;display:flex;justify-content:space-between;align-items:center}
h1{font-size:17px;margin:0}.sub{color:#8b949e;font-size:12px}
.layout{display:flex;height:calc(100vh - 62px)}
.side{width:300px;border-right:1px solid #2b3240;padding:14px;overflow:auto}
.main{flex:1;display:flex;flex-direction:column;min-width:0}
.bar{padding:8px 14px;border-bottom:1px solid #2b3240;display:flex;gap:8px;align-items:center}
.bar .sp{flex:1}
button,.btn{background:#1f6feb;border:0;color:#fff;padding:7px 12px;border-radius:7px;font-size:13px;cursor:pointer;text-decoration:none}
.btn.ghost{background:#161b22;border:1px solid #2b3240;color:#e6edf3}
.samp{display:block;width:100%;text-align:left;background:#161b22;border:1px solid #2b3240;color:#e6edf3;padding:9px 11px;border-radius:8px;margin:7px 0;cursor:pointer}
.samp:hover{border-color:#1f6feb}.samp small{color:#8b949e;display:block}
iframe{flex:1;border:0;background:#0e1117;width:100%}
.hint{color:#8b949e;font-size:12px;margin:12px 4px 4px}
</style></head><body>
<header><div><h1>SecureMailScope</h1>
<div class="sub">Passive cryptographic posture assessment &middot; local console, no authentication</div></div>
</header>
<div class="layout"><div class="side">
<button class="btn" id="up">Upload PCAP&hellip;</button>
<input type="file" id="file" accept=".pcap,.pcapng" style="display:none">
<div class="hint">Bundled samples</div><div id="list"></div>
</div><div class="main">
<div class="bar"><b id="cur">Select a capture to analyze</b><span class="sp"></span>
<a class="btn ghost" id="dljson" target="_blank" rel="noopener">JSON</a>
<a class="btn ghost" id="dlpdf" target="_blank" rel="noopener">PDF</a></div>
<iframe id="rep" title="analysis report"></iframe>
</div></div>"""
_SCRIPT = r"""<script>
const $=s=>document.querySelector(s);
function setReport(qs,label){
  $('#rep').src='/report?'+qs+'&fmt=html';
  $('#cur').textContent=label;
  $('#dljson').href='/report?'+qs+'&fmt=json';
  $('#dlpdf').href='/report?'+qs+'&fmt=pdf';
}
async function loadSamples(){
  try{
    const d=await (await fetch('/api/samples')).json();
    $('#list').innerHTML=(d.samples||[]).map(s=>
      `<button class="samp" data-rel="${encodeURIComponent(s.rel)}">${s.name}`+
      `<small>${(s.size/1024).toFixed(1)} KiB</small></button>`).join('')
      ||'<div class="hint">no samples — run <code>gen-samples</code> first</div>';
    document.querySelectorAll('.samp').forEach(b=>b.onclick=()=>
      setReport('path='+b.dataset.rel,b.textContent));
  }catch(e){$('#list').innerHTML='<div class="hint">could not load samples</div>';}
}
$('#up').onclick=()=>$('#file').click();
$('#file').onchange=async e=>{
  const f=e.target.files[0]; if(!f) return;
  $('#cur').textContent='Uploading & analyzing '+f.name+'…';
  try{
    const r=await fetch('/api/upload',{method:'POST',body:await f.arrayBuffer()});
    if(!r.ok){$('#cur').textContent='upload failed ('+r.status+')';return;}
    const d=await r.json(); setReport('token='+d.token, f.name+' (uploaded)');
  }catch(e){$('#cur').textContent='upload error';}
};
loadSamples();
</script></body></html>"""

_PAGE = _HEAD + _SCRIPT




