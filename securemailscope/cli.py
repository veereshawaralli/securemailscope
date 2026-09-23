"""SecureMailScope command-line interface.

Subcommands:
  gen-samples   write the synthetic PCAP corpus (zero-credential demo data)
  analyze       analyze a PCAP and print a scoreboard; optionally write reports
  train         train and persist the ML risk model (optional, needs sklearn)
  dashboard     launch the local interactive dashboard (needs fastapi/uvicorn)
  demo          end-to-end: generate samples, analyze the combined capture and
                write JSON + HTML + PDF reports
"""
from __future__ import annotations

import argparse
import os
import sys

from .version import __version__

_TLS_COL = {True: "", False: "no TLS"}


def _tls_label(su: dict) -> str:
    if not su.get("tls_present"):
        return "no TLS"
    return su.get("negotiated_version_name") or "TLS"


def _print_scoreboard(result) -> None:
    """Print a compact per-session table plus the rolled-up posture."""
    print(f"\n  source : {result.source}")
    print(f"  {'GRADE':5}  {'SCORE':>5}  {'PROTO:PORT':<16} {'TLS':<9} "
          f"{'RISK':<9} {'FND':>3}  TOP FINDING")
    print("  " + "-" * 74)
    for s in result.sessions:
        top = s.findings[0].id if s.findings else "-"
        proto = f"{s.protocol}:{s.server_port}"
        print(f"  {s.grade:<5}  {s.score:>5}  {proto:<16} "
              f"{_tls_label(s.summary):<9} {s.risk_label:<9} "
              f"{len(s.findings):>3}  {top}")
    print("  " + "-" * 74)
    print(f"  OVERALL: {result.overall_grade} ({result.overall_score}/100) "
          f"across {len(result.sessions)} session(s)\n")
def _write_reports(result, *, json_path=None, html_path=None, pdf_path=None,
                   out_dir=None, base=None) -> None:
    """Write any requested report formats, degrading if reportlab is absent."""
    from . import report
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        base = base or "report"
        json_path = json_path or os.path.join(out_dir, base + ".json")
        html_path = html_path or os.path.join(out_dir, base + ".html")
        pdf_path = pdf_path or os.path.join(out_dir, base + ".pdf")
    for path, fmt in ((json_path, "json"), (html_path, "html"),
                      (pdf_path, "pdf")):
        if not path:
            continue
        try:
            report.write(result, path, fmt=fmt)
            print(f"  wrote {fmt.upper():4} -> {path}")
        except Exception as e:                       # e.g. reportlab missing
            print(f"  skip  {fmt.upper():4} ({e})")


def _cmd_gen_samples(a) -> int:
    from .samples.generate import generate
    paths = generate(a.out)
    print(f"wrote {len(paths)} pcap(s) to {a.out}:")
    for p in paths:
        print("  ", os.path.basename(p))
    return 0


def _cmd_analyze(a) -> int:
    from .analysis.engine import analyze
    ml = None
    if not a.no_ml:
        from .ml.model import load_default
        ml = load_default()
        if not ml.ml_backed:
            print("  [ml] no trained model found — using rule-based fallback")
    if not os.path.isfile(a.pcap):
        print(f"error: no such file: {a.pcap}", file=sys.stderr)
        return 2
    result = analyze(a.pcap, ml=ml)
    _print_scoreboard(result)
    base = os.path.splitext(os.path.basename(a.pcap))[0]
    _write_reports(result, json_path=a.json, html_path=a.html, pdf_path=a.pdf,
                   out_dir=a.out_dir, base=base)
    return 0
def _cmd_train(a) -> int:
    from .ml.train import train
    return train(a.out, a.n, a.seed)


def _cmd_dashboard(a) -> int:
    try:
        from .dashboard import get_serve
        serve = get_serve()
    except Exception as e:
        print(f"error: dashboard unavailable ({e})", file=sys.stderr)
        print("install it with: pip install fastapi uvicorn", file=sys.stderr)
        return 2
    return serve(host=a.host, port=a.port, samples_dir=a.samples)


def _cmd_demo(a) -> int:
    from .analysis.engine import analyze
    from .samples.generate import generate
    print("[1/3] generating synthetic PCAP corpus ...")
    paths = generate(os.path.join(a.out, "pcaps"))
    combined = [p for p in paths if p.endswith("all.pcap")][0]
    print(f"      {len(paths)} captures in {os.path.join(a.out, 'pcaps')}")
    ml = None
    if not a.no_ml:
        from .ml.model import load_default
        ml = load_default()
    print("[2/3] analyzing combined capture ...")
    result = analyze(combined, ml=ml)
    _print_scoreboard(result)
    print("[3/3] writing reports ...")
    _write_reports(result, out_dir=a.out, base="securemailscope_demo")
    print(f"\nDemo complete. Open {os.path.join(a.out, 'securemailscope_demo.html')} "
          f"in a browser, or run: securemailscope dashboard")
    return 0
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="securemailscope",
        description="AI-assisted cryptographic posture assessment for email "
                    "(SMTP/IMAP/POP3) from passive PCAP captures.")
    p.add_argument("--version", action="version",
                   version=f"securemailscope {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-samples", help="write the synthetic PCAP corpus")
    g.add_argument("--out", default="samples/pcaps", help="output directory")
    g.set_defaults(func=_cmd_gen_samples)

    an = sub.add_parser("analyze", help="analyze a PCAP and score its posture")
    an.add_argument("pcap", help="path to a .pcap file")
    an.add_argument("--json", help="write JSON report to this path")
    an.add_argument("--html", help="write HTML report to this path")
    an.add_argument("--pdf", help="write PDF report to this path")
    an.add_argument("--out-dir", dest="out_dir",
                    help="write JSON+HTML+PDF into this directory")
    an.add_argument("--no-ml", action="store_true",
                    help="skip the ML model (rules only)")
    an.set_defaults(func=_cmd_analyze)

    tr = sub.add_parser("train", help="train and save the ML risk model")
    tr.add_argument("--out", default=None, help="model output path (.joblib)")
    tr.add_argument("-n", type=int, default=4000, help="synthetic sample count")
    tr.add_argument("--seed", type=int, default=7, help="random seed")
    tr.set_defaults(func=_cmd_train)

    db = sub.add_parser("dashboard", help="launch the local dashboard")
    db.add_argument("--host", default="127.0.0.1", help="bind address")
    db.add_argument("--port", type=int, default=8000, help="port")
    db.add_argument("--samples", default="samples/pcaps",
                    help="directory of bundled sample pcaps")
    db.set_defaults(func=_cmd_dashboard)

    dm = sub.add_parser("demo", help="generate + analyze + report, end to end")
    dm.add_argument("--out", default="samples", help="output directory")
    dm.add_argument("--no-ml", action="store_true", help="rules only")
    dm.set_defaults(func=_cmd_demo)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":        # pragma: no cover
    raise SystemExit(main())



