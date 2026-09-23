# SecureMailScope

**AI-assisted cryptographic security posture assessment for secure email (SMTP / IMAP / POP3), from passive PCAP captures.**

> SIH 2026 · Problem Statement **26159** · Org: **NTRO** · Theme: Blockchain & Cybersecurity · Category: Software

SecureMailScope is a passive network-forensic framework. Point it at a packet
capture of email traffic and it reconstructs each TLS session, extracts and
validates the X.509 certificates, detects deprecated protocols / weak ciphers /
cleartext credential exposure, then scores the cryptographic posture and emits
prioritized, standards-referenced remediations as **JSON / HTML / PDF** reports
and an **interactive dashboard**.

It is **fully passive** — it never connects to a mail server, needs no
credentials, and reads no live traffic. A built-in synthetic PCAP generator
ships a labeled corpus so the whole pipeline runs **offline with zero setup**.

---

## Highlights

- **Pure-Python capture parsing.** PCAP → Ethernet → IP → TCP reassembly →
  TLS record/handshake reconstruction, all in the standard library. No
  libpcap, tshark, scapy or dpkt required — it runs anywhere Python does.
- **Real X.509 analysis.** Key size/type, signature hash, validity window,
  self-signed / chain-completeness checks via the `cryptography` library.
- **STARTTLS-aware protocol logic.** Understands SMTP/IMAP/POP3 banners,
  STARTTLS/STLS upgrades, implicit-TLS ports, and flags cleartext `AUTH`/
  `USER`/`PASS` and STARTTLS stripping/downgrade.
- **Explainable rules engine.** Every finding carries a stable ID, severity,
  evidence, a concrete fix, and RFC/CVE references.
- **AI/ML layer.** RandomForest risk classifier + IsolationForest anomaly
  detector over an 18-dimensional feature vector, with a **deterministic
  rule-based fallback** so results are identical whether or not scikit-learn
  is installed.
- **Reports + dashboard.** Self-contained HTML, machine-readable JSON,
  printable PDF, and a local FastAPI dashboard for interactive triage.

---

## Install

Requires **Python 3.9+** (developed on 3.14). The only hard dependency is
`cryptography`; everything else is optional and degrades gracefully.

```bash
# core install (X.509 analysis + JSON/HTML reports + rule-based scoring)
pip install -e .

# everything: ML model, PDF export, dashboard
pip install -e ".[all]"

# or pick à la carte
pip install -e ".[ml]"         # scikit-learn risk model + anomaly detector
pip install -e ".[pdf]"        # reportlab PDF export
pip install -e ".[dashboard]"  # fastapi + uvicorn dashboard
```

This installs a `securemailscope` console command. Everything is also runnable
without installing, via `python -m securemailscope <subcommand>`.

## Quickstart — the zero-credential demo

One command generates the synthetic corpus, analyzes the combined capture and
writes all three report formats:

```bash
securemailscope demo
```

Output lands in `samples/`:

- `samples/pcaps/*.pcap` — the labeled synthetic captures (open cleanly in Wireshark)
- `samples/securemailscope_demo.{json,html,pdf}` — the reports

Open `samples/securemailscope_demo.html` in any browser, or launch the
dashboard (below). Add `--no-ml` to force the rule-based scorer.

---

## Command-line usage

```bash
securemailscope gen-samples [--out samples/pcaps]
securemailscope analyze <capture.pcap> [--json F] [--html F] [--pdf F]
                                       [--out-dir DIR] [--no-ml]
securemailscope demo [--out samples] [--no-ml]
securemailscope train [--out model.joblib] [-n 4000] [--seed 7]
securemailscope dashboard [--host 127.0.0.1] [--port 8000] [--samples DIR]
```

**Analyze a capture and print the posture scoreboard:**

```bash
securemailscope analyze samples/pcaps/all.pcap --out-dir out
```

```
  GRADE  SCORE  PROTO:PORT       TLS       RISK      FND  TOP FINDING
  --------------------------------------------------------------------------
  A        100  SMTP:587         TLS 1.2   minimal     1  SMS-OK
  F          2  SMTP:25          no TLS    critical    3  SMS-AUTH-CLEARTEXT
  F          6  IMAP:143         TLS 1.0   high        7  SMS-CERT_EXPIRED
  C         78  POP3:995         TLS 1.2   high        1  SMS-CIPHER-RC4
  A        100  SMTP:465         TLS 1.2   minimal     1  SMS-OK
  A        100  IMAP:993         TLS 1.3   minimal     2  SMS-CERT-ENCRYPTED
  F          2  SMTP:587         no TLS    critical    3  SMS-AUTH-CLEARTEXT
  --------------------------------------------------------------------------
  OVERALL: F (23/100) across 7 session(s)
```

`--json/--html/--pdf` write individual reports; `--out-dir` writes all three
into a directory. If `reportlab` is absent the PDF is skipped with a notice and
the other formats still succeed.

## Dashboard

```bash
securemailscope dashboard        # http://127.0.0.1:8000
```

A local FastAPI app: pick a bundled sample or upload your own `.pcap` and get
the scoreboard, per-session findings and recommendations interactively. It
binds to loopback only and runs **without authentication** — it is a local
analyst tool; do not expose it to an untrusted network.

---

## The synthetic corpus

`gen-samples` (and `demo`) write seven labeled scenarios plus a combined
`all.pcap`. Certificates are real; TLS handshakes are hand-encoded. No real
hosts or credentials are involved.

| Capture | Scenario | Posture |
|---|---|---|
| `01_smtp_starttls_good` | SMTP 587, STARTTLS → TLS 1.2 ECDHE-RSA-AES128-GCM, valid CA-issued cert | **A / 100** |
| `02_smtp_cleartext_auth` | SMTP 25, cleartext `AUTH`, no STARTTLS offered | **F / 2** |
| `03_imap_legacy_tls10` | IMAP 143, STARTTLS → TLS 1.0 CBC-SHA, expired self-signed 1024-bit cert | **F / 6** |
| `04_pop3s_rc4` | POP3S 995, implicit TLS 1.2 with RC4 | **C / 78** |
| `05_smtps_tls12_strong` | SMTPS 465, implicit TLS 1.2 ECDHE-RSA-AES256-GCM, valid cert | **A / 100** |
| `06_imaps_tls13` | IMAPS 993, implicit TLS 1.3 (Certificate is encrypted) | **A / 100** |
| `07_smtp_starttls_stripped` | SMTP 587, STARTTLS advertised but stripped; cleartext `AUTH` | **F / 2** |

Combined `all.pcap` → **OVERALL F (23/100)** across 7 sessions.

## How it works

```
 .pcap ─► pcapio ─► TCP reassembly ─► protocols ─► tls ─► certs
                                          │          │       │
                                    STARTTLS/       handshake X.509
                                    cleartext       + cipher   parse
                                    detection       suite      + weakness
                                          └──────────┼─────────┘
                                                     ▼
                                              analysis.rules  ──►  Findings
                                                     │
                                     posture scoring + ml risk/anomaly
                                                     ▼
                                        report (json / html / pdf) + dashboard
```

1. **pcapio** — parse the pcap global/record headers, Ethernet/IP/TCP, and
   reassemble each TCP stream in sequence order.
2. **protocols** — identify SMTP/IMAP/POP3 by port and banner, track the
   STARTTLS/STLS upgrade boundary, and flag pre-TLS cleartext credentials.
3. **tls** — walk TLS records and handshake messages; decode the negotiated
   version and cipher suite (with weakness tags: RC4, CBC, NO_PFS, …).
4. **certs** — parse the presented X.509 chain and tag weaknesses (key size,
   signature hash, expiry, self-signed, incomplete chain).
5. **analysis** — the rules engine turns those facts into graded findings;
   posture scoring rolls them into a per-session and overall grade.
6. **ml** — augments each session with a risk label + anomaly flag.
7. **report / dashboard** — render the results.

---

## Scoring model

Each finding carries a severity; the session score starts at 100 and deducts a
penalty per finding, clamped to `[0, 100]`:

| Severity | Penalty |
|---|---|
| INFO | 0 |
| LOW | 4 |
| MEDIUM | 10 |
| HIGH | 22 |
| CRITICAL | 38 |

Grades: **A** ≥ 90 · **B** ≥ 80 · **C** ≥ 70 · **D** ≥ 60 · **F** < 60.

The overall score weights the weakest link:
`round(0.6 × worst_session + 0.4 × mean_session)`, clamped — one badly broken
session drags the whole posture down, as it should for a security assessment.

## Findings catalogue

Protocol / transport:

| ID | Severity | Meaning |
|---|---|---|
| `SMS-AUTH-CLEARTEXT` | CRITICAL | Credentials sent before encryption |
| `SMS-TLS-ABSENT` | CRITICAL | No TLS on the email session |
| `SMS-STARTTLS-STRIPPED` | HIGH | STARTTLS advertised but session stayed cleartext |
| `SMS-NO-STARTTLS` | HIGH | No STARTTLS offered on a cleartext port |

TLS version:

| ID | Severity | Meaning |
|---|---|---|
| `SMS-SSL-OBSOLETE` | CRITICAL | SSL 2.0/3.0 (POODLE/DROWN) |
| `SMS-TLS-DEPRECATED` | HIGH | TLS 1.0/1.1 (RFC 8996) |
| `SMS-TLS13` | INFO | Modern TLS 1.3 negotiated |

Cipher suite (`SMS-CIPHER-<TAG>`):

| Tag | Severity | Meaning |
|---|---|---|
| `NULL_CIPHER` / `NO_ENCRYPTION` / `EXPORT` | CRITICAL | No/negligible confidentiality |
| `RC4` / `MD5` | HIGH | Broken stream cipher / MAC |
| `3DES` / `NO_PFS` | MEDIUM | SWEET32 / no forward secrecy |
| `CBC` / `SHA1_MAC` | LOW | BEAST/Lucky13 class / SHA-1 MAC |
| `UNKNOWN` | LOW | Suite not in the known registry |

Certificate (`SMS-<TAG>`):

| Tag | Severity | Meaning |
|---|---|---|
| `VERY_WEAK_RSA_KEY` / `MD5_SIG` | CRITICAL | RSA < 1024 / MD5 signature |
| `WEAK_RSA_KEY` / `WEAK_EC_KEY` / `SHA1_SIG` / `CERT_EXPIRED` | HIGH | Weak key/sig or expired |
| `DSA_KEY` / `CERT_NOT_YET_VALID` / `SELF_SIGNED` / `CERT_PARSE_ERROR` | MEDIUM | — |
| `CERT_EXPIRING_SOON` / `CHAIN_INCOMPLETE` | LOW | Renew soon / serve intermediates |
| `SMS-CERT-ENCRYPTED` / `SMS-CERT_NOT_ANALYZED` | INFO | TLS 1.3 encrypts cert / `cryptography` absent |

`SMS-OK` (INFO) is emitted when a session has no weaknesses.

---

## AI / ML layer

Each session is reduced to an **18-dimensional feature vector** (TLS presence
and version, cipher weakness flags, key size, cert validity, cleartext-auth
flag, finding-severity counts, …). Two models run over it:

- a **RandomForest** risk classifier → `minimal / low / medium / high / critical`
- an **IsolationForest** anomaly detector → outlier flag + score

Train and persist a model (needs the `ml` extra):

```bash
securemailscope train --out model.joblib
```

If scikit-learn or a trained model is absent, a **deterministic rule-based
scorer** produces the same label set from the finding severities, so a fresh
clone gives correct, reproducible results with no ML install. The ML layer
**augments** the explainable rules — it never overrides them.

## Project layout

```
securemailscope/
  pcapio/       pcap read/write + Ethernet/IP/TCP parse + stream reassembly
  protocols/    SMTP/IMAP/POP3 detection, STARTTLS + cleartext-auth logic
  tls/          TLS record/handshake parsing, cipher-suite registry
  certs/        X.509 parsing and weakness analysis (cryptography)
  analysis/     rules engine, posture scoring, recommendation aggregation
  ml/           feature extraction, risk/anomaly model + rule fallback
  report/       json / html / pdf writers
  dashboard/    local FastAPI app
  samples/      synthetic certificate + PCAP generator (tlsgen, generate)
  cli.py        command-line entry point
tests/          stdlib unittest suite (also pytest-collectable)
```

## Testing

The suite runs on the **standard library only** — no pytest required:

```bash
python -m unittest discover -s tests -t .
```

It locks the posture scoreboard for all seven scenarios plus the combined
capture, and covers the TLS/cipher decoding, certificate analysis, rules,
scoring, recommendation de-duplication, report writers and the ML model.
(`pytest` also collects it as-is if you prefer.)

## Security & privacy

- **Fully passive & offline.** No connections to mail servers, no credentials,
  no live capture. It only reads `.pcap` files you give it.
- **The dashboard is unauthenticated and loopback-bound** — a local analyst
  tool, not a service to expose.
- Real captures may contain sensitive data (cleartext credentials are exactly
  what this tool surfaces). Handle input pcaps and generated reports as
  sensitive material.

## Limitations

- TLS 1.3 encrypts the Certificate message, so certificates cannot be
  extracted passively from a 1.3 session (reported as `SMS-CERT-ENCRYPTED`).
- Certificate *trust-chain validation against a root store* is out of scope;
  analysis covers structure, key/signature strength, validity and
  self-signed/completeness — not path validation to a trusted anchor.

## License

MIT.





