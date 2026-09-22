"""Synthetic PCAP generator: writes a set of labeled SMTP/IMAP/POP3 captures
covering strong, deprecated and broken cryptographic postures. Certificates are
real; TLS handshakes are hand-encoded. Output opens cleanly in Wireshark and
feeds the zero-credential offline demo. No real hosts or credentials involved.
"""
from __future__ import annotations

import os

from ..pcapio.writer import (PcapWriter, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN,
                             tcp_frame)
from . import tlsgen as T

CLIENT_IP = "10.0.0.5"
SERVER_IP = "10.0.0.10"


def _emit(w, t, src, dst, sp, dp, seq, data, from_client):
    off = 0
    while off < len(data):
        chunk = data[off:off + 1400]
        w.write(t, tcp_frame(src, dst, sp, dp, seq + off, 1,
                             TCP_PSH | TCP_ACK, chunk, from_client))
        off += len(chunk)
        t += 0.0006
    return t


def _write_pcap(path, cport, sport, cdata, sdata):
    with PcapWriter(path) as w:
        w.write(0.0, tcp_frame(CLIENT_IP, SERVER_IP, cport, sport, 1000, 0,
                               TCP_SYN, b"", True))
        w.write(0.001, tcp_frame(SERVER_IP, CLIENT_IP, sport, cport, 5000,
                                 1001, TCP_SYN | TCP_ACK, b"", False))
        t = _emit(w, 0.002, SERVER_IP, CLIENT_IP, sport, cport, 5001, sdata,
                  False)
        t = _emit(w, t, CLIENT_IP, SERVER_IP, cport, sport, 1001, cdata, True)
        w.write(t + 0.001, tcp_frame(CLIENT_IP, SERVER_IP, cport, sport,
                                     1001 + len(cdata), 1, TCP_FIN | TCP_ACK,
                                     b"", True))


def _build_certs() -> dict:
    ca_key = T.gen_key("rsa4096")
    ca = T.make_cert("Example Root CA", ca_key, "Example Root CA", ca_key,
                     days_from=-800, days_to=3000, ca=True)
    leaf_key = T.gen_key("rsa2048")
    good = T.make_cert("mail.example.com", leaf_key, "Example Root CA", ca_key,
                       days_from=-30, days_to=365,
                       sans=["mail.example.com", "smtp.example.com"])
    weak_key = T.gen_key("rsa1024")
    weak = T.make_cert("mail.legacy.example", weak_key, "mail.legacy.example",
                       weak_key, days_from=-800, days_to=-10, sig="sha1")
    return {"ca": ca, "good": good, "weak": weak}


# scenario name -> (severity headline) for the manifest/README
SCENARIOS = [
    "01_smtp_starttls_good", "02_smtp_cleartext_auth", "03_imap_legacy_tls10",
    "04_pop3s_rc4", "05_smtps_tls12_strong", "06_imaps_tls13",
    "07_smtp_starttls_stripped",
]


def generate(outdir: str = "samples/pcaps") -> list:
    """Write every scenario pcap (plus a combined all.pcap). Returns paths."""
    os.makedirs(outdir, exist_ok=True)
    c = _build_certs()
    strong12 = [0xC02F, 0xC030, 0x009C]
    written = []

    def emit(name, cport, sport, cdata, sdata):
        p = os.path.join(outdir, name + ".pcap")
        _write_pcap(p, cport, sport, cdata, sdata)
        written.append(p)

    # 1) SMTP submission (587) STARTTLS -> TLS 1.2 ECDHE-RSA-AES128-GCM, valid cert
    cs = b"EHLO client.example.org\r\nSTARTTLS\r\n"
    ss = (b"220 mail.example.com ESMTP Postfix\r\n250-mail.example.com\r\n"
          b"250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n220 2.0.0 Ready to start TLS\r\n")
    ch = T.client_hello(0x0303, strong12, sni="mail.example.com",
                        groups=[0x0017, 0x001d])
    sh = T.server_hello(0x0303, 0xC02F)
    ct = T.certificate([c["good"], c["ca"]])
    emit("01_smtp_starttls_good", 40001, 587, cs + ch, ss + sh + ct)

    # 2) SMTP (25) cleartext AUTH, no STARTTLS offered
    cs = b"EHLO client\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\n"
    ss = (b"220 mail.plain.example ESMTP\r\n250-mail.plain.example\r\n"
          b"250 AUTH LOGIN PLAIN\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n"
          b"235 2.7.0 Authentication successful\r\n")
    emit("02_smtp_cleartext_auth", 40002, 25, cs, ss)

    # 3) IMAP (143) STARTTLS -> TLS 1.0 RSA-AES128-CBC-SHA, expired self-signed SHA1/1024 cert
    cs = b"a1 STARTTLS\r\n"
    ss = (b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready\r\n"
          b"a1 OK Begin TLS negotiation now\r\n")
    ch = T.client_hello(0x0301, [0x002F, 0x0035], sni="mail.legacy.example")
    sh = T.server_hello(0x0301, 0x002F)
    ct = T.certificate([c["weak"]])
    emit("03_imap_legacy_tls10", 40003, 143, cs + ch, ss + sh + ct)

    # 4) POP3S (995) implicit TLS 1.2 with RC4 (ECDHE-RSA-RC4-SHA)
    ch = T.client_hello(0x0303, [0xC011, 0xC013], sni="pop.example.com",
                        groups=[0x0017])
    sh = T.server_hello(0x0303, 0xC011)
    ct = T.certificate([c["good"], c["ca"]])
    emit("04_pop3s_rc4", 40004, 995, ch, sh + ct)

    # 5) SMTPS (465) implicit TLS 1.2 ECDHE-RSA-AES256-GCM, valid cert
    ch = T.client_hello(0x0303, strong12, sni="mail.example.com",
                        groups=[0x0017, 0x001d])
    sh = T.server_hello(0x0303, 0xC030)
    ct = T.certificate([c["good"], c["ca"]])
    emit("05_smtps_tls12_strong", 40005, 465, ch, sh + ct)

    # 6) IMAPS (993) implicit TLS 1.3 (cert is encrypted -> not extractable)
    ch = T.client_hello(0x0303, [0x1301, 0x1302, 0x1303],
                        sni="imap.example.com", supported_versions=[0x0304, 0x0303],
                        groups=[0x001d, 0x0017])
    sh = T.server_hello(0x0303, 0x1301, supported_version=0x0304)
    emit("06_imaps_tls13", 40006, 993, ch, sh + T.encrypted_blob())

    # 7) SMTP submission (587) STARTTLS advertised but stripped; cleartext AUTH
    cs = b"EHLO client\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\n"
    ss = (b"220 mail.example.com ESMTP\r\n250-mail.example.com\r\n"
          b"250-STARTTLS\r\n250 AUTH LOGIN PLAIN\r\n"
          b"334 VXNlcm5hbWU6\r\n235 2.7.0 OK\r\n")
    emit("07_smtp_starttls_stripped", 40007, 587, cs, ss)

    # combined capture with every scenario back-to-back
    combined = os.path.join(outdir, "all.pcap")
    _concat(combined, written)
    written.append(combined)
    return written


def _concat(dst: str, parts: list) -> None:
    """Concatenate packet records of several pcaps under one global header."""
    with open(parts[0], "rb") as fh:
        header = fh.read(24)
    with open(dst, "wb") as out:
        out.write(header)
        for p in parts:
            with open(p, "rb") as fh:
                out.write(fh.read()[24:])


if __name__ == "__main__":        # pragma: no cover
    for path in generate():
        print("wrote", path)
