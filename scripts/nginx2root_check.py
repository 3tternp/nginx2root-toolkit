#!/usr/bin/env python3
"""
nginx2root_check.py
Vairav Technology CSOC - NGINX2Root (CVE-2026-123007 + 4 related) exposure check

Read-only. Never sends exploit traffic. Checks, per NGINX instance:
  1. Version against fixed releases (OSS 1.31.9 / 1.30.7; Plus 37.3.0.1 / 37.0.8.1)
  2. Distro backport evidence (package changelog names the CVE)
  3. Running process still on an old binary (reload vs restart)  [Linux]
  4. Which affected features the active config uses (HTTP/2, HTTP/3, resolver+SSI/mirror, mail proxy)
  5. Kernel SCTP module state (root-escalation step)                [Linux]
  6. Optional: handshake-only remote probe for HTTP/2 (ALPN h2) and HTTP/3 (Alt-Svc)

Exit codes: 0 = no exposure found, 1 = vulnerable / restart required, 2 = review needed, 3 = nginx not found
Usage:  sudo python3 nginx2root_check.py [--nginx-bin PATH] [--config-dump FILE]
                                         [--probe HOST[:PORT]] [--docker] [--json] [--no-color]
"""
import argparse, glob, json, os, re, shutil, socket, ssl, subprocess, sys, time

FIXED_STABLE, FIXED_MAINLINE = (1, 30, 7), (1, 31, 9)
CVES = [  # id, title, introduced
    ("CVE-2026-123007", "HTTP/2 flow-control overflow (nginx2root)", (1, 9, 5)),
    ("CVE-2026-123633", "HTTP/2 connection draining use-after-free", (1, 19, 7)),
    ("CVE-2026-123634", "DNS resolver use-after-free (variable proxy_pass + SSI/mirror)", (1, 13, 4)),
    ("CVE-2026-121810", "HTTP/3 (QUIC) stream use-after-free", (1, 25, 0)),
    ("CVE-2026-113425", "Mail proxy auth_http use-after-free", (0, 5, 15)),
]
USE_COLOR = sys.stdout.isatty()


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if USE_COLOR else txt


OK, WARN, BAD, INFO = (lambda t: c(t, "32"), lambda t: c(t, "33"), lambda t: c(t, "31;1"), lambda t: c(t, "36"))


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 127, str(e)


def parse_version(text):
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(x) for x in m.groups()) if m else None


def version_fixed(v):
    return v >= FIXED_MAINLINE or ((1, 30, 7) <= v < (1, 31, 0))


def strip_comments(cfg):
    return "\n".join(re.sub(r"(^|\s)#.*$", "", ln) for ln in cfg.splitlines())


def analyse_config(cfg, flags):
    t = strip_comments(cfg)
    f = {
        "http2": bool(re.search(r"\blisten\b[^;]*\bhttp2\b", t) or re.search(r"(?:^|[;{}])\s*http2\s+on\s*;", t, re.M)),
        "http3": bool(re.search(r"\blisten\b[^;]*\bquic\b", t) or re.search(r"(?:^|[;{}])\s*http3\s+on\s*;", t, re.M)),
        "proxy_pass": bool(re.search(r"\bproxy_pass\b", t)),
        "var_proxy_pass": bool(re.search(r"\bproxy_pass\s+[^;]*\$", t)),
        "resolver": bool(re.search(r"(?:^|[;{}])\s*resolver\s", t, re.M)),
        "ssi": bool(re.search(r"(?:^|[;{}])\s*ssi\s+on\s*;", t, re.M)),
        "mirror": bool(re.search(r"(?:^|[;{}])\s*mirror\s+(?!off)\S+", t, re.M)),
        "mail_auth_http": bool(re.search(r"(?:^|[;{}])\s*mail\s*\{", t, re.M) and re.search(r"\bauth_http\b", t)),
    }
    f["resolver_chain"] = f["resolver"] and f["var_proxy_pass"] and (f["ssi"] or f["mirror"])
    if flags is not None:  # compiled-in modules
        if "http_v2_module" not in flags: f["http2"] = False
        if "http_v3_module" not in flags: f["http3"] = False
        if "mail" not in flags: f["mail_auth_http"] = False
    return f


def evaluate(v, feats, backport):
    """Return list of (cve, title, status, detail)."""
    out = []
    for cid, title, since in CVES:
        if backport:
            out.append((cid, title, "FIXED", "distro changelog names this CVE")); continue
        if v is None:
            out.append((cid, title, "REVIEW", "version not parsed")); continue
        if version_fixed(v):
            out.append((cid, title, "FIXED", "version >= fixed release")); continue
        if v < since:
            out.append((cid, title, "N/A", f"feature introduced in {'.'.join(map(str, since))}")); continue
        if feats is None:
            out.append((cid, title, "POSSIBLE", "config not readable (run as root / use --config-dump)")); continue
        used = {"CVE-2026-123007": feats["http2"], "CVE-2026-123633": feats["http2"] and feats["proxy_pass"],
                "CVE-2026-123634": feats["resolver_chain"], "CVE-2026-121810": feats["http3"],
                "CVE-2026-113425": feats["mail_auth_http"]}[cid]
        out.append((cid, title, "EXPOSED" if used else "VULN-BUILD",
                    "affected feature in use" if used else "vulnerable build, affected feature not seen in config"))
    return out


def find_binaries(explicit):
    found = {}
    cands = [explicit] if explicit else []
    if not explicit:
        w = shutil.which("nginx")
        cands += [w] if w else []
        cands += ["/usr/sbin/nginx", "/usr/local/sbin/nginx", "/usr/local/nginx/sbin/nginx", "/opt/nginx/sbin/nginx",
                  r"C:\nginx\nginx.exe"] + glob.glob("/opt/*/sbin/nginx") + glob.glob("/opt/nginx*/nginx")
        for exe in glob.glob("/proc/[0-9]*/exe"):
            try:
                tgt = os.readlink(exe).replace(" (deleted)", "")
                if os.path.basename(tgt) == "nginx": cands.append(tgt)
            except OSError:
                pass
    for p in cands:
        if p and os.path.isfile(p):
            found[os.path.realpath(p)] = p
    return list(found.values())


def running_masters(binpath):
    res = []
    real = os.path.realpath(binpath)
    for d in glob.glob("/proc/[0-9]*"):
        try:
            pid = int(os.path.basename(d))
            exe = os.readlink(d + "/exe")
            deleted = exe.endswith(" (deleted)")
            if os.path.realpath(exe.replace(" (deleted)", "")) != real and not deleted: continue
            cmd = open(d + "/cmdline", "rb").read().decode(errors="ignore")
            if "master" not in cmd: continue
            started = os.stat(d).st_ctime
            res.append((pid, deleted, started))
        except (OSError, ValueError):
            continue
    return res


def pkg_backport(binpath):
    """True if the distro package changelog names CVE-2026-123007."""
    if shutil.which("dpkg"):
        rc, o = run(["dpkg", "-S", binpath])
        if rc == 0:
            pkg = o.split(":")[0].strip()
            for fn in glob.glob(f"/usr/share/doc/{pkg}/changelog*"):
                try:
                    import gzip
                    data = (gzip.open(fn, "rt", errors="ignore") if fn.endswith(".gz") else open(fn, errors="ignore")).read()
                    if "CVE-2026-123007" in data: return True, pkg
                except OSError:
                    pass
            return False, pkg
    if shutil.which("rpm"):
        rc, o = run(["rpm", "-qf", binpath])
        if rc == 0:
            return ("CVE-2026-123007" in run(["rpm", "-q", "--changelog", o.strip()])[1]), o.strip()
    return False, None


def sctp_state():
    if not sys.platform.startswith("linux"): return None
    loaded = "sctp" in open("/proc/modules").read().split() if os.path.exists("/proc/modules") else False
    blocked = False
    for fn in glob.glob("/etc/modprobe.d/*.conf") + glob.glob("/usr/lib/modprobe.d/*.conf"):
        try:
            if re.search(r"^\s*install\s+sctp\s+/bin/(false|true)", open(fn).read(), re.M): blocked = True
        except OSError:
            pass
    avail = run(["modinfo", "sctp"])[0] == 0 if shutil.which("modinfo") else None
    return {"loaded": loaded, "blocked": blocked, "available": avail}


def probe(target):
    host, _, port = target.partition(":")
    port = int(port or 443)
    res = {"target": target, "h2": None, "alt_svc": None, "error": None}
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=6) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            res["h2"] = t.selected_alpn_protocol() == "h2"
            t.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = t.recv(4096)
                if not chunk: break
                data += chunk
            m = re.search(rb"(?im)^alt-svc:\s*(.+)$", data)
            res["alt_svc"] = m.group(1).decode(errors="ignore").strip() if m else None
    except Exception as e:
        res["error"] = str(e)
    return res


def check_instance(binpath, cfg_dump, as_root):
    inst = {"binary": binpath, "version": None, "plus": False, "flags_known": False}
    rc, vtxt = run([binpath, "-v"]); inst["version_text"] = vtxt.strip().splitlines()[0] if vtxt.strip() else ""
    inst["plus"] = "nginx-plus" in vtxt.lower()
    v = parse_version(vtxt); inst["version"] = ".".join(map(str, v)) if v else None
    rc, vv = run([binpath, "-V"]); flags = vv if "configure arguments" in vv else None
    flag_str = flags
    inst["flags_known"] = flags is not None
    cfg = open(cfg_dump).read() if cfg_dump else None
    if cfg is None:
        rc, out = run([binpath, "-T"])
        cfg = out if "configuration file" in out and "emerg" not in out.split("\n", 1)[0] else None
    feats = analyse_config(cfg, flag_str) if cfg else None
    inst["features"] = feats
    backport, pkg = pkg_backport(binpath)
    inst["package"] = pkg; inst["backport"] = backport
    inst["cves"] = [dict(zip(("cve", "title", "status", "detail"), r)) for r in evaluate(v, feats, backport)]
    inst["masters"] = []
    if sys.platform.startswith("linux"):
        for pid, deleted, started in running_masters(binpath):
            stale = deleted or os.stat(binpath).st_mtime > started
            inst["masters"].append({"pid": pid, "needs_restart": stale})
    if inst["plus"]:
        verdict = "REVIEW"
    elif v is None:
        verdict = "REVIEW"
    elif backport or version_fixed(v):
        verdict = "RESTART-REQUIRED" if any(m["needs_restart"] for m in inst["masters"]) else "PATCHED"
    else:
        verdict = "VULNERABLE"
    if verdict == "PATCHED" and any(m["needs_restart"] for m in inst["masters"]): verdict = "RESTART-REQUIRED"
    inst["verdict"] = verdict
    return inst


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(description="NGINX2Root (CVE-2026-123007 + 4 related) read-only exposure check")
    ap.add_argument("--nginx-bin"); ap.add_argument("--config-dump", help="file containing 'nginx -T' output")
    ap.add_argument("--probe", action="append", default=[], help="HOST[:PORT] handshake-only HTTP/2 + Alt-Svc check")
    ap.add_argument("--docker", action="store_true", help="also check running Docker containers")
    ap.add_argument("--json", action="store_true"); ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    if a.no_color or a.json: USE_COLOR = False
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    report = {"host": socket.gethostname(), "time": time.strftime("%F %T"), "instances": [], "containers": [], "probes": [], "sctp": sctp_state()}
    for b in find_binaries(a.nginx_bin):
        report["instances"].append(check_instance(b, a.config_dump, as_root))
    if a.docker and shutil.which("docker"):
        rc, o = run(["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"])
        for ln in o.splitlines():
            cid, img, name = (ln.split("\t") + ["", "", ""])[:3]
            rc, vt = run(["docker", "exec", cid, "nginx", "-v"])
            v = parse_version(vt)
            if v:
                report["containers"].append({"id": cid, "image": img, "name": name, "version": ".".join(map(str, v)),
                                             "verdict": "PATCHED" if version_fixed(v) else "VULNERABLE"})
    for t in a.probe: report["probes"].append(probe(t))
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 66); print(f" NGINX2Root (CVE-2026-123007 + 4) exposure check - {report['host']} - {report['time']}"); print("=" * 66)
        if not as_root and sys.platform.startswith("linux"): print(WARN("[!] Not root: config and process inspection may be incomplete (use sudo)."))
        if not report["instances"]: print(INFO("[i] No nginx binary found on this host."))
        for i in report["instances"]:
            print(f"\n--- {i['binary']} ---\n  {i['version_text']}  (package: {i['package'] or 'not from a package manager'})")
            if i["plus"]: print(WARN("  NGINX Plus detected: confirm against F5 - fixed 37.3.0.1 / 37.0.8.1; R33-R36 have no fix."))
            if i["backport"]: print(OK("  Package changelog names CVE-2026-123007 (backported fix)."))
            for r in i["cves"]:
                col = {"FIXED": OK, "N/A": INFO, "EXPOSED": BAD, "VULN-BUILD": WARN, "POSSIBLE": WARN, "REVIEW": WARN}[r["status"]]
                print(f"  {col('%-10s' % r['status'])} {r['cve']}  {r['title']}  [{r['detail']}]")
            for m in i["masters"]:
                print((BAD if m["needs_restart"] else OK)(f"  master PID {m['pid']}: " + ("running OLD binary - RESTART required (reload is not enough)" if m["needs_restart"] else "running current binary")))
            col = {"PATCHED": OK, "VULNERABLE": BAD, "RESTART-REQUIRED": BAD, "REVIEW": WARN}[i["verdict"]]
            print("  VERDICT: " + col(i["verdict"]))
        for ct in report["containers"]:
            print(f"\n[container] {ct['name']} ({ct['image']}) nginx {ct['version']}: " + (OK if ct["verdict"] == "PATCHED" else BAD)(ct["verdict"]))
        s = report["sctp"]
        if s:
            print("\n--- Kernel SCTP (root-escalation step) ---")
            print(f"  loaded={s['loaded']} blocked_via_modprobe={s['blocked']} available={s['available']}")
            if not s["blocked"] and s["available"]: print(WARN("  SCTP can be loaded. If unused, block it: echo 'install sctp /bin/false' > /etc/modprobe.d/disable-sctp.conf"))
        for p in report["probes"]:
            print(f"\n--- Probe {p['target']} ---")
            if p["error"]: print(WARN(f"  Could not complete handshake: {p['error']}"))
            else:
                print("  HTTP/2 (ALPN h2): " + (BAD("OFFERED") if p["h2"] else OK("not offered")))
                print("  Alt-Svc: " + (BAD(p["alt_svc"]) if p["alt_svc"] and "h3" in p["alt_svc"] else (p["alt_svc"] or "none")))
                print(INFO("  Note: a CDN/LB may terminate HTTP/2 in front of NGINX - test the origin directly."))
        print("\nNote: heuristics only; version and config checks cannot prove a host is safe. Patch and RESTART.")
    verdicts = [i["verdict"] for i in report["instances"]] + [ct["verdict"] for ct in report["containers"]]
    if not verdicts: sys.exit(3)
    if any(v in ("VULNERABLE", "RESTART-REQUIRED") for v in verdicts): sys.exit(1)
    if "REVIEW" in verdicts: sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
