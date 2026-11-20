# 🛡️ NGINX2Root Toolkit CVE-2026-123007 (+ 4 related)

> **Vairav Technology Security Pvt. Ltd. · Cyber Security Operations Centre (CSOC)**
> Advisory **VTS-SA-2026-1119-NGINX2ROOT** · 🏷️ **TLP:CLEAR** · 20 November 2026

Read-only scripts that tell you whether an NGINX host is exposed to **NGINX2Root** the HTTP/2 flow-control flaw **CVE-2026-123007** and four related memory-safety flaws fixed by F5 on 18 November 2026.

---

## 🧭 Contents

- [🔬 What the scripts decide](#-what-the-scripts-decide)
- [🗂️ Package contents](#️-package-contents)
- [🪪 Requirements](#-requirements)
- [🐍 Script 1 Python (any OS)](#-script-1--nginx2root_checkpy)
- [🐧 Script 2 Bash (Linux)](#-script-2--nginx2root_check_linuxsh)
- [🪟 Script 3 PowerShell (Windows)](#-script-3--nginx2root_check_windowsps1)
- [🧮 Reading the results](#-reading-the-results)
- [📦 Fixed versions](#-fixed-versions)
- [🐳 Containers and Kubernetes](#-containers-and-kubernetes)
- [🩹 Patch and restart](#-patch-and-restart)
- [🧯 Interim controls](#-interim-controls)
- [🪛 Troubleshooting](#-troubleshooting)
- [🧷 Verify file integrity](#-verify-file-integrity)
- [🧪 Testing status](#-testing-status)

---

## 🔬 What the scripts decide

Each NGINX instance gets a **verdict**, built from six checks:

| # | Check | Why it matters |
|---|---|---|
| 1️⃣ | 🏷️ **Version** | Fixed builds are OSS **1.31.9 / 1.30.7** and Plus **37.3.0.1 / 37.0.8.1**. October releases do **not** fix these flaws |
| 2️⃣ | 📦 **Distro backport** | Ubuntu/Debian/RHEL may fix without changing the version — the script looks for the CVE ID in the package changelog |
| 3️⃣ | 🔁 **Restart state** | A **reload keeps the vulnerable binary in memory**. The script flags a master process older than the binary on disk |
| 4️⃣ | ⚙️ **Features in config** | Each CVE needs a feature: HTTP/2, HTTP/3 (QUIC), variable `proxy_pass` + resolver + SSI/mirror, or mail proxy `auth_http` |
| 5️⃣ | 🧬 **Kernel SCTP** | The public root chain uses a separate Linux SCTP flaw; reports whether the module is loaded or blocked |
| 6️⃣ | 🌐 **Remote probe** *(optional)* | Handshake-only check for HTTP/2 (ALPN `h2`) and HTTP/3 (`Alt-Svc`) |

The five CVEs:

| CVE | Flaw | Needs | Since |
|---|---|---|---|
| 🔴 **CVE-2026-123007** | HTTP/2 flow-control overflow → out-of-bounds read/write | HTTP/2 on a reachable listener | 1.9.5 |
| 🟠 CVE-2026-123633 | HTTP/2 connection draining use-after-free | HTTP/2 + proxying to a backend | 1.19.7 |
| 🟠 CVE-2026-123634 | DNS resolver use-after-free | `resolver` + variable `proxy_pass` + SSI or mirror | 1.13.4 |
| 🟠 CVE-2026-121810 | HTTP/3 (QUIC) stream use-after-free | HTTP/3 listener | 1.25.0 |
| 🟠 CVE-2026-113425 | Mail proxy `auth_http` use-after-free | `mail` block with `auth_http` | 0.5.15 |

> 🛑 **These scripts never send exploit traffic.** Do **not** run the public PoC against production — failed attempts crash NGINX workers.

---

## 🗂️ Package contents

```
nginx2root-toolkit/
├── 📘 README.md                          ← this file
├── 🧷 SHA256SUMS.txt                     ← script checksums
└── 📁 scripts/
    ├── 🐍 nginx2root_check.py            ← Linux / Windows / macOS (Python 3.8+)
    ├── 🐧 nginx2root_check_linux.sh      ← Linux (bash)
    └── 🪟 nginx2root_check_windows.ps1   ← Windows (PowerShell 5.1+, 7+ for probe)
```

| Script | Platform | 👁️ Read-only | 🔄 Restarts services | 🔎 Restart-state check | 🌐 Remote probe |
|---|---|:---:|:---:|:---:|:---:|
| 🐍 `nginx2root_check.py` | Linux, Windows, macOS | ✔️ | ✖️ | Linux only | ✔️ |
| 🐧 `nginx2root_check_linux.sh` | Linux | ✔️ | ✖️ | ✔️ | ✔️ (needs `openssl`) |
| 🪟 `nginx2root_check_windows.ps1` | Windows (and PowerShell 7 elsewhere) | ✔️ | ✖️ | ✔️ | PowerShell 7+ only |

---

## 🪪 Requirements

| Platform | Needs |
|---|---|
| 🐧 Linux | `bash`, **root** (`sudo`) so `nginx -T` and `/proc` can be read; optional `dpkg`/`rpm`, `openssl`, `curl`, `docker` |
| 🐍 Python | Python 3.8+, standard library only |
| 🪟 Windows | PowerShell 5.1+ run **as Administrator**; PowerShell 7+ for `-Probe` |

```bash
unzip nginx2root-toolkit.zip
cd nginx2root-toolkit/scripts
chmod +x *.sh *.py
```

---

## 🐍 Script 1 `nginx2root_check.py`

Cross-platform check with optional JSON output for tooling.

```bash
sudo python3 nginx2root_check.py                       # auto-discover nginx
sudo python3 nginx2root_check.py --nginx-bin /opt/nginx/sbin/nginx
sudo python3 nginx2root_check.py --docker              # also check running containers
python3 nginx2root_check.py --probe www.example.com:443 --probe 10.0.0.5:8443
sudo python3 nginx2root_check.py --json > nginx2root_$(hostname).json
```

| Option | Purpose |
|---|---|
| `--nginx-bin PATH` | Check one specific binary |
| `--config-dump FILE` | Use saved `nginx -T` output instead of running it |
| `--probe HOST[:PORT]` | Handshake-only HTTP/2 and `Alt-Svc` check (repeatable) |
| `--docker` | Run `nginx -v` inside running containers |
| `--json` / `--no-color` | Machine-readable or plain output |

---

## 🐧 Script 2 `nginx2root_check_linux.sh`

Same checks in plain bash, no Python needed.

```bash
sudo ./nginx2root_check_linux.sh
sudo ./nginx2root_check_linux.sh --probe www.example.com:443 --docker
sudo ./nginx2root_check_linux.sh --no-color | tee nginx2root_$(hostname).txt   # save report
```

Options match the Python script: `--nginx-bin`, `--config-dump`, `--probe`, `--docker`, `--no-color`.

**Sample output**

```
--- /usr/sbin/nginx ---
  nginx version: nginx/1.28.0  (package: not from a package manager)
  EXPOSED    CVE-2026-123007  HTTP/2 flow-control overflow (nginx2root)  [affected feature in use]
  EXPOSED    CVE-2026-123633  HTTP/2 connection draining use-after-free  [affected feature in use]
  VULN-BUILD CVE-2026-113425  Mail proxy auth_http use-after-free  [vulnerable build, affected feature not seen in config]
  master PID 732: running OLD binary - RESTART required (reload is not enough)
  VERDICT: VULNERABLE
```

---

## 🪟 Script 3 `nginx2root_check_windows.ps1`

For `nginx.exe` on Windows Server (also runs under PowerShell 7 on Linux for the local checks).

```powershell
powershell -ExecutionPolicy Bypass -File .\nginx2root_check_windows.ps1
powershell -ExecutionPolicy Bypass -File .\nginx2root_check_windows.ps1 -NginxBin "C:\nginx\nginx.exe"
pwsh .\nginx2root_check_windows.ps1 -Probe www.example.com:443        # probe needs PowerShell 7+
```

| Parameter | Purpose |
|---|---|
| `-NginxBin` | Path to `nginx.exe` |
| `-ConfigDump` | File containing `nginx -T` output |
| `-Probe` | One or more `HOST[:PORT]` targets (PowerShell 7+) |

---

## 🧮 Reading the results

| Status | Meaning |
|---|---|
| 🟢 `FIXED` | Version is at or above the fixed release, or the package changelog names the CVE |
| 🔵 `N/A` | The vulnerable feature did not exist in this version |
| 🔴 `EXPOSED` | **Vulnerable build and the affected feature is in the active config** — highest priority |
| 🟡 `VULN-BUILD` | Vulnerable build; feature not seen in config (may be enabled later or in an unread include) |
| 🟡 `POSSIBLE` | Vulnerable build; config could not be read — run as root or use `--config-dump` |
| 🟡 `REVIEW` | Could not decide (for example NGINX Plus) — confirm manually |

| Verdict | Action |
|---|---|
| ✅ `PATCHED` | Fixed build is installed and running |
| 🔁 `RESTART-REQUIRED` | Fixed binary on disk, **old process still running** — restart NGINX |
| ❌ `VULNERABLE` | Upgrade, then restart |
| 🔍 `REVIEW` | NGINX Plus or unparsed version — check against the F5 advisory |

**Exit codes:** `0` no exposure found · `1` vulnerable or restart required · `2` review needed · `3` nginx not found.

> ⚠️ A `PATCHED` verdict is a **version and configuration check**, not proof of safety. Config detection is pattern-based: verify unusual setups by hand.

---

## 📦 Fixed versions

| Product | Affected | Fixed |
|---|---|---|
| 🟩 NGINX Open Source mainline | 1.31.0 – 1.31.8 | **1.31.9** |
| 🟩 NGINX Open Source stable and older | 1.9.5 – 1.30.6 | **1.30.7** |
| 🟦 NGINX Plus 37.1 and later | 37.1.0 – 37.2.0.1 | **37.3.0.1** |
| 🟦 NGINX Plus 37.0 | 37.0.0 – 37.0.7.1 | **37.0.8.1** |
| 🟥 NGINX Plus R33 – R36 | All | No fix — move to a fixed 37.x |
| 🟧 Community ingress-nginx | Archived March 2026 | No fixes — plan migration |

> 📦 Ubuntu and Debian listed their packages as vulnerable at publication. Confirm the **full package version** and the vendor advisory, not `nginx -v` alone.

---

## 🐳 Containers and Kubernetes

```bash
sudo ./nginx2root_check_linux.sh --docker                       # running Docker containers
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}' | grep -Ei 'nginx|ingress'
kubectl exec -n <ns> <pod> -- nginx -v                          # one pod
```

- Rebuild images from the **1.31.9 / 1.30.7** tags (including Alpine) and redeploy; also update Helm charts, machine images and autoscaling templates.
- F5 NGINX Ingress Controller **5.8.0** and Gateway Fabric **2.9.0** ship NGINX 1.31.9.

---

## 🩹 Patch and restart

1. ⬆️ Upgrade to **1.31.9 / 1.30.7** (OSS) or **37.3.0.1 / 37.0.8.1** (Plus), or to a distro package that names CVE-2026-123007.
2. 🔁 **Restart** `sudo nginx -t && sudo systemctl restart nginx` — or do a live binary upgrade. **A reload is not enough.**
3. 🔎 Re-run the script and confirm `VERDICT: PATCHED` with `running current binary`.

---

## 🧯 Interim controls

Use only until you can patch; each control covers specific CVEs. Test first and record an end date.

| Feature | Control | Covers |
|---|---|---|
| 🌐 HTTP/2 | Remove `http2` from `listen` lines (and `http2 off;` on 1.25.1+); restart. Breaks gRPC and other HTTP/2-only services | 123007, 123633 |
| 🚀 HTTP/3 | Remove `quic`/`http3` listeners; block UDP 443 if not required | 121810 |
| 🔗 Resolver chain | Use fixed upstream groups; remove SSI and mirror where unneeded | 123634 |
| ✉️ Mail proxy | Bind mail listeners to loopback or trusted networks | 113425 |
| 🧬 SCTP (root step) | `echo "install sctp /bin/false" > /etc/modprobe.d/disable-sctp.conf` on hosts not using SCTP (does not unload a loaded module) | Escalation only |

---

## 🪛 Troubleshooting

| Problem | Fix |
|---|---|
| `Not root` warning / `POSSIBLE` statuses | Run with `sudo`, or save `sudo nginx -T > nginx_T.txt` and pass `--config-dump nginx_T.txt` |
| `No nginx binary found` | Pass `--nginx-bin /path/to/nginx` (custom builds, `/opt`, containers) |
| Version shows old on Ubuntu/Debian | Backported fix — check the package changelog for CVE-2026-123007 (the script does this automatically) |
| Probe says `h2 OFFERED` but host is patched | The probe only shows HTTP/2 is *enabled*; use the version check for patch state |
| Probe result differs from the origin | A CDN or load balancer terminates HTTP/2 — probe the NGINX origin directly |
| `Execution policy` error on Windows | Run with `-ExecutionPolicy Bypass` as shown above |

---

## 🧷 Verify file integrity

```bash
sha256sum -c SHA256SUMS.txt
```

---

## 🧪 Testing status

| Script | Status |
|---|---|
| 🐍 Python | Run against simulated NGINX 1.28.0 / 1.30.7 / 1.31.8 / 1.31.9 builds, a local TLS server (HTTP/2 + `Alt-Svc`), and a stale-master process |
| 🐧 Bash | Same scenarios as Python; output and exit codes matched |
| 🪟 PowerShell | **Syntax-reviewed only** — not executed. Test on one Windows host before wide use |
| 🧱 All | Package-changelog backport check and `--docker` path were **not** exercised against real packages or containers |

---

*Vairav Technology Security Pvt. Ltd. · sales@vairavtech.com · vairavtech.com*
