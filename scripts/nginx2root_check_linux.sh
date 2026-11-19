#!/bin/bash
# =============================================================================
# nginx2root_check_linux.sh
# Vairav Technology CSOC - NGINX2Root (CVE-2026-123007 + 4 related) exposure check
#
# Read-only. Never sends exploit traffic. Per NGINX instance it checks:
#   1. Version vs fixed releases (OSS 1.31.9 / 1.30.7; Plus 37.3.0.1 / 37.0.8.1)
#   2. Distro backport evidence (package changelog names the CVE)
#   3. Running master still on an old binary (reload is not enough - restart)
#   4. Affected features in the active config (HTTP/2, HTTP/3, resolver+SSI/mirror, mail proxy)
#   5. Kernel SCTP module state (root-escalation step)
#   6. Optional handshake-only remote probe for HTTP/2 (ALPN h2) and HTTP/3 (Alt-Svc)
#
# Usage:  sudo bash nginx2root_check_linux.sh [--nginx-bin PATH] [--config-dump FILE]
#                                             [--probe HOST[:PORT]]... [--docker] [--no-color]
# Exit codes: 0 no exposure found | 1 vulnerable / restart required | 2 review needed | 3 nginx not found
# =============================================================================

NGINX_BIN=""; CFG_DUMP=""; PROBES=(); DOCKER=0; COLOR=1
while [ $# -gt 0 ]; do
  case "$1" in
    --nginx-bin) NGINX_BIN="$2"; shift 2 ;;
    --config-dump) CFG_DUMP="$2"; shift 2 ;;
    --probe) PROBES+=("$2"); shift 2 ;;
    --docker) DOCKER=1; shift ;;
    --no-color) COLOR=0; shift ;;
    -h|--help) sed -n 2,19p "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done
[ -t 1 ] || COLOR=0
if [ "$COLOR" -eq 1 ]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31;1m'; C=$'\033[36m'; N=$'\033[0m'; else G=; Y=; R=; C=; N=; fi

vnum() { local IFS=.; set -- $1; echo $(( ${1:-0}*1000000 + ${2:-0}*1000 + ${3:-0} )); }
is_fixed() { local n; n=$(vnum "$1"); [ "$n" -ge 1031009 ] || { [ "$n" -ge 1030007 ] && [ "$n" -lt 1031000 ]; }; }

echo "=================================================================="
echo " NGINX2Root (CVE-2026-123007 + 4) exposure check - $(hostname) - $(date '+%F %T')"
echo "=================================================================="
[ "$(id -u)" -ne 0 ] && echo "${Y}[!] Not root: config and process inspection may be incomplete (use sudo).${N}"

# ---- locate binaries ---------------------------------------------------------
declare -A SEEN; BINS=()
add_bin() { local p="$1" r; [ -n "$p" ] && [ -x "$p" ] || return; r=$(readlink -f "$p"); [ -n "${SEEN[$r]}" ] && return; SEEN[$r]=1; BINS+=("$r"); }
if [ -n "$NGINX_BIN" ]; then add_bin "$NGINX_BIN"; else
  add_bin "$(command -v nginx 2>/dev/null)"
  for p in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx /opt/nginx/sbin/nginx /opt/*/sbin/nginx /opt/nginx*/nginx; do add_bin "$p"; done
  for e in /proc/[0-9]*/exe; do t=$(readlink "$e" 2>/dev/null) || continue; t=${t% (deleted)}; [ "$(basename "$t")" = "nginx" ] && add_bin "$t"; done
fi
[ ${#BINS[@]} -eq 0 ] && [ "$DOCKER" -eq 0 ] && { echo "${C}[i] No nginx binary found on this host.${N}"; EXIT=3; }

WORST=0   # 0 ok, 2 review, 1 vuln  (1 wins)
bump() { case "$1" in 1) WORST=1 ;; 2) [ "$WORST" -ne 1 ] && WORST=2 ;; esac; }
FOUND_ANY=0

for BIN in "${BINS[@]}"; do
  FOUND_ANY=1
  echo; echo "--- $BIN ---"
  VTXT=$("$BIN" -v 2>&1 | head -1); VER=$(echo "$VTXT" | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2)
  FLAGS=$("$BIN" -V 2>&1 | grep 'configure arguments')
  PLUS=0; echo "$VTXT" | grep -qi 'nginx-plus' && PLUS=1

  # package + backport evidence
  PKG=""; BACKPORT=0
  if command -v dpkg >/dev/null 2>&1 && PKG=$(dpkg -S "$BIN" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$PKG" ]; then
    for f in /usr/share/doc/"$PKG"/changelog*; do [ -f "$f" ] && { zgrep -q 'CVE-2026-123007' "$f" 2>/dev/null || grep -q 'CVE-2026-123007' "$f" 2>/dev/null; } && BACKPORT=1; done
  elif command -v rpm >/dev/null 2>&1 && PKG=$(rpm -qf "$BIN" 2>/dev/null | head -1) && [ -n "$PKG" ] && ! echo "$PKG" | grep -q 'not owned'; then
    rpm -q --changelog "$PKG" 2>/dev/null | grep -q 'CVE-2026-123007' && BACKPORT=1
  else PKG=""; fi
  echo "  $VTXT  (package: ${PKG:-not from a package manager})"
  [ "$PLUS" -eq 1 ] && echo "  ${Y}NGINX Plus detected: confirm against F5 - fixed 37.3.0.1 / 37.0.8.1; R33-R36 have no fix.${N}"
  [ "$BACKPORT" -eq 1 ] && echo "  ${G}Package changelog names CVE-2026-123007 (backported fix).${N}"

  # config
  CFG=""
  if [ -n "$CFG_DUMP" ]; then CFG=$(cat "$CFG_DUMP" 2>/dev/null)
  else CFGOUT=$("$BIN" -T 2>&1); echo "$CFGOUT" | grep -q 'configuration file' && ! echo "$CFGOUT" | head -1 | grep -q emerg && CFG="$CFGOUT"; fi
  F_H2=0; F_H3=0; F_PROXY=0; F_VARPROXY=0; F_RES=0; F_SSI=0; F_MIR=0; F_MAIL=0
  if [ -n "$CFG" ]; then
    T=$(echo "$CFG" | sed 's/#.*$//' | tr '\n' ' ')
    has() { echo "$T" | grep -Eq "$1"; }
    has '(^|[;{}])[[:space:]]*listen[^;]*[[:space:]]http2([[:space:];]|$)|(^|[;{}])[[:space:]]*http2[[:space:]]+on[[:space:]]*;' && F_H2=1
    has '(^|[;{}])[[:space:]]*listen[^;]*[[:space:]]quic([[:space:];]|$)|(^|[;{}])[[:space:]]*http3[[:space:]]+on[[:space:]]*;' && F_H3=1
    has '(^|[;{}[:space:]])proxy_pass[[:space:]]' && F_PROXY=1
    has 'proxy_pass[[:space:]]+[^;]*\$' && F_VARPROXY=1
    has '(^|[;{}])[[:space:]]*resolver[[:space:]]' && F_RES=1
    has '(^|[;{}])[[:space:]]*ssi[[:space:]]+on[[:space:]]*;' && F_SSI=1
    echo "$T" | grep -oE '(^|[;{}])[[:space:]]*mirror[[:space:]]+[^[:space:];]+' | grep -vE 'mirror[[:space:]]+off$' | grep -q . && F_MIR=1
    has '(^|[;{}])[[:space:]]*mail[[:space:]]*\{' && has 'auth_http[[:space:]]' && F_MAIL=1
    if [ -n "$FLAGS" ]; then   # modules compiled in?
      echo "$FLAGS" | grep -q 'http_v2_module' || F_H2=0
      echo "$FLAGS" | grep -q 'http_v3_module' || F_H3=0
      echo "$FLAGS" | grep -q -- '--with-mail' || F_MAIL=0
    fi
  fi
  F_CHAIN=0; [ $F_RES -eq 1 ] && [ $F_VARPROXY -eq 1 ] && { [ $F_SSI -eq 1 ] || [ $F_MIR -eq 1 ]; } && F_CHAIN=1

  # per-CVE table
  show() { # id title since(num) used
    local id="$1" title="$2" since="$3" used="$4" st dt col
    if [ "$BACKPORT" -eq 1 ]; then st=FIXED; dt="distro changelog names this CVE"; col=$G
    elif [ -z "$VER" ]; then st=REVIEW; dt="version not parsed"; col=$Y
    elif is_fixed "$VER"; then st=FIXED; dt="version >= fixed release"; col=$G
    elif [ "$(vnum "$VER")" -lt "$(vnum "$since")" ]; then st="N/A"; dt="feature introduced in $since"; col=$C
    elif [ -z "$CFG" ]; then st=POSSIBLE; dt="config not readable (run as root / use --config-dump)"; col=$Y
    elif [ "$used" -eq 1 ]; then st=EXPOSED; dt="affected feature in use"; col=$R
    else st=VULN-BUILD; dt="vulnerable build, affected feature not seen in config"; col=$Y; fi
    printf '  %s%-10s%s %s  %s  [%s]\n' "$col" "$st" "$N" "$id" "$title" "$dt"
  }
  show CVE-2026-123007 "HTTP/2 flow-control overflow (nginx2root)" 1.9.5 $F_H2
  show CVE-2026-123633 "HTTP/2 connection draining use-after-free" 1.19.7 $(( F_H2 && F_PROXY ))
  show CVE-2026-123634 "DNS resolver use-after-free (variable proxy_pass + SSI/mirror)" 1.13.4 $F_CHAIN
  show CVE-2026-121810 "HTTP/3 (QUIC) stream use-after-free" 1.25.0 $F_H3
  show CVE-2026-113425 "Mail proxy auth_http use-after-free" 0.5.15 $F_MAIL

  # running master on old binary?
  STALE=0
  for pid in $(pgrep -f 'nginx: master' 2>/dev/null); do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    del=0; case "$exe" in *"(deleted)") del=1; exe=${exe% (deleted)} ;; esac
    [ "$del" -eq 0 ] && [ "$(readlink -f "$exe")" != "$BIN" ] && continue
    start=$(date -d "$(ps -o lstart= -p "$pid")" +%s 2>/dev/null); mt=$(stat -c %Y "$BIN" 2>/dev/null)
    if [ "$del" -eq 1 ] || { [ -n "$start" ] && [ -n "$mt" ] && [ "$mt" -gt "$start" ]; }; then
      STALE=1; echo "  ${R}master PID $pid: running OLD binary - RESTART required (reload is not enough)${N}"
    else echo "  ${G}master PID $pid: running current binary${N}"; fi
  done

  # verdict
  if [ "$PLUS" -eq 1 ] || [ -z "$VER" ]; then V=REVIEW; bump 2; col=$Y
  elif [ "$BACKPORT" -eq 1 ] || is_fixed "$VER"; then
    if [ "$STALE" -eq 1 ]; then V=RESTART-REQUIRED; bump 1; col=$R; else V=PATCHED; col=$G; fi
  else V=VULNERABLE; bump 1; col=$R; fi
  echo "  VERDICT: ${col}${V}${N}"
done

# ---- docker ------------------------------------------------------------------
if [ "$DOCKER" -eq 1 ] && command -v docker >/dev/null 2>&1; then
  echo; echo "--- Running Docker containers ---"
  while IFS=$'\t' read -r cid img name; do
    [ -z "$cid" ] && continue
    out=$(docker exec "$cid" nginx -v 2>&1) || continue
    v=$(echo "$out" | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2); [ -z "$v" ] && continue
    FOUND_ANY=1
    if is_fixed "$v"; then echo "  ${G}PATCHED${N}     $name ($img) nginx $v"; else echo "  ${R}VULNERABLE${N}  $name ($img) nginx $v"; bump 1; fi
  done < <(docker ps --format '{{.ID}}'$'\t''{{.Image}}'$'\t''{{.Names}}' 2>/dev/null)
fi

# ---- SCTP --------------------------------------------------------------------
echo; echo "--- Kernel SCTP (root-escalation step) ---"
LOADED=no; grep -qw sctp /proc/modules 2>/dev/null && LOADED=yes
BLOCKED=no; grep -rEqs '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+/bin/(false|true)' /etc/modprobe.d /usr/lib/modprobe.d 2>/dev/null && BLOCKED=yes
AVAIL=unknown; command -v modinfo >/dev/null 2>&1 && { modinfo sctp >/dev/null 2>&1 && AVAIL=yes || AVAIL=no; }
echo "  loaded=$LOADED blocked_via_modprobe=$BLOCKED available=$AVAIL"
[ "$BLOCKED" = no ] && [ "$AVAIL" = yes ] && echo "  ${Y}SCTP can be loaded. If unused, block it: echo 'install sctp /bin/false' > /etc/modprobe.d/disable-sctp.conf${N}"

# ---- probes ------------------------------------------------------------------
for tgt in "${PROBES[@]}"; do
  host=${tgt%%:*}; port=${tgt#*:}; [ "$port" = "$tgt" ] && port=443
  echo; echo "--- Probe $host:$port (handshake only) ---"
  if ! command -v openssl >/dev/null 2>&1; then echo "  ${Y}openssl not available${N}"; continue; fi
  alpn=$(timeout 8 openssl s_client -connect "$host:$port" -servername "$host" -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol|No ALPN')
  case "$alpn" in *"protocol: h2"*) echo "  HTTP/2 (ALPN h2): ${R}OFFERED${N}" ;; *) echo "  HTTP/2 (ALPN h2): ${G}not offered${N}" ;; esac
  if command -v curl >/dev/null 2>&1; then
    alt=$(curl -skI --http1.1 --max-time 8 "https://$host:$port/" 2>/dev/null | grep -i '^alt-svc:' | tr -d '\r')
    [ -n "$alt" ] && echo "  ${R}$alt${N}" || echo "  Alt-Svc: none"
  fi
  echo "  ${C}Note: a CDN/LB may terminate HTTP/2 in front of NGINX - test the origin directly.${N}"
done

echo; echo "Note: heuristics only; version and config checks cannot prove a host is safe. Patch and RESTART."
[ "$FOUND_ANY" -eq 0 ] && exit 3
exit $WORST
