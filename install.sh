#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v2.4 - point-to-point tunnel over IP protocol 50 (ESP)
#                            + Backhaul reverse tunnel carried inside it
#
#    Iran server   : 10.10.10.2   (menu option 1)   backhaul SERVER
#    Kharej client : 10.10.10.1   (menu option 2)   backhaul CLIENT
#
#  How it works
#   * Linux kernel XFRM (IPsec ESP) + an "xfrm interface" (espt0) on each side.
#     No IKE daemon and no handshake: only encrypted ESP packets hit the wire.
#   * AES-256-GCM in the kernel. One random master key (the "token"); per-direction
#     session keys are derived from it and rotate every hour from the UTC clock
#     (previous/current/next hour inbound SAs are always loaded -> no downtime).
#   * Transport: ESP-in-UDP (default - survives NAT and protocol-50 filtering)
#     or raw ESP (IP protocol 50).
#   * Backhaul (reverse tunnel, github.com/Musixal/Backhaul) runs inside the tunnel: the Kharej
#     client dials 10.10.10.2:8090 through ESP, the Iran server opens the public ports.
#     The Backhaul transport is chosen during the install on the Iran server:
#     tcp / tcpmux / udp / ws / wss / wsmux / wssmux (it travels inside the token).
#
#  v2.4 - Backhaul core instead of Rathole
#   * The reverse tunnel inside the ESP tunnel is now Backhaul. The core is downloaded from the
#     official release (backhaul_linux_<arch>.tar.gz); a local file / mirror URL is accepted too.
#   * The Backhaul transport is selected during the install (Iran side): tcp, tcpmux, udp, ws, wss,
#     wsmux, wssmux. The Kharej side follows the token automatically. wss / wssmux use a
#     self-signed certificate that is generated on the Iran server.
#   * NEW menu 14: change the Backhaul transport later (Iran first, then Kharej) - same key.
#   * The port list, the UDP switch (accept_udp, tcp transport only) and the target address live in
#     the Iran server's Backhaul config. The target address is therefore asked on the Iran side and
#     travels inside the token (token format v3; v1 / v2 "dnat" tokens are still accepted).
#   * Fix: the persistent sysctl file was written with a literal "\n" instead of line breaks.
#   * Everything else (ESP tunnel, key rotation, watchdog, self-healing, MTU, tuning, diagnose) is unchanged.
#
#  v2.3 - second hardening pass: everything that can cause disconnects or slow transfers
#   * MTU is derived from the WAN link MTU (never above the old safe default); menu 9 can
#     set a value or press m to MEASURE the real path MTU with DF probes. A path-MTU black
#     hole is the classic "ping works but downloads stall / crawl" failure. Diagnose shows it.
#   * Self-healing every 30 s, without waiting for ping failures: restores firewall rules that
#     ufw/firewalld/netfilter-persistent removed, restarts a dead UDP helper (no helper = no
#     ESP-in-UDP at all), notices a changed local IP / default route / renamed NIC, a missing
#     tunnel address, flushed xfrm policies or states.
#   * Fewer false rebuilds: a lost ping while real traffic still arrives no longer rebuilds;
#     the preventive rebuild waits for a quiet moment (at most 1 h); the UDP helper socket
#     survives rebuilds (no gap for incoming ESP packets); pings tolerate 2 s of queueing.
#   * Settings changes (menu 9) apply live (SIGHUP / ip link set): no service restart, so
#     rathole connections are not dropped.
#   * Network tuning (on by default, switch in menu 9): BBR+fq, bigger TCP buffers, bigger
#     netdev backlog (decrypted packets queue there), TCP MTU probing, no slow-start after
#     idle, bigger conntrack table. Original values are saved and restored when switched
#     off / on uninstall. ip_forward is only enabled for the legacy DNAT engine now.
#   * systemd: OOMScoreAdjust so the tunnel is not the OOM killer's first victim.
#   * Upgrade without re-install: run the new file, menu 7 (it copies itself to /usr/local/bin).
#
#  v2.2 - fixes for "no ping / no connection after install"
#   * NEW Diagnose (menu 11 / `esp-tunnel diag`): measures packets during a live test and
#     names the cause: route conflict, nothing encrypted, UDP port blocked, clock skew,
#     key/token mismatch, packets arriving but not decrypted, local firewall.
#   * NEW UDP probe: the UDP helper answers clear-text probes (no crypto) so a blocked UDP
#     port is told apart from a configuration problem, and the peer's clock offset is measured.
#   * NEW menu 12: change transport / UDP port on both sides without re-installing.
#   * NEW menu 13: sync the system clock from an HTTPS Date header (NTP is often blocked in
#     Iran; hourly key rotation needs both clocks within < 1 hour of each other).
#   * NEW pre-flight checks: other IPsec daemons, 10.10.10.0/24 used by another interface,
#     UDP port already taken, nftables/firewalld present, clock not synchronised.
#   * Watchdog no longer rebuilds the tunnel every few minutes before the peer has ever
#     answered (it destroyed the counters and firewall rules while the other side was
#     still being installed); after the first contact it behaves as before.
#   * UDP helper: restart race fixed (old socket must be gone before the new bind), stale
#     pid can no longer kill an unrelated process, bind errors are reported.
#   * Kernel self-test now also checks iproute2 if_id / encap support.
#   * Reply rule for probes in the firewall chain; awk package mapping fixed; fewer forks
#     in the watchdog loop (bash built-ins instead of date/cat/awk on every cycle).
#
#  Usage:  bash esp-tunnel.sh        (interactive menu, run as root)
#          esp-tunnel                (after first install)
#          esp-tunnel diag           (diagnosis without the menu)
# ==============================================================================

APP="esp-tunnel"
VERSION="2.4"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"
TUNE_ORIG="${CONF_DIR}/sysctl.orig"     # sysctl values of this server before the tuning

# Backhaul (reverse tunnel engine)
LIB_DIR="/usr/local/lib/${APP}"
BH_BIN="${LIB_DIR}/backhaul"
BH_CONF="${CONF_DIR}/backhaul.toml"
BH_CRT="${CONF_DIR}/backhaul.crt"         # self-signed certificate for wss / wssmux (Iran side)
BH_KEY="${CONF_DIR}/backhaul.key"
BH_UNIT="${APP}-backhaul"
BH_UNIT_FILE="/etc/systemd/system/${BH_UNIT}.service"
BH_REPO="Musixal/Backhaul"
BH_FALLBACK_TAG="v0.7.2"          # used when the latest tag cannot be resolved
DEFAULT_BH_PORT=8090              # control port, bound on the tunnel address only
DEFAULT_BH_TRANSPORT="tcp"
BH_HB_INTERVAL=15                 # server heartbeat (s)
MAX_FWD_PORTS=1000                # Backhaul opens one listener per forwarded port

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600          # key rotation period (seconds)
SEQ_STEP=1000000        # initial ESP sequence seed per second inside an epoch
MTU_ESP=1400
MTU_UDP=1380
DEFAULT_UDP_PORT=4500
DEFAULT_FORCE_REBUILD_SEC=43200   # 12h - unconditional preventive rebuild, 0 = disabled
DEFAULT_RX_STALL_SEC=45           # seconds of "tx moving, rx frozen" before an early rebuild

# ---- runtime state (filled by load_config) -----------------------------------
ROLE=""; MASTER=""; IRAN_IP=""; KHAREJ_IP=""; MODE="esp"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_ESP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
ENGINE=""; BH_PORT="$DEFAULT_BH_PORT"; BH_TARGET="127.0.0.1"; BH_AUTH=""; BH_TRANSPORT="$DEFAULT_BH_TRANSPORT"
MTU_SET=0; NET_TUNE=1            # MTU_SET 0 = automatic;  NET_TUNE 1 = BBR / buffer tuning on

# ---- daemon watchdog state (globals; meaningful only while cmd_daemon runs) --
RX0=0; TX0=0; RX_STALL_START=0; LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; XPREV=""
REB_N=0; BACKOFF_UNTIL=0; UP_SINCE=0; EVER_UP=0; CNT_RX=0; CNT_TX=0
PREV_BYTES=0; PING_RX0=0; BASE_POL=0; BASE_SA=0; PM_BEST=0; PM_REC=0

# UDP socket that lets the kernel decapsulate ESP-in-UDP. The kernel hands packets that start
# with four zero bytes (the "non-ESP marker") to user space: those are used as clear-text probes.
PY_UDP='
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
while True:
    try:
        d, a = s.recvfrom(2048)
        if d[:9] == b"\x00\x00\x00\x00ESPT?":
            s.sendto(b"\x00\x00\x00\x00ESPT!" + d[9:40] + b"|" + str(int(time.time() * 1000)).encode(), a)
    except Exception:
        time.sleep(0.05)
'

# Probe client: prints "<replies> <sent> <avg rtt ms | -> <peer clock offset s | ->"
PY_PROBE='
import socket, sys, time, os
host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
ok = 0
rtt = []
skew = []
for i in range(n):
    nonce = os.urandom(4).hex().encode()
    t0 = time.time()
    t1 = t0
    got = None
    try:
        s.sendto(b"\x00\x00\x00\x00ESPT?" + nonce, (host, port))
        while True:
            d, a = s.recvfrom(2048)
            t1 = time.time()
            if d.startswith(b"\x00\x00\x00\x00ESPT!" + nonce):
                got = d
                break
    except Exception:
        pass
    if got is not None:
        ok += 1
        rtt.append((t1 - t0) * 1000.0)
        try:
            skew.append(int(got.split(b"|")[1]) / 1000.0 - (t0 + t1) / 2.0)
        except Exception:
            pass
    time.sleep(0.2)
r = "%.0f" % (sum(rtt) / len(rtt)) if rtt else "-"
k = str(int(round(sum(skew) / len(skew)))) if skew else "-"
print(ok, n, r, k)
'

# Path-MTU probe: DF-marked probes of the given total IP sizes (descending); prints the first
# size that the peer answers (0 = none). The reply is tiny, so this measures our -> peer direction.
PY_PMTU='
import socket, sys, os
host, port = sys.argv[1], int(sys.argv[2])
sizes = [int(x) for x in sys.argv[3:]]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.8)
try:
    s.setsockopt(socket.IPPROTO_IP, 10, 2)   # IP_MTU_DISCOVER = IP_PMTUDISC_DO (sets DF)
except Exception:
    pass
best = 0
for size in sizes:
    pl = size - 28
    if pl < 40:
        continue
    nonce = os.urandom(4).hex().encode()
    pkt = (b"\x00\x00\x00\x00ESPT?" + nonce + b"." + b"x" * pl)[:pl]
    got = False
    for attempt in range(2):
        try:
            s.sendto(pkt, (host, port))
            while True:
                d, a = s.recvfrom(2048)
                if d.startswith(b"\x00\x00\x00\x00ESPT!" + nonce):
                    got = True
                    break
        except Exception:
            pass
        if got:
            break
    if got:
        best = size
        break
print(best)
'

# ------------------------------------------------------------------------------
#  Small helpers
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
err()  { echo "${C_R}[x]${C_0} $*" >&2; }
log()  { echo "[${APP}] $*"; }          # daemon logs (journald adds timestamps)
have() { command -v "$1" >/dev/null 2>&1; }
row()  { printf '  %-16s %s\n' "$1" "$2"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {   # confirm "question" [y|n]   (default answer)
  local def=${2:-n} a p="[y/N]"
  [[ $def == y ]] && p="[Y/n]"
  read -r -p "$1 $p " a
  a=${a:-$def}
  [[ $a =~ ^[Yy] ]]
}

pause() { read -r -p "Press Enter to continue..." _; }

valid_ip() {
  local o
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( 10#$o <= 255 )) || return 1
  done
  return 0
}

is_private_ip() {
  [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

valid_bh_transport() {
  case $1 in tcp|tcpmux|udp|ws|wss|wsmux|wssmux) return 0 ;; esac
  return 1
}

# "1080, 443 ,8000-8100"  ->  "1080,443,8000-8100"   (returns 1 if invalid)
norm_ports() {
  local raw=${1//[[:space:]]/} spec a b
  local -a out=() specs=()
  raw=${raw//،/,}
  [[ -n $raw ]] || return 1
  IFS=',' read -ra specs <<< "$raw"
  for spec in "${specs[@]}"; do
    [[ -z $spec ]] && continue
    if [[ $spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      valid_port "$a" && valid_port "$b" && (( 10#$a <= 10#$b )) || return 1
      out+=("$((10#$a))-$((10#$b))")
    else
      valid_port "$spec" || return 1
      out+=("$((10#$spec))")
    fi
  done
  (( ${#out[@]} > 0 )) || return 1
  local IFS=,
  echo "${out[*]}"
}

ports_include() {   # ports_include "1080,8000-8100" 8050
  local spec a b
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  for spec in "${specs[@]}"; do
    if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
    (( $2 >= a && $2 <= b )) && return 0
  done
  return 1
}

# "1080,8000-8002" -> one port per line, sorted, no duplicates
expand_ports() {
  local spec a b p
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  {
    for spec in "${specs[@]}"; do
      [[ -z $spec ]] && continue
      if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
      for (( p = 10#$a; p <= 10#$b; p++ )); do echo "$p"; done
    done
  } | sort -nu
}

ssh_ports() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  [[ -n $p ]] || p=$(ss -Hltnp 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]}')
  [[ -n $p ]] || p=22
  echo "$p ${SSH_CONNECTION##* }"
}

kdf() { printf '%s' "$1" | sha512sum | awk '{print $1}'; }

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Sets LOCAL_ADDR (our source address towards $1) and WAN_DEV
route_info() {
  local out
  out=$(ip -4 route get "$1" 2>/dev/null | head -n1)
  LOCAL_ADDR=$(awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")
  WAN_DEV=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")
  [[ -n $LOCAL_ADDR && -n $WAN_DEV ]]
}

detect_public_ip() {
  local addr pub
  addr=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
  if [[ -z $addr ]] || is_private_ip "$addr"; then
    if have curl; then
      pub=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null)
      valid_ip "$pub" && addr=$pub
    fi
  fi
  echo "$addr"
}

# ------------------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  ENGINE=""; BH_PORT=""; BH_TARGET=""; BH_TRANSPORT=""; MTU_SET=""; NET_TUNE=""
  # shellcheck disable=SC1090
  source "$CONF"
  MODE=${MODE:-esp}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  FORCE_REBUILD_SEC=${FORCE_REBUILD_SEC:-$DEFAULT_FORCE_REBUILD_SEC}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  # configs written by esp-tunnel 1.x have no engine: they keep the iptables DNAT behaviour
  ENGINE=${ENGINE:-dnat}; BH_PORT=${BH_PORT:-$DEFAULT_BH_PORT}; BH_TARGET=${BH_TARGET:-127.0.0.1}
  valid_bh_transport "${BH_TRANSPORT:-}" || BH_TRANSPORT=$DEFAULT_BH_TRANSPORT
  MTU_SET=${MTU_SET:-0}; NET_TUNE=${NET_TUNE:-1}
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  BH_AUTH=$(kdf "${MASTER}|backhaul|auth" | cut -c1-40)
  if [[ $MODE == udp ]]; then MTU=$MTU_UDP; else MTU=$MTU_ESP; fi
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config - contains the secret master key, keep private"
      printf 'ROLE=%q\n'      "$ROLE"
      printf 'MASTER=%q\n'    "$MASTER"
      printf 'IRAN_IP=%q\n'   "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n' "$KHAREJ_IP"
      printf 'MODE=%q\n'      "$MODE"
      printf 'UDP_PORT=%q\n'  "$UDP_PORT"
      printf 'PORTS=%q\n'     "$PORTS"
      printf 'FWD_PROTO=%q\n' "$FWD_PROTO"
      printf 'FORCE_REBUILD_SEC=%q\n' "$FORCE_REBUILD_SEC"
      printf 'RX_STALL_SEC=%q\n'      "$RX_STALL_SEC"
      printf 'ENGINE=%q\n'    "$ENGINE"
      printf 'BH_PORT=%q\n'   "$BH_PORT"
      printf 'BH_TARGET=%q\n' "$BH_TARGET"
      printf 'BH_TRANSPORT=%q\n' "$BH_TRANSPORT"
      printf 'MTU_SET=%q\n'  "$MTU_SET"
      printf 'NET_TUNE=%q\n' "$NET_TUNE"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

# token v3 = base64( v3|master|iran_ip|kharej_ip|mode|udp_port|ports|proto|engine|bh_port|bh_transport|bh_target|checksum )
# (v1 tokens and v2 tokens of the "dnat" engine are still accepted; v2 tokens of the old Rathole engine are not)
make_token() {
  local payload chk
  payload="v3|${MASTER}|${IRAN_IP}|${KHAREJ_IP}|${MODE}|${UDP_PORT}|${PORTS}|${FWD_PROTO}|${ENGINE}|${BH_PORT}|${BH_TRANSPORT}|${BH_TARGET}"
  chk=$(printf '%s' "$payload" | sha256sum | cut -c1-6)
  printf '%s|%s' "$payload" "$chk" | base64 -w0
}

T_MASTER=""; T_IRAN=""; T_KHAREJ=""; T_MODE=""; T_UDP=""; T_PORTS=""; T_PROTO=""; T_ENGINE=""; T_BHPORT=""; T_BHTR=""; T_BHTARGET=""
parse_token() {
  local t dec n chk want payload
  local -a F=()
  t=$(tr -d '[:space:]' <<<"$1")
  [[ -n $t ]] || return 1
  dec=$(base64 -d <<<"$t" 2>/dev/null) || return 1
  IFS='|' read -ra F <<< "$dec"
  n=${#F[@]}
  case ${F[0]} in
    v1) (( n == 9 ))  || return 1 ;;
    v2) (( n == 11 )) || return 1 ;;
    v3) (( n == 13 )) || return 1 ;;
    *)  return 1 ;;
  esac
  chk=${F[n-1]}
  payload=$(IFS='|'; printf '%s' "${F[*]:0:n-1}")
  want=$(printf '%s' "$payload" | sha256sum | cut -c1-6)
  [[ $chk == "$want" ]] || return 1
  T_MASTER=${F[1]}; T_IRAN=${F[2]}; T_KHAREJ=${F[3]}; T_MODE=${F[4]}; T_UDP=${F[5]}; T_PORTS=${F[6]}; T_PROTO=${F[7]}
  case ${F[0]} in
    v3) T_ENGINE=${F[8]}; T_BHPORT=${F[9]}; T_BHTR=${F[10]}; T_BHTARGET=${F[11]} ;;
    v2) T_ENGINE=${F[8]}; T_BHPORT=${F[9]}; T_BHTR=$DEFAULT_BH_TRANSPORT; T_BHTARGET=127.0.0.1 ;;
    *)  T_ENGINE=dnat;    T_BHPORT=$DEFAULT_BH_PORT; T_BHTR=$DEFAULT_BH_TRANSPORT; T_BHTARGET=127.0.0.1 ;;
  esac
  [[ $T_MASTER =~ ^[0-9a-f]{64}$ ]] || return 1
  valid_ip "$T_IRAN" && valid_ip "$T_KHAREJ" || return 1
  [[ $T_MODE == esp || $T_MODE == udp ]] || return 1
  valid_port "$T_UDP" || return 1
  [[ $T_PROTO == tcp || $T_PROTO == udp || $T_PROTO == both ]] || return 1
  [[ $T_ENGINE == backhaul || $T_ENGINE == dnat ]] || return 1
  valid_port "$T_BHPORT" || return 1
  valid_bh_transport "$T_BHTR" || return 1
  valid_ip "$T_BHTARGET" || return 1
  norm_ports "$T_PORTS" >/dev/null || return 1
  return 0
}

# ------------------------------------------------------------------------------
#  Pre-flight: dependencies, kernel support, conflicts, clock
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required (systemctl not found)."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum base64 awk od head; do
    have "$c" || missing+=("$c")
  done
  if [[ $MODE == udp ]] && ! have python3; then missing+=(python3); fi
  if [[ $ENGINE == backhaul ]]; then
    for c in tar gzip curl; do have "$c" || missing+=("$c"); done
    # the self-signed certificate of wss / wssmux is created on the Iran server only
    if [[ $ROLE == iran && ( $BH_TRANSPORT == wss || $BH_TRANSPORT == wssmux ) ]] && ! have openssl; then
      missing+=(openssl)
    fi
  fi
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing commands: ${missing[*]} (no supported package manager found)."; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss)   [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)    [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      awk)     pkgs+=(gawk) ;;
      iptables|python3|tar|gzip|curl|openssl) pkgs+=("$c") ;;
      *)       pkgs+=(coreutils) ;;
    esac
  done
  info "Installing missing packages: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  for c in "${missing[@]}"; do
    have "$c" || { err "Could not install '$c'. Install it manually and run again."; return 1; }
  done
  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 gcm aesni_intel nf_conntrack xt_TCPMSS iptable_nat iptable_filter iptable_mangle; do
    modprobe -q "$m" 2>/dev/null
  done
  return 0
}

check_kernel() {
  local t="espchk0" out virt k
  local -a enc=()
  virt=$(systemd-detect-virt 2>/dev/null)
  case $virt in
    openvz|lxc|lxc-libvirt) warn "Virtualization '$virt' detected - XFRM/IPsec normally does NOT work inside containers." ;;
  esac
  load_modules
  ip link del "$t" 2>/dev/null
  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "This system has no XFRM-interface support: $out"
    err "Needs Linux >= 4.19 (uname -r), iproute2 >= 5.0 and a real/KVM server (not OpenVZ/LXC)."
    return 1
  fi
  ip link del "$t" 2>/dev/null
  k=$(printf '%072d' 0)
  [[ $MODE == udp ]] && enc=(encap espinudp 4500 4500 0.0.0.0)
  if ! out=$(ip xfrm state add src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 reqid 4242 mode tunnel \
             aead 'rfc4106(gcm(aes))' "0x$k" 128 "${enc[@]}" if_id 4242 2>&1); then
    err "Cannot create an AES-GCM ESP state (kernel crypto, or iproute2 without if_id/encap support): $out"
    return 1
  fi
  ip xfrm state delete src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 2>/dev/null
  if ! out=$(ip xfrm policy add src 10.255.255.1/32 dst 10.255.255.2/32 dir out if_id 4242 \
             tmpl src 127.0.0.2 dst 127.0.0.3 proto esp reqid 4242 mode tunnel 2>&1); then
    err "Cannot create an XFRM policy with if_id (iproute2 too old?): $out"
    return 1
  fi
  ip xfrm policy delete src 10.255.255.1/32 dst 10.255.255.2/32 dir out if_id 4242 2>/dev/null
  return 0
}

clock_status() {
  local ntp=""
  have timedatectl && ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  echo "Clock (UTC)   : $(date -u '+%F %T')   NTP synchronized: ${ntp:-unknown}"
}

# Things that silently break the tunnel: warn before installing
preflight_check() {
  local p lst holder bad=0
  have systemctl && ! systemctl is-active --quiet "$APP" 2>/dev/null && udp_helper_stop   # stale helper of a crashed run
  if have pgrep; then
    for p in charon charon-systemd pluto racoon iked; do
      if pgrep -x "$p" >/dev/null 2>&1; then
        warn "IPsec daemon '${p}' is running - it can take over UDP 500/4500 and the XFRM policies and break this tunnel."
        bad=1
      fi
    done
  fi
  lst=$(ip -4 -o addr show 2>/dev/null | awk -v ifn="$IF_NAME" '$2 != ifn && $4 ~ /^10\.10\.10\./ {print "    addr  " $2 "  " $4}')
  lst+=$'\n'$(ip -4 route show 2>/dev/null | awk -v ifn="$IF_NAME" '$1 ~ /^10\.10\.10\./ && $0 !~ ("dev " ifn) {print "    route " $0}')
  lst=$(sed '/^[[:space:]]*$/d' <<< "$lst")
  if [[ -n $lst ]]; then
    err "Something else already uses the tunnel subnet 10.10.10.0/24 - tunnel traffic would be routed wrongly:"
    echo "$lst" >&2
    bad=1
  fi
  if [[ $MODE == udp ]] && ! systemctl is-active --quiet "$APP" 2>/dev/null; then
    if [[ -n $(ss -Hlun "sport = :${UDP_PORT}" 2>/dev/null) ]]; then
      holder=$(ss -Hlunp "sport = :${UDP_PORT}" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -n1)
      err "UDP port ${UDP_PORT} is already in use on this server ${holder}. Stop that service or choose another port."
      return 1
    fi
  fi
  if have nft; then
    lst=$(nft list tables 2>/dev/null | awk '$2 == "inet" || $2 == "netdev" || $2 == "bridge" {printf "%s/%s ", $2, $3}')
    [[ -n $lst ]] && warn "nftables tables present (${lst}): if one of them drops input traffic, allow the peer's tunnel packets and interface ${IF_NAME}."
  fi
  if have timedatectl && [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == no ]]; then
    warn "The system clock is not NTP-synchronised. Both servers must show the same UTC time (well under 1 hour apart) - see menu 13."
  fi
  if (( bad )); then confirm "Continue anyway?" n || return 1; fi
  return 0
}

# ------------------------------------------------------------------------------
#  Firewall (iptables, dedicated chains so cleanup is exact)
# ------------------------------------------------------------------------------
ipt() { iptables -w 5 "$@"; }

fw_chain_reset() {   # table chain hook-chain
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -N "$c" 2>/dev/null || ipt -t "$t" -F "$c"
  ipt -t "$t" -I "$h" 1 -j "$c"
}

fw_chain_remove() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -F "$c" 2>/dev/null
  ipt -t "$t" -X "$c" 2>/dev/null
}

fw_remove() {
  have iptables || return 0
  fw_chain_remove filter ESPT_IN   INPUT
  fw_chain_remove filter ESPT_FWD  FORWARD
  fw_chain_remove mangle ESPT_MSS  POSTROUTING
  fw_chain_remove nat    ESPT_PRE  PREROUTING
  fw_chain_remove nat    ESPT_POST POSTROUTING
}

fw_apply() {
  local spec d pr bp=tcp
  local -a specs=() protos=()

  # accept the tunnel transport from the peer + everything that comes out of the tunnel
  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $MODE == udp ]]; then
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --sport "$UDP_PORT" -j ACCEPT   # replies to our own probes
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi
  if [[ $ROLE == iran && $ENGINE == backhaul ]]; then
    # the Backhaul control port lives on the tunnel address only - never answer it from the WAN side
    [[ $BH_TRANSPORT == udp ]] && bp=udp
    ipt -I ESPT_IN 1 -i "$WAN_DEV" -p "$bp" -d "$IP_IRAN" --dport "$BH_PORT" -j DROP
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  # avoid fragmentation / PMTU black holes inside the tunnel
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

  # legacy engine only: iptables DNAT of the chosen ports to the Kharej tunnel address.
  # With the Backhaul engine there is NO DNAT - the Backhaul server owns the public ports.
  if [[ $ROLE == iran && $ENGINE == dnat ]]; then
    fw_chain_reset nat ESPT_PRE  PREROUTING
    fw_chain_reset nat ESPT_POST POSTROUTING
    case $FWD_PROTO in
      tcp) protos=(tcp) ;;
      udp) protos=(udp) ;;
      *)   protos=(tcp udp) ;;
    esac
    IFS=',' read -ra specs <<< "$PORTS"
    for spec in "${specs[@]}"; do
      [[ -z $spec ]] && continue
      d=${spec/-/:}
      for pr in "${protos[@]}"; do
        ipt -t nat -A ESPT_PRE ! -i "$IF_NAME" -p "$pr" --dport "$d" -j DNAT --to-destination "$IP_KHAREJ"
      done
    done
    # everything that enters the tunnel leaves with the tunnel address 10.10.10.2
    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" -j SNAT --to-source "$IP_IRAN"
  fi
  return 0
}

# transport packets from the peer accepted since the firewall chain was (re)loaded
outer_rx_count() {
  ipt -nvxL ESPT_IN 2>/dev/null | awk -v p="$PEER_PUB" -v m="$MODE" -v port="$UDP_PORT" '
    $3 == "ACCEPT" && $8 == p {
      if (m == "udp") { if ($4 == "udp" && $0 ~ ("dpt:" port "( |$)")) s += $1 }
      else if ($4 == "esp" || $4 == "50") s += $1
    }
    END { print s + 0 }'
}

# ---- inner MTU ---------------------------------------------------------------
# largest inner packet that still fits into an outer packet of <$1> bytes
# (outer IP 20 + [UDP 8] + ESP header 8 + IV 8 + ICV 16; ESP pads payload+2 to a multiple of 4)
mtu_fit() {
  local avail=$(( $1 - 20 - 8 - 8 - 16 ))
  [[ $MODE == udp ]] && avail=$(( avail - 8 ))
  echo $(( avail / 4 * 4 - 2 ))
}

# sets MTU: the manual value, otherwise the safe default - lowered when the WAN link MTU is small
calc_mtu() {
  local base wmtu="" fit
  if [[ $MODE == udp ]]; then base=$MTU_UDP; else base=$MTU_ESP; fi
  if [[ ${MTU_SET:-0} =~ ^[0-9]+$ ]] && (( MTU_SET >= 576 )); then MTU=$MTU_SET; return 0; fi
  MTU=$base
  [[ -r /sys/class/net/${WAN_DEV}/mtu ]] && wmtu=$(<"/sys/class/net/${WAN_DEV}/mtu")
  if [[ $wmtu =~ ^[0-9]+$ ]]; then
    fit=$(mtu_fit "$wmtu")
    (( fit < MTU )) && MTU=$fit
  fi
  (( MTU < 576 )) && MTU=576
  return 0
}

# ---- network tuning (BBR, bigger buffers ...) ----------------------------------
TUNE_KEYS="net.core.default_qdisc net.ipv4.tcp_congestion_control net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.netdev_max_backlog net.ipv4.tcp_mtu_probing net.ipv4.tcp_slow_start_after_idle net.netfilter.nf_conntrack_max"

tune_save_orig() {   # remember this server's values before the first change
  local k v
  [[ -f $TUNE_ORIG ]] && return 0
  mkdir -p "$CONF_DIR"
  for k in $TUNE_KEYS; do
    v=$(sysctl -n "$k" 2>/dev/null) || continue
    printf '%s=%s\n' "$k" "$v"
  done > "$TUNE_ORIG"
}

tune_restore() {     # put the original values back (tuning switched off / uninstall)
  local k v
  [[ -f $TUNE_ORIG ]] || return 0
  while IFS='=' read -r k v; do
    [[ -n $k ]] && sysctl -qw "${k}=${v}" >/dev/null 2>&1
  done < "$TUNE_ORIG"
  rm -f "$TUNE_ORIG"
}

tune_wanted() {      # "key value" for every setting this server should have - never lowers a value
  local cur a b c k
  modprobe -q tcp_bbr 2>/dev/null
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    echo "net.core.default_qdisc fq"
    echo "net.ipv4.tcp_congestion_control bbr"
  fi
  for k in net.core.rmem_max net.core.wmem_max; do
    cur=$(sysctl -n "$k" 2>/dev/null)
    [[ $cur =~ ^[0-9]+$ ]] || continue
    (( cur < 16777216 )) && cur=16777216
    echo "$k $cur"
  done
  for k in net.ipv4.tcp_rmem net.ipv4.tcp_wmem; do
    read -r a b c <<< "$(sysctl -n "$k" 2>/dev/null)"
    [[ $c =~ ^[0-9]+$ ]] || continue
    (( c < 16777216 )) && c=16777216
    echo "$k $a $b $c"
  done
  cur=$(sysctl -n net.core.netdev_max_backlog 2>/dev/null)
  if [[ $cur =~ ^[0-9]+$ ]]; then (( cur < 16384 )) && cur=16384; echo "net.core.netdev_max_backlog $cur"; fi
  cur=$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null)
  if [[ $cur =~ ^[0-9]+$ ]]; then [[ $cur == 0 ]] && cur=1; echo "net.ipv4.tcp_mtu_probing $cur"; fi
  if [[ -n $(sysctl -n net.ipv4.tcp_slow_start_after_idle 2>/dev/null) ]]; then echo "net.ipv4.tcp_slow_start_after_idle 0"; fi
  cur=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null)
  if [[ $cur =~ ^[0-9]+$ ]]; then (( cur < 131072 )) && cur=131072; echo "net.netfilter.nf_conntrack_max $cur"; fi
}

sysctl_apply() {
  local k v
  local -a lines=()
  if [[ $ENGINE == dnat ]]; then                 # only the legacy DNAT engine routes packets
    lines+=("net.ipv4.ip_forward = 1")
    sysctl -qw net.ipv4.ip_forward=1 >/dev/null 2>&1
  fi
  if [[ ${NET_TUNE:-1} == 1 ]]; then
    tune_save_orig
    while read -r k v; do
      [[ -n $k ]] || continue
      if sysctl -qw "${k}=${v}" >/dev/null 2>&1; then lines+=("${k} = ${v}"); fi
    done < <(tune_wanted)
  fi
  if (( ${#lines[@]} > 0 )); then printf '%s\n' "${lines[@]}" > "$SYSCTL_FILE"; else rm -f "$SYSCTL_FILE"; fi
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ------------------------------------------------------------------------------
#  Interface / policies / security associations
# ------------------------------------------------------------------------------
iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create interface $IF_NAME: $out"; return 1
  fi
  have nmcli && nmcli device set "$IF_NAME" managed no >/dev/null 2>&1
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || { log "ERROR: cannot set $LOCAL_INNER on $IF_NAME"; return 1; }
  calc_mtu
  ip link set "$IF_NAME" mtu "$MTU" up            || { log "ERROR: cannot bring $IF_NAME up"; return 1; }
  return 0
}

policies_remove() {
  local a b
  for a in "$IP_IRAN" "$IP_KHAREJ"; do
    if [[ $a == "$IP_IRAN" ]]; then b=$IP_KHAREJ; else b=$IP_IRAN; fi
    ip xfrm policy delete src "$a/32" dst "$b/32" dir out if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst "$b/32" dir in  if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null
  done
}

policies_setup() {
  local out
  policies_remove
  # out : only 10.10.10.local -> 10.10.10.peer may enter the tunnel
  # in  : only 10.10.10.peer  -> 10.10.10.local is accepted for this host
  # fwd : replies coming back through the tunnel (source must be the peer tunnel IP)
  out=$(ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy out: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy in: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy fwd: $out"; return 1; }
  return 0
}

# SA registry: one line per installed SA -> "<dir> <epoch> <spi> <src> <dst>"
sa_add() {   # sa_add <in|out> <epoch>
  local dir=$1 e=$2 src dst label spi key seq out
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL
  fi
  grep -q "^$dir $e " "$REG" 2>/dev/null && return 0

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)     # 32-byte AES key + 4-byte GCM salt
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
  if [[ $dir == out ]]; then
    # start the sequence counter high inside the epoch so a restart never reuses a GCM nonce
    seq=$(( ($(date +%s) % EPOCH_LEN) * SEQ_STEP ))
    if ! out=$(ip xfrm state add "${args[@]}" replay-oseq "$seq" 2>&1); then
      out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
      log "note: replay-oseq not supported by this iproute2, continuing without it"
    fi
  else
    out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {   # prune_sa <current-epoch>
  local e=$1 dir ep spi src dst keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      (( ep < e - 1 || ep > e + 1 )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
      log "removed expired SA ($dir, epoch $ep)"
    fi
  done < "$REG"
  cat "$tmp" > "$REG"
  rm -f "$tmp"
}

install_epoch() {   # newest outbound first, inbound for previous/current/next epoch
  local e=$1 x
  sa_add out "$e" || return 1
  for x in $((e - 1)) "$e" $((e + 1)); do
    sa_add in "$x" || return 1
  done
  prune_sa "$e"
  return 0
}

sa_flush() {
  local dir ep spi src dst
  if [[ -f $REG ]]; then
    while read -r dir ep spi src dst; do
      [[ -n $spi ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    done < "$REG"
  fi
  rm -f "$REG"
}

udp_helper_stop() {
  local pid i
  [[ -f $UDP_PID_FILE ]] || return 0
  pid=$(<"$UDP_PID_FILE")
  # only ever kill our own helper (a stale pid file may point at an unrelated process)
  if [[ $pid =~ ^[0-9]+$ ]] && { tr '\0' ' ' < "/proc/${pid}/cmdline"; } 2>/dev/null | grep -q 'ESPT'; then
    kill "$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
  fi
  rm -f "$UDP_PID_FILE"
  return 0
}

udp_helper_start() {   # holds the UDP socket that lets the kernel decapsulate ESP-in-UDP
  local pid i
  udp_helper_stop
  mkdir -p "$RUN_DIR"
  python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>"${RUN_DIR}/udp.err" &
  pid=$!
  echo "$pid" > "$UDP_PID_FILE"
  for i in 1 2 3 4 5 6 7 8; do
    sleep 0.25
    kill -0 "$pid" 2>/dev/null || break
    ss -Hlunp "sport = :${UDP_PORT}" 2>/dev/null | grep -q "pid=${pid}," && return 0
  done
  kill -0 "$pid" 2>/dev/null && return 0
  log "ERROR: cannot open UDP port ${UDP_PORT} for ESP-in-UDP (already in use?): $(tr '\n' ' ' < "${RUN_DIR}/udp.err" 2>/dev/null)"
  rm -f "$UDP_PID_FILE"
  return 1
}

# true when OUR helper is alive and was started for the configured UDP port
udp_helper_alive() {
  local pid cl
  [[ -f $UDP_PID_FILE ]] || return 1
  pid=$(<"$UDP_PID_FILE")
  [[ $pid =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  cl=$({ tr '\0' ' ' < "/proc/${pid}/cmdline"; } 2>/dev/null)
  [[ $cl == *ESPT* && $cl =~ [[:space:]]${UDP_PORT}[[:space:]]*$ ]]
}

udp_helper_ensure() { udp_helper_alive && return 0; udp_helper_start; }

teardown_all() {   # teardown_all [keep-helper]  - a rebuild keeps the UDP socket: no gap for incoming ESP
  fw_remove
  [[ ${1:-} == keep-helper ]] || udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  return 0
}

setup_all() {
  teardown_all keep-helper
  mkdir -p "$RUN_DIR"; : > "$REG"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  iface_setup            || return 1
  policies_setup         || return 1
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$CUR_EPOCH" || return 1
  if [[ $MODE == udp ]]; then udp_helper_ensure || return 1; fi
  sysctl_apply
  fw_apply
  log "tunnel up: role=$ROLE ${LOCAL_INNER} <-> ${PEER_INNER}  transport=$MODE  engine=$ENGINE  local=$LOCAL_ADDR($WAN_DEV) peer=$PEER_PUB mtu=$MTU epoch=$CUR_EPOCH"
  return 0
}

# ------------------------------------------------------------------------------
#  Backhaul core: download, config, service
# ------------------------------------------------------------------------------
bh_arch() {   # asset suffix of the official release for this CPU (backhaul_linux_<arch>.tar.gz)
  case $(uname -m) in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) return 1 ;;
  esac
}

# a Go binary: -v prints the version; -h / --version are fallbacks for other builds
bh_works() {
  [[ -x $1 ]] || return 1
  "$1" -v >/dev/null 2>&1 || "$1" --version >/dev/null 2>&1 || "$1" -h >/dev/null 2>&1
}

bh_version() {
  local v
  v=$("$BH_BIN" -v 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -n1)
  echo "${v:-?}"
}

# latest release tag WITHOUT the rate-limited GitHub API (follows the /releases/latest redirect)
bh_latest_tag() {
  local tag
  have curl || return 1
  tag=$(curl -fsSL --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${BH_REPO}/releases/latest" 2>/dev/null | sed 's#.*/tag/##')
  [[ $tag =~ ^v[0-9]+(\.[0-9]+)+$ ]] && echo "$tag"
}

bh_install_from() {   # bh_install_from <tar.gz-or-binary>  -> $BH_BIN
  local f=$1 tmp magic
  [[ -f $f ]] || { err "File not found: $f"; return 1; }
  tmp=$(mktemp -d)
  magic=$(head -c2 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  if [[ $magic == 1f8b ]]; then                       # gzip -> the official release archive
    tar -xzf "$f" -C "$tmp" 2>/dev/null || { err "Cannot extract $f"; rm -rf "$tmp"; return 1; }
    f=$(find "$tmp" -type f -name backhaul | head -n1)
    [[ -n $f ]] || { err "No 'backhaul' binary inside the archive."; rm -rf "$tmp"; return 1; }
  fi
  mkdir -p "$LIB_DIR"
  install -m 755 "$f" "${BH_BIN}.new" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  if ! bh_works "${BH_BIN}.new"; then
    rm -f "${BH_BIN}.new"
    err "This backhaul binary does not run on this system (wrong CPU, or not a Linux build)."
    return 1
  fi
  mv -f "${BH_BIN}.new" "$BH_BIN"      # atomic: safe even while the old binary is running
}

bh_fetch() {   # bh_fetch <url> -> installs it
  local tmp rc
  tmp=$(mktemp)
  curl -fL -sS --retry 2 --connect-timeout 10 --max-time 180 -o "$tmp" "$1" && bh_install_from "$tmp"
  rc=$?
  rm -f "$tmp"
  return $rc
}

# ensure_backhaul [force]   force = download again even if a core is already installed
ensure_backhaul() {
  local force=${1:-} tag arch ans
  if [[ -z $force ]] && bh_works "$BH_BIN"; then
    ok "Backhaul core is already installed (v$(bh_version))."
    return 0
  fi
  # a backhaul that another script already put on this server can be reused - handy when GitHub is blocked
  if [[ -z $force ]] && have backhaul && bh_install_from "$(command -v backhaul)"; then
    ok "Reused the backhaul found in PATH (v$(bh_version))."
    return 0
  fi
  if arch=$(bh_arch); then
    tag=$(bh_latest_tag)
    if [[ -n $tag ]]; then
      info "Downloading Backhaul ${tag} (linux ${arch})..."
      if bh_fetch "https://github.com/${BH_REPO}/releases/download/${tag}/backhaul_linux_${arch}.tar.gz"; then
        ok "Backhaul ${tag} installed."; return 0
      fi
    fi
    if [[ $tag != "$BH_FALLBACK_TAG" ]]; then
      info "Trying Backhaul ${BH_FALLBACK_TAG}..."
      if bh_fetch "https://github.com/${BH_REPO}/releases/download/${BH_FALLBACK_TAG}/backhaul_linux_${arch}.tar.gz"; then
        ok "Backhaul ${BH_FALLBACK_TAG} installed."; return 0
      fi
    fi
    warn "Could not download Backhaul (is GitHub reachable from this server?)."
  else
    warn "No official Backhaul build for this CPU architecture ($(uname -m))."
  fi
  echo "Give a direct URL (a mirror) or a local path to a backhaul .tar.gz / binary you uploaded (scp), or press Enter to abort."
  read -r -p "URL or path: " ans
  [[ -n $ans ]] || return 1
  if [[ $ans =~ ^https?:// ]]; then bh_fetch "$ans"; else bh_install_from "$ans"; fi || return 1
  ok "Backhaul installed (v$(bh_version))."
  return 0
}

# ports that are already listening on this server (Backhaul of THIS tunnel excluded)
busy_ports() {   # busy_ports "<norm ports>" -> space separated list
  local mp used p
  mp=$(systemctl show -p MainPID --value "$BH_UNIT" 2>/dev/null); mp=${mp:-0}
  used=$(ss -Hltunp 2>/dev/null | awk -v mp="$mp" '
    mp != 0 && index($0, "pid=" mp ",") { next }
    { n = split($5, a, ":"); print a[n] }' | sort -u)
  for p in $(expand_ports "$1"); do
    grep -qx "$p" <<< "$used" && printf '%s ' "$p"
  done
  return 0
}

# the "ports = [...]" array of the Iran (server) config. Without a custom target the list is written as
# given (single ports and ranges, forwarded to the same port on the Kharej side). With a custom target
# address every port becomes an explicit "port=target:port" mapping.
bh_ports_toml() {
  local spec p i n
  local -a specs=() items=()
  if [[ ${BH_TARGET:-127.0.0.1} == 127.0.0.1 ]]; then
    IFS=',' read -ra specs <<< "$PORTS"
    for spec in "${specs[@]}"; do
      [[ -n $spec ]] && items+=("\"${spec}\"")
    done
  else
    for p in $(expand_ports "$PORTS"); do
      items+=("\"${p}=${BH_TARGET}:${p}\"")
    done
  fi
  n=${#items[@]}
  echo "ports = ["
  for (( i = 0; i < n; i++ )); do
    if (( i < n - 1 )); then echo "${items[i]},"; else echo "${items[i]}"; fi
  done
  echo "]"
}

bh_mux_toml() {   # SMUX settings shared by tcpmux / wsmux / wssmux (the key name is spelled this way upstream)
  echo "mux_version = 1"
  echo "mux_framesize = 32768"
  echo "mux_recievebuffer = 4194304"
  echo "mux_streambuffer = 65536"
}

# wss / wssmux: self-signed certificate on the Iran server (the Backhaul client does not verify it)
bh_tls_ensure() {
  [[ -s $BH_CRT && -s $BH_KEY ]] && return 0
  have openssl || { log "ERROR: openssl is needed for the ${BH_TRANSPORT} transport (apt install openssl)"; return 1; }
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$BH_KEY" -out "$BH_CRT" -days 3650 -subj "/CN=${IP_IRAN}" >/dev/null 2>&1
  ) || { log "ERROR: cannot create the TLS certificate"; rm -f "$BH_KEY" "$BH_CRT"; return 1; }
  chmod 600 "$BH_KEY" "$BH_CRT"
  log "created a self-signed TLS certificate for ${BH_TRANSPORT}: ${BH_CRT}"
  return 0
}

bh_write_config() {
  [[ -n $BH_AUTH ]] || { log "ERROR: backhaul config needs the master key"; return 1; }
  if [[ $ROLE == iran ]]; then
    [[ -n $PORTS ]] || { log "ERROR: backhaul server config needs a port list"; return 1; }
    if [[ $BH_TRANSPORT == wss || $BH_TRANSPORT == wssmux ]]; then bh_tls_ensure || return 1; fi
  fi
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# generated by ${APP} - changes are overwritten"
      if [[ $ROLE == iran ]]; then
        echo "[server]"
        echo "bind_addr = \"${LOCAL_INNER}:${BH_PORT}\""
        echo "transport = \"${BH_TRANSPORT}\""
        echo "token = \"${BH_AUTH}\""
        echo "heartbeat = ${BH_HB_INTERVAL}"
        echo "channel_size = 2048"
        if [[ $BH_TRANSPORT != udp ]]; then
          echo "keepalive_period = 20"
          echo "nodelay = true"
        fi
        # UDP inside the TCP tunnel exists for the plain tcp transport only
        if [[ $BH_TRANSPORT == tcp && $FWD_PROTO != tcp ]]; then echo "accept_udp = true"; fi
        if [[ $BH_TRANSPORT == *mux ]]; then
          echo "mux_con = 8"
          bh_mux_toml
        fi
        if [[ $BH_TRANSPORT == wss || $BH_TRANSPORT == wssmux ]]; then
          echo "tls_cert = \"${BH_CRT}\""
          echo "tls_key = \"${BH_KEY}\""
        fi
        echo "sniffer = false"
        echo "web_port = 0"
        echo "log_level = \"info\""
        bh_ports_toml
      else
        echo "[client]"
        echo "remote_addr = \"${PEER_INNER}:${BH_PORT}\""
        echo "transport = \"${BH_TRANSPORT}\""
        echo "token = \"${BH_AUTH}\""
        echo "connection_pool = 8"
        echo "aggressive_pool = false"
        if [[ $BH_TRANSPORT != udp ]]; then
          echo "keepalive_period = 20"
          echo "dial_timeout = 10"
          echo "nodelay = true"
        fi
        echo "retry_interval = 1"
        if [[ $BH_TRANSPORT == *mux ]]; then bh_mux_toml; fi
        echo "sniffer = false"
        echo "web_port = 0"
        echo "log_level = \"info\""
      fi
    } > "${BH_CONF}.new"
  )
  chmod 600 "${BH_CONF}.new" && mv -f "${BH_CONF}.new" "$BH_CONF"
}

write_bh_unit() {
  cat > "$BH_UNIT_FILE" <<EOF
[Unit]
Description=Backhaul reverse tunnel over the ESP tunnel (${APP})
After=network-online.target ${APP}.service
Requires=${APP}.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} bh-run
Restart=always
RestartSec=3
OOMScoreAdjust=-500
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

# units of the old Rathole engine (esp-tunnel 2.0 - 2.3) are switched off and removed
legacy_rathole_cleanup() {
  local u="${APP}-rathole"
  if [[ -f /etc/systemd/system/${u}.service ]]; then
    systemctl disable --now "$u" >/dev/null 2>&1
    rm -f "/etc/systemd/system/${u}.service"
    systemctl daemon-reload
  fi
  return 0
}

# runs under systemd: wait for the tunnel address, then become backhaul
cmd_bh_run() {
  local mode
  load_config || { log "ERROR: missing or invalid $CONF"; exit 1; }
  [[ $ENGINE == backhaul ]] || { log "ERROR: engine is '$ENGINE', not backhaul"; exit 1; }
  bh_works "$BH_BIN" || { log "ERROR: backhaul core missing at $BH_BIN (menu option 10)"; exit 1; }
  [[ -s $BH_CONF ]] || bh_write_config || exit 1
  for _ in $(seq 1 60); do
    ip -4 addr show dev "$IF_NAME" 2>/dev/null | grep -q "inet ${LOCAL_INNER}/" && break
    sleep 1
  done
  if [[ $ROLE == iran ]]; then mode=server; else mode=client; fi
  log "[backhaul] starting as ${ROLE} (${mode}), transport ${BH_TRANSPORT}, control ${IP_IRAN}:${BH_PORT}, core v$(bh_version)"
  exec "$BH_BIN" -c "$BH_CONF"
}

start_backhaul() {
  legacy_rathole_cleanup
  if [[ $ENGINE != backhaul ]]; then
    systemctl disable --now "$BH_UNIT" >/dev/null 2>&1
    rm -f "$BH_UNIT_FILE"
    return 0
  fi
  bh_works "$BH_BIN" || { err "Backhaul core is missing - use menu option 10."; return 1; }
  bh_write_config    || return 1
  write_bh_unit
  systemctl daemon-reload
  systemctl enable "$BH_UNIT" >/dev/null 2>&1
  systemctl restart "$BH_UNIT"
  sleep 2
  if systemctl is-active --quiet "$BH_UNIT"; then
    ok "Backhaul reverse-tunnel service is running (transport: ${BH_TRANSPORT})."
    return 0
  fi
  err "Backhaul service failed to start. Last log lines:"
  journalctl -u "$BH_UNIT" -n 25 --no-pager
  return 1
}

# number of established TCP connections on the Backhaul control port (control + data channels).
# The udp transport has no TCP sessions to count: "n/a"
bh_conn_count() {
  if [[ $BH_TRANSPORT == udp ]]; then echo "n/a"; return 0; fi
  ss -Htn state established 2>/dev/null | awk -v a="${IP_IRAN}:${BH_PORT}" \
    '{for(i=1;i<=NF;i++) if($i==a){c++; break}} END{print c+0}'
}

# "<ports listening>/<ports configured>" on the Iran server
bh_listen_summary() {
  local used p n=0 t=0
  used=$(ss -Hltun 2>/dev/null | awk '{k=split($5,a,":"); print a[k]}' | sort -u)
  for p in $(expand_ports "$PORTS"); do
    t=$((t + 1))
    grep -qx "$p" <<< "$used" && n=$((n + 1))
  done
  echo "$n/$t"
}

# after an ESP rebuild the tunnel address is recreated - make sure the Backhaul server still listens on it
bh_post_rebuild() {
  local fl=-Hltn
  [[ $ENGINE == backhaul && $ROLE == iran ]] || return 0
  systemctl is-active --quiet "$BH_UNIT" 2>/dev/null || return 0
  [[ $BH_TRANSPORT == udp ]] && fl=-Hlun
  if ! ss "$fl" "sport = :${BH_PORT}" 2>/dev/null | grep -q "${LOCAL_INNER}:${BH_PORT}"; then
    log "backhaul control listener missing after the rebuild - restarting backhaul"
    systemctl restart --no-block "$BH_UNIT"
  fi
}

# ------------------------------------------------------------------------------
#  Watchdog helpers: interface counters, xfrm error counters, forensic dump
# ------------------------------------------------------------------------------
read_counters() {   # sets CNT_RX / CNT_TX (bytes) without forking
  local d="/sys/class/net/${IF_NAME}/statistics"
  CNT_RX=0; CNT_TX=0
  [[ -r $d/rx_bytes ]] && CNT_RX=$(<"$d/rx_bytes")
  [[ -r $d/tx_bytes ]] && CNT_TX=$(<"$d/tx_bytes")
  return 0
}

# "<packets sent> <packets received+decrypted>" summed over this tunnel's loaded SAs
xfrm_pkt_counts() {
  route_info "$PEER_PUB" >/dev/null 2>&1
  ip -s xfrm state 2>/dev/null | awk -v la="$LOCAL_ADDR" -v pa="$PEER_PUB" '
    $1 == "src" { cur = ""; if ($2 == la && $4 == pa) cur = "out"; else if ($2 == pa && $4 == la) cur = "in"; next }
    /lifetime current:/ { getline; if (cur != "" && match($0, /[0-9]+\(packets\)/)) s[cur] += substr($0, RSTART, RLENGTH - 9); next }
    END { printf "%d %d\n", s["out"], s["in"] }'
}

xfrm_nonzero_counters() {   # e.g. "XfrmInStateProtoError=3 XfrmInTmplMismatch=1"
  awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null
}

# Dumps SA state, interface counters, xfrm error counters and recent *kernel*
# log so a rebuild that just happened is still diagnosable afterwards.
# Uses fd 3 for the SA-registry loop so the inner pipelines don't fight over stdin.
forensic_snapshot() {
  local reason=$1 dir ep spi src dst line
  log "----- forensic snapshot: ${reason} -----"
  if [[ -s $REG ]]; then
    while read -r dir ep spi src dst <&3; do
      [[ -n $spi ]] || continue
      ip xfrm state get src "$src" dst "$dst" proto esp spi "$spi" 2>&1 | while IFS= read -r line; do
        log "xfrm-state (${dir}/epoch ${ep}): ${line}"
      done
    done 3< "$REG"
  fi
  ip -s link show "$IF_NAME" 2>&1 | while IFS= read -r line; do log "link: ${line}"; done
  local x; x=$(xfrm_nonzero_counters)
  log "xfrm error counters: ${x:-none (clean)}"
  log "outer packets accepted from the peer since the last rule load: $(outer_rx_count)"
  journalctl -k -n 40 --no-pager 2>/dev/null | while IFS= read -r line; do log "kernel: ${line}"; done
  log "----- end forensic snapshot -----"
}

# Common rebuild path for every watchdog trigger: logs (with or without a full
# forensic dump), tears down + rebuilds, and resets all watchdog counters so
# the freshly-rebuilt tunnel gets a clean slate.
watchdog_rebuild() {   # watchdog_rebuild "<reason>" [skip-forensic]
  local reason=$1 back
  if [[ ${2:-} == skip-forensic ]]; then
    log "$reason"
  else
    forensic_snapshot "$reason"
  fi
  if route_info "$PEER_PUB" && setup_all; then
    log "rebuild complete"
    xfrm_baseline
    bh_post_rebuild
  else
    log "ERROR: rebuild attempt failed, will retry next cycle"
  fi
  printf -v LAST_REBUILD '%(%s)T' -1
  UP_SINCE=0
  # unscheduled rebuilds that do not bring the link back: back off instead of repeating every minute
  if [[ ${2:-} != skip-forensic ]]; then
    REB_N=$(( REB_N + 1 ))
    if (( REB_N >= 3 )); then
      back=$(( 120 * (REB_N - 2) )); (( back > 900 )) && back=900
      BACKOFF_UNTIL=$(( LAST_REBUILD + back ))
      log "WARN: ${REB_N} rebuilds in a row did not bring the link back - next automatic rebuild in ${back}s at the earliest"
      if (( REB_N == 3 )); then
        log "HINT: a rebuild cannot fix a network that drops the packets. Run the diagnosis (menu 11) on BOTH servers;"
        log "HINT: if one side sends ESP but the other receives none, change transport/port (menu 12)."
      fi
    fi
  fi
  RX_STALL_START=0
  FAILS=0
  PEER_STATE="unknown"
  read_counters; RX0=$CNT_RX; TX0=$CNT_TX
}

# ------------------------------------------------------------------------------
#  Daemon (runs under systemd): setup, hourly key rotation, health watchdog
# ------------------------------------------------------------------------------
# policy / state counts right after a (re)build: the self-check later compares against THESE
# numbers, so a different `ip xfrm` output format can never cause false rebuilds
xfrm_baseline() {
  BASE_POL=$(ip xfrm policy 2>/dev/null | grep -cE "^src (${IP_IRAN}|${IP_KHAREJ})/32")
  BASE_SA=$(ip xfrm state 2>/dev/null | grep -cE "^src (${LOCAL_ADDR}|${PEER_PUB}) dst (${LOCAL_ADDR}|${PEER_PUB})")
}

# SIGHUP: re-read the settings that may change at run time (no restart -> connections survive)
wd_reload() {
  local v
  v=$(bash -c 'source "$1" >/dev/null 2>&1; echo "${FORCE_REBUILD_SEC:-x} ${RX_STALL_SEC:-x} ${MTU_SET:-0} ${NET_TUNE:-1} ${BH_TRANSPORT:-tcp}"' _ "$CONF" 2>/dev/null)
  read -r FORCE_REBUILD_SEC RX_STALL_SEC MTU_SET NET_TUNE BH_TRANSPORT <<< "$v"
  [[ $FORCE_REBUILD_SEC =~ ^[0-9]+$ ]] || FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  [[ $RX_STALL_SEC =~ ^[0-9]+$ ]]      || RX_STALL_SEC=$DEFAULT_RX_STALL_SEC
  [[ $MTU_SET =~ ^[0-9]+$ ]]           || MTU_SET=0
  [[ $NET_TUNE == 0 ]]                 || NET_TUNE=1
  valid_bh_transport "$BH_TRANSPORT"   || BH_TRANSPORT=$DEFAULT_BH_TRANSPORT
  log "settings reloaded: rx-stall ${RX_STALL_SEC}s, preventive rebuild ${FORCE_REBUILD_SEC}s, mtu-set ${MTU_SET}, tuning ${NET_TUNE}, backhaul transport ${BH_TRANSPORT}"
}

cmd_daemon() {
  local tries=0 last_fix=0 last_xwarn=0 e now xcur tick=0 rate la wd chk n_pol n_sa
  load_config || { log "ERROR: missing or invalid $CONF"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT
  trap 'wd_reload' HUP

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB after 60s"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  xfrm_baseline
  printf -v LAST_REBUILD '%(%s)T' -1
  read_counters; RX0=$CNT_RX; TX0=$CNT_TX; PREV_BYTES=$(( CNT_RX + CNT_TX ))
  XPREV=$(xfrm_nonzero_counters)
  EVER_UP=0
  log "watchdog active: rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"
  log "waiting for the peer $PEER_INNER (the other side must be installed and its service running)"

  while true; do
    sleep 5 &
    wait $!
    printf -v now '%(%s)T' -1
    tick=$(( tick + 1 ))
    read_counters
    rate=$(( CNT_RX + CNT_TX - PREV_BYTES )); PREV_BYTES=$(( CNT_RX + CNT_TX ))   # bytes since the last cycle
    (( rate < 0 )) && rate=0

    # --- hourly key rotation (make-before-break, no packet loss) ---
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; xfrm_baseline; else log "WARN: key rotation failed, will retry"; fi
    fi

    # --- preventive rebuild (the "every 12h" safety net) - waits for a quiet moment, at most 1 h ---
    if (( FORCE_REBUILD_SEC > 0 && now - LAST_REBUILD >= FORCE_REBUILD_SEC )); then
      if (( rate > 250000 && now - LAST_REBUILD < FORCE_REBUILD_SEC + 3600 )); then
        (( tick % 12 == 0 )) && log "preventive rebuild postponed: the tunnel is busy (runs when quiet, at the latest in 1 h)"
      else
        watchdog_rebuild "scheduled preventive rebuild (every $((FORCE_REBUILD_SEC/3600))h)" skip-forensic
        continue
      fi
    fi

    # --- interface missing ---
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface $IF_NAME vanished"
      continue
    fi

    # --- every 30 s: self-healing checks (no need to wait for ping failures) ---
    if (( tick % 6 == 0 )); then
      xcur=$(xfrm_nonzero_counters)
      if [[ -n $xcur && $xcur != "$XPREV" ]] && (( now - last_xwarn >= 300 )); then
        log "WARN: xfrm error counters changed: $xcur"
        last_xwarn=$now
      fi
      XPREV=$xcur

      # firewall rules removed by ufw / firewalld / netfilter-persistent / iptables-restore
      if ! ipt -C INPUT -j ESPT_IN >/dev/null 2>&1; then
        log "WARN: the tunnel firewall rules were removed by something else - restoring them"
        fw_apply
      fi
      # the UDP helper holds the encap socket: without it the kernel cannot receive ESP-in-UDP at all
      if [[ $MODE == udp ]] && ! udp_helper_alive; then
        log "WARN: the UDP helper is not running - restarting it"
        udp_helper_start || log "ERROR: cannot restart the UDP helper"
      fi
      # local IP / default route / NIC name changed (DHCP renew, failover, rename)
      la=$LOCAL_ADDR; wd=$WAN_DEV
      if route_info "$PEER_PUB"; then
        if [[ $LOCAL_ADDR != "$la" || $WAN_DEV != "$wd" ]]; then
          watchdog_rebuild "local address/route to the peer changed (${la}/${wd} -> ${LOCAL_ADDR}/${WAN_DEV})" skip-forensic
          continue
        fi
      else
        LOCAL_ADDR=$la; WAN_DEV=$wd
      fi
      # address / policies / states flushed by someone else (compared with the numbers right after the last build)
      if (( now - LAST_REBUILD >= 60 )); then
        chk=""
        ip -4 addr show dev "$IF_NAME" 2>/dev/null | grep -q "inet ${LOCAL_INNER}/" || chk="tunnel address ${LOCAL_INNER} is gone"
        if [[ -z $chk ]]; then
          n_pol=$(ip xfrm policy 2>/dev/null | grep -cE "^src (${IP_IRAN}|${IP_KHAREJ})/32")
          (( n_pol >= BASE_POL )) || chk="xfrm policies were removed (${n_pol}/${BASE_POL})"
        fi
        if [[ -z $chk ]]; then
          n_sa=$(ip xfrm state 2>/dev/null | grep -cE "^src (${LOCAL_ADDR}|${PEER_PUB}) dst (${LOCAL_ADDR}|${PEER_PUB})")
          (( n_sa >= BASE_SA )) || chk="xfrm states were removed (${n_sa}/${BASE_SA})"
        fi
        if [[ -n $chk ]]; then
          watchdog_rebuild "integrity check: ${chk}" skip-forensic
          continue
        fi
      fi
    fi

    # --- asymmetric blackout: outbound flowing, nothing received. Only after the peer has
    #     answered at least once - before that "no inbound" is normal (peer not installed yet) ---
    if (( EVER_UP && CNT_TX > TX0 && CNT_RX == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      if (( now - RX_STALL_START >= RX_STALL_SEC && now >= BACKOFF_UNTIL )); then
        watchdog_rebuild "asymmetric blackout: no inbound traffic for ${RX_STALL_SEC}s while outbound is active"
        continue
      fi
    else
      RX_STALL_START=0; RX0=$CNT_RX; TX0=$CNT_TX
    fi

    # --- ping watchdog (also exercises the path when otherwise idle) ---
    if ping -c1 -W2 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      if [[ $PEER_STATE != up ]]; then log "peer $PEER_INNER reachable - tunnel UP"; fi
      PEER_STATE=up; FAILS=0; EVER_UP=1
      (( UP_SINCE == 0 )) && UP_SINCE=$now
      if (( now - UP_SINCE >= 120 )); then REB_N=0; BACKOFF_UNTIL=0; fi   # stable for 2 min: forget past failures
    else
      UP_SINCE=0
      (( FAILS == 0 )) && PING_RX0=$CNT_RX
      FAILS=$(( FAILS + 1 ))
      if (( FAILS == 3 )); then PEER_STATE=down; log "peer $PEER_INNER not answering for ~15s"; fi
      if (( FAILS >= 12 )); then
        if (( CNT_RX - PING_RX0 > 50000 )); then
          # a saturated link can lose pings while data still flows: a rebuild would only hurt
          log "pings are lost but real traffic still arrives - the link is alive, not rebuilding"
          PING_RX0=$CNT_RX
        elif (( now - last_fix >= 180 && now >= BACKOFF_UNTIL )); then
          last_fix=$now
          if (( EVER_UP || REB_N == 0 )); then
            watchdog_rebuild "peer unreachable (ping) for 60s+"
          else
            log "still no answer from $PEER_INNER (never reached since start) - not rebuilding; run the diagnosis (menu 11) on both servers"
          fi
        fi
        FAILS=3
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }

cmd_fw() {
  load_config || exit 1
  route_info "$PEER_PUB" || exit 1
  fw_apply
  log "firewall / port-forward rules reloaded"
}

# ------------------------------------------------------------------------------
#  Installation helpers
# ------------------------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  if [[ ! -f $src ]]; then
    err "Save this script to a file first (bash esp-tunnel.sh); it cannot install itself from a pipe."
    return 1
  fi
  if [[ $src != "$BIN" ]]; then
    install -m 755 "$src" "$BIN" || return 1
  fi
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP (IP protocol 50) tunnel (${APP})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} teardown
Restart=always
RestartSec=3
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    [[ -s $REG ]] && ip link show "$IF_NAME" >/dev/null 2>&1 && break
  done
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service is running (auto-starts on boot)."
  else
    err "Service failed to start. Last log lines:"
    journalctl -u "$APP" -n 25 --no-pager
    return 1
  fi
  start_backhaul
}

wait_link() {   # wait_link <seconds>  -> 0 as soon as the peer answers a ping through the tunnel
  local i t=${1:-15}
  for (( i = 0; i < t; i++ )); do
    ping -c1 -W1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "A tunnel is already configured on this server (role: $ROLE)."
    confirm "Re-install and overwrite it?" n || return 1
  fi
  return 0
}

ask_ports() {
  local raw norm p spec cnt busy
  local -a sp=()
  while true; do
    read -r -p "Ports to open on the Iran server (comma separated, e.g. 1080,443,8000-8100): " raw
    if ! norm=$(norm_ports "$raw"); then
      err "Invalid list. Use numbers 1-65535 separated by commas (ranges like 8000-8100 are allowed)."
      continue
    fi
    for p in $(ssh_ports); do
      [[ $p =~ ^[0-9]+$ ]] || continue
      if ports_include "$norm" "$p"; then
        err "Port $p is the SSH port of this server - forwarding it would lock you out. Remove it."
        continue 2
      fi
    done
    if [[ $ENGINE == backhaul ]]; then
      cnt=$(expand_ports "$norm" | wc -l)
      if (( cnt > MAX_FWD_PORTS )); then
        err "$cnt ports requested - Backhaul opens one listener per port, the limit here is $MAX_FWD_PORTS."
        continue
      fi
      if ports_include "$norm" "$BH_PORT"; then
        err "Port $BH_PORT is reserved for the Backhaul control channel. Remove it."
        continue
      fi
      if [[ $MODE == udp ]] && ports_include "$norm" "$UDP_PORT"; then
        err "Port $UDP_PORT is used by the ESP-in-UDP transport itself. Remove it from the list."
        continue
      fi
      busy=$(busy_ports "$norm")
      if [[ -n $busy ]]; then
        err "Already used by a local service on this server: ${busy}- Backhaul could not open them. Free them or choose other ports."
        continue
      fi
    fi
    PORTS=$norm
    break
  done
  if [[ $ENGINE != backhaul ]]; then
    IFS=',' read -ra sp <<< "$PORTS"
    for spec in "${sp[@]}"; do
      [[ $spec == *-* ]] && continue
      if [[ -n $(ss -Hltun "sport = :$spec" 2>/dev/null) ]]; then
        warn "Port $spec is already used by a local service here; after forwarding, connections to it will go to Kharej instead."
      fi
    done
  fi
}

ask_transport() {
  local c
  echo
  echo "Transport:"
  echo "  1) Raw ESP - IP protocol 50   (fastest, smallest overhead - but many providers/ISPs drop protocol 50:"
  echo "                                 the tunnel then never comes up, or works only for a few seconds / one way)"
  echo "  2) ESP-in-UDP                 (recommended between Iran and abroad: looks like ordinary UDP, survives NAT)"
  read -r -p "Select [2]: " c
  if [[ ${c:-2} == 1 ]]; then
    MODE=esp
    UDP_PORT=$DEFAULT_UDP_PORT
  else
    MODE=udp
    while true; do
      read -r -p "UDP port for ESP-in-UDP [${DEFAULT_UDP_PORT}]: " UDP_PORT
      UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}
      valid_port "$UDP_PORT" && break
      err "Invalid port."
    done
    echo "Remember: UDP ${UDP_PORT} must be open in BOTH servers' external/cloud firewalls."
    echo "If the tunnel does not come up, try another port later (menu 12) - 4500 is the well-known IPsec NAT-T port and is filtered on some networks."
  fi
}

# Backhaul transport = the protocol of the reverse tunnel that runs INSIDE the ESP tunnel.
# Chosen on the Iran server; the Kharej side takes it from the token.
ask_bh_transport() {
  local c def=1
  case ${BH_TRANSPORT:-tcp} in
    tcp) def=1 ;; tcpmux) def=2 ;; udp) def=3 ;; ws) def=4 ;; wss) def=5 ;; wsmux) def=6 ;; wssmux) def=7 ;;
  esac
  echo
  echo "Backhaul transport (the protocol of the reverse tunnel that runs INSIDE the ESP tunnel):"
  echo "  1) tcp      plain TCP, lowest overhead; the only one that can also carry UDP (default)"
  echo "  2) tcpmux   TCP + multiplexing (many user connections share a few tunnel connections)"
  echo "  3) udp      tunnel over UDP"
  echo "  4) ws       WebSocket"
  echo "  5) wss      WebSocket + TLS (a self-signed certificate is created automatically)"
  echo "  6) wsmux    WebSocket + multiplexing"
  echo "  7) wssmux   WebSocket + TLS + multiplexing"
  echo "  (the ESP tunnel is already encrypted - the TLS of wss / wssmux only costs extra CPU)"
  while true; do
    read -r -p "Select [${def}]: " c
    case ${c:-$def} in
      1|tcp)    BH_TRANSPORT=tcp ;;
      2|tcpmux) BH_TRANSPORT=tcpmux ;;
      3|udp)    BH_TRANSPORT=udp ;;
      4|ws)     BH_TRANSPORT=ws ;;
      5|wss)    BH_TRANSPORT=wss ;;
      6|wsmux)  BH_TRANSPORT=wsmux ;;
      7|wssmux) BH_TRANSPORT=wssmux ;;
      *) err "Invalid choice."; continue ;;
    esac
    break
  done
  ok "Backhaul transport: ${BH_TRANSPORT}"
}

ask_fwd_proto() {
  local c
  if [[ $ENGINE == backhaul ]]; then
    case $BH_TRANSPORT in
      tcp)
        echo
        echo "Forward which protocol on those ports?"
        echo "  1) TCP + UDP (default - UDP is carried inside the TCP tunnel)   2) TCP only"
        echo "  (Backhaul always opens TCP on the listed ports, so there is no 'UDP only' option)"
        read -r -p "Select [1]: " c
        case $c in 2) FWD_PROTO=tcp ;; *) FWD_PROTO=both ;; esac
        ;;
      udp)
        FWD_PROTO=both
        info "UDP transport: what it carries is decided by Backhaul's udp transport - test your service after the install."
        ;;
      *)
        FWD_PROTO=tcp
        info "The ${BH_TRANSPORT} transport carries TCP only (UDP forwarding needs the tcp transport)."
        ;;
    esac
    return 0
  fi
  echo
  echo "Forward which protocol on those ports?"
  echo "  1) TCP + UDP (default)   2) TCP only   3) UDP only"
  read -r -p "Select [1]: " c
  case $c in 2) FWD_PROTO=tcp ;; 3) FWD_PROTO=udp ;; *) FWD_PROTO=both ;; esac
}

# Where the forwarded services listen on the Kharej server. Backhaul keeps the destination in the
# server (Iran) config, so it is asked on the Iran side and travels in the token.
ask_bh_target() {
  local a def=${BH_TARGET:-127.0.0.1}
  echo
  echo "Where do the forwarded services listen on the KHAREJ server?"
  echo "  127.0.0.1 works for services bound to 127.0.0.1 or 0.0.0.0."
  echo "  Use ${IP_KHAREJ} only if they listen exclusively on the tunnel address."
  while true; do
    read -r -p "Target address [${def}]: " a
    a=${a:-$def}
    if valid_ip "$a"; then BH_TARGET=$a; return 0; fi
    err "Invalid IPv4 address."
  done
}

fw_hint() {
  if [[ $MODE == udp ]]; then
    echo "Open UDP ${UDP_PORT} (in and out) in your provider's external / cloud firewall if it has one."
  else
    echo "Open IP protocol 50 (ESP) in your provider's external / cloud firewall if it has one."
  fi
}

# leftover cron jobs that restart the tunnel fight the built-in watchdog
cron_warn() {
  local f found=""
  for f in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /var/spool/cron/crontabs; do
    [[ -e $f ]] || continue
    found+="$(grep -rIl -e "$APP" -- "$f" 2>/dev/null)"$'\n'
  done
  found=$(sed '/^$/d' <<< "$found" | sort -u)
  if [[ -n $found ]]; then
    warn "Cron jobs that mention ${APP} exist - a job that restarts the tunnel fights the built-in watchdog:"
    sed 's/^/      /' <<< "$found" >&2
    warn "Remove them unless you know you need them."
  fi
}

print_token() {
  local tok
  tok=$(make_token)
  echo
  echo "${C_Y}================= TOKEN (secret - contains the encryption key) =================${C_0}"
  echo "$tok"
  echo "${C_Y}=================================================================================${C_0}"
  echo "Copy it to the Kharej server: run this script there -> option 2 -> paste the token."
  echo "Send it over a secure channel (SSH/SCP). Anyone with the token can decrypt the tunnel."
}

# ------------------------------------------------------------------------------
#  Connection tools: UDP probe, diagnosis, clock
# ------------------------------------------------------------------------------
udp_probe() {   # udp_probe [count] -> "<replies> <sent> <rtt ms|-> <peer clock offset s|->"
  python3 -c "$PY_PROBE" "$PEER_PUB" "$UDP_PORT" "${1:-5}" 2>/dev/null
}

# sets PM_BEST (largest outer packet that got through, 0 = none) and PM_REC (tunnel MTU that fits it)
pmtu_scan() {
  local cur s
  local -a list=()
  PM_BEST=0; PM_REC=0
  [[ $MODE == udp ]] && have python3 || return 1
  cur=$MTU
  [[ -r /sys/class/net/${IF_NAME}/mtu ]] && cur=$(<"/sys/class/net/${IF_NAME}/mtu")
  list=($(( cur + 65 )))                      # biggest outer packet this tunnel can create
  for s in 1500 1480 1460 1440 1420 1400 1380 1360 1340 1300 1280; do
    (( s < list[0] )) && list+=("$s")
  done
  PM_BEST=$(python3 -c "$PY_PMTU" "$PEER_PUB" "$UDP_PORT" "${list[@]}" 2>/dev/null)
  [[ $PM_BEST =~ ^[0-9]+$ ]] || PM_BEST=0
  (( PM_BEST > 0 )) && PM_REC=$(mtu_fit "$PM_BEST")
  return 0
}

diagnose() {
  local out loss dev n_pol n_sa k v d x fw_ok bhc=""
  local o0=0 i0=0 o1=0 i1=0 r0=0 r1=0 d_out=0 d_in=0 d_rx=0
  local pr_ok=0 pr_n=5 pr_rtt="-" pr_skew="-" have_probe=0 skew_abs=0 cause="" nz="" cur_mtu=0 mtu_warn=""
  local -A XB=()

  if ! load_config 2>/dev/null; then warn "Tunnel is not installed."; return; fi
  route_info "$PEER_PUB" >/dev/null 2>&1
  echo "${C_B}=================== ESP tunnel diagnosis ===================${C_0}"
  echo "Role ${ROLE}:  ${LOCAL_INNER} <-> ${PEER_INNER}      peer public IP ${PEER_PUB}"
  if [[ $MODE == udp ]]; then echo "Transport: ESP-in-UDP on port ${UDP_PORT}"; else echo "Transport: raw ESP (IP protocol 50)"; fi
  clock_status
  echo
  if ! systemctl is-active --quiet "$APP" 2>/dev/null; then
    err "Service ${APP} is not running.  Try: systemctl restart ${APP} ; journalctl -u ${APP} -n 40 --no-pager"
    return
  fi

  dev=$(ip -4 route get "$PEER_INNER" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
  n_pol=$(ip xfrm policy 2>/dev/null | grep -cE "^src (${IP_IRAN}|${IP_KHAREJ})/32")
  n_sa=$(ip xfrm state 2>/dev/null | grep -cE "^src (${LOCAL_ADDR}|${PEER_PUB}) dst (${LOCAL_ADDR}|${PEER_PUB})")
  x=$(ip -br addr show "$IF_NAME" 2>/dev/null | awk '{print $1, $2, $3}')
  row "Interface" "${x:-${C_R}${IF_NAME} missing${C_0}}"
  if [[ $dev == "$IF_NAME" ]]; then row "Route to peer" "via ${IF_NAME} (ok)"; else row "Route to peer" "${C_R}via '${dev:-none}' (must be ${IF_NAME})${C_0}"; fi
  row "Kernel state" "policies ${n_pol}/3, SAs ${n_sa}/4"
  if ipt -nL ESPT_IN >/dev/null 2>&1; then fw_ok="loaded"; else fw_ok="${C_R}missing${C_0}"; fi
  row "Firewall chain" "$fw_ok"

  if [[ $MODE == udp ]] && have python3; then
    have_probe=1
    read -r pr_ok pr_n pr_rtt pr_skew <<< "$(udp_probe 5)"
    pr_ok=${pr_ok:-0}; pr_n=${pr_n:-5}; pr_rtt=${pr_rtt:--}; pr_skew=${pr_skew:--}
    if (( pr_ok > 0 )); then
      row "UDP probe" "${pr_ok}/${pr_n} replies from ${PEER_PUB}:${UDP_PORT}, rtt ${pr_rtt} ms, peer clock offset ${pr_skew} s"
      if [[ $pr_skew =~ ^-?[0-9]+$ ]]; then
        skew_abs=${pr_skew#-}
        if (( skew_abs > 60 )); then warn "  the two clocks differ by ${pr_skew}s - fix with menu 13 on the server that is wrong"; fi
      fi
      # path MTU: a black hole here makes bulk transfers stall or crawl while ping looks fine
      pmtu_scan
      cur_mtu=$MTU; [[ -r /sys/class/net/${IF_NAME}/mtu ]] && cur_mtu=$(<"/sys/class/net/${IF_NAME}/mtu")
      if (( PM_BEST > 0 )); then
        row "Path MTU" "outer packets up to ${PM_BEST} bytes pass (this direction); tunnel MTU ${cur_mtu}, safe up to ${PM_REC}"
        if (( PM_REC < cur_mtu )); then
          mtu_warn="large packets are dropped on the path - set the tunnel MTU to ${PM_REC} (menu 9, press m to measure and apply it)"
          row "" "${C_Y}${mtu_warn}${C_0}"
        fi
      else
        row "Path MTU" "not measured (no probe size was answered)"
      fi
    else
      row "UDP probe" "${C_R}0/${pr_n} replies - nothing answers on ${PEER_PUB}:${UDP_PORT}/udp${C_0}"
    fi
  fi

  # --- live measurement: packets counted before/after a short ping burst ---
  read -r o0 i0 <<< "$(xfrm_pkt_counts)"
  r0=$(outer_rx_count)
  if [[ -r /proc/net/xfrm_stat ]]; then
    while read -r k v; do XB[$k]=$v; done < /proc/net/xfrm_stat
  fi
  echo
  echo "Testing the tunnel (6 pings, ~3 s)..."
  out=$(LC_ALL=C ping -c 6 -i 0.5 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1)
  tail -n 2 <<< "$out"
  loss=$(grep -oE '[0-9]+% packet loss' <<< "$out" | grep -oE '^[0-9]+')
  read -r o1 i1 <<< "$(xfrm_pkt_counts)"
  r1=$(outer_rx_count)
  d_out=$(( ${o1:-0} - ${o0:-0} )); d_in=$(( ${i1:-0} - ${i0:-0} )); d_rx=$(( ${r1:-0} - ${r0:-0} ))
  if [[ -r /proc/net/xfrm_stat ]]; then
    while read -r k v; do
      d=$(( v - ${XB[$k]:-0} ))
      (( d > 0 )) && nz+="${k}(+${d}) "
    done < /proc/net/xfrm_stat
  fi
  echo
  row "ESP sent" "${d_out} packets encrypted during the test"
  row "Peer -> here" "${d_rx} transport packets arrived, ${d_in} decrypted"
  if [[ -n $nz ]]; then
    row "XFRM errors" "${C_Y}${nz}${C_0}(new during the test)"
    [[ $nz == *XfrmInNoStates* ]]        && echo "      InNoStates: packets arrive for a key/SPI this server does not have -> different token/key, clocks >= 1 h apart, or the peer uses another transport."
    [[ $nz == *XfrmInStateProtoError* ]] && echo "      InStateProtoError: decryption/authentication failed -> key mismatch (token from another install?)."
    [[ $nz == *XfrmInTmplMismatch* || $nz == *XfrmInNoPols* || $nz == *XfrmInPolBlock* ]] && echo "      Inbound policy mismatch -> restart the tunnel (menu 7); look for other IPsec software."
    [[ $nz == *XfrmOutNoStates* ]]       && echo "      OutNoStates: no outbound key loaded -> restart the tunnel (menu 7)."
    [[ $nz == *XfrmOutBundleGenError* || $nz == *XfrmOutBundleCheckError* ]] && echo "      OutBundle*: cannot build the outer route to the peer -> check the route to ${PEER_PUB}."
  else
    row "XFRM errors" "none during the test"
  fi
  if [[ $ENGINE == backhaul ]]; then
    bhc=$(bh_conn_count)
    row "Backhaul" "service $(systemctl is-active "$BH_UNIT" 2>/dev/null), transport ${BH_TRANSPORT}, connections on ${IP_IRAN}:${BH_PORT}: ${bhc}"
  fi
  echo

  if [[ -n $loss ]] && (( loss == 0 )); then
    echo "${C_G}Verdict: the tunnel works (0% packet loss).${C_0}"
    if [[ $ENGINE == backhaul ]] && { ! systemctl is-active --quiet "$BH_UNIT" 2>/dev/null || [[ $bhc == 0 ]]; }; then
      warn "...but the Backhaul reverse tunnel is not connected: journalctl -u ${BH_UNIT} -n 30 --no-pager"
    fi
    [[ -n $mtu_warn ]] && warn "...but ${mtu_warn}"
    return
  fi

  if [[ $dev != "$IF_NAME" ]]; then
    cause="Traffic to ${PEER_INNER} does not use ${IF_NAME} (it goes via '${dev:-nothing}'). Another interface or route owns 10.10.10.0/24 - remove it (ip -4 addr / ip -4 route), then restart the tunnel."
  elif (( n_pol < 3 || n_sa < 4 )); then
    cause="The kernel state is incomplete (policies ${n_pol}/3, SAs ${n_sa}/4). Restart the tunnel (menu 7); if it stays incomplete read: journalctl -u ${APP} -n 50 --no-pager"
  elif (( d_out == 0 )); then
    cause="Nothing is being encrypted - the pings never enter the tunnel. See the XFRM errors above and the service log (journalctl -u ${APP} -n 50 --no-pager)."
  elif (( have_probe && pr_ok == 0 )); then
    cause="UDP ${UDP_PORT} gets no answer from ${PEER_PUB}. Either the other server is not installed/running yet, or UDP ${UDP_PORT} is blocked (provider/cloud firewall, or filtering between Iran and abroad). Open UDP ${UDP_PORT} on BOTH servers; if it still fails change the port with menu 12 (for example 443, 8443, 53 or a random high port)."
  elif (( skew_abs >= 3300 )); then
    cause="The two clocks differ by about ${pr_skew}s. Keys rotate hourly from the UTC clock and both sides must agree within well under 1 hour. Use menu 13 on the server with the wrong time."
  elif (( d_rx == 0 && d_in == 0 )); then
    if [[ $MODE == udp ]]; then
      if (( have_probe )); then
        cause="Probes pass but no tunnel packets arrive from the peer. The other side is not sending (service stopped, other port/transport - compare menu 3 on both) or the network drops ESP-looking UDP: run this diagnosis on the OTHER server, and if its 'ESP sent' is > 0 change the UDP port (menu 12)."
      else
        cause="No packets from the peer arrive. Run this diagnosis on the OTHER server: if its 'ESP sent' is > 0 the network drops them - open UDP ${UDP_PORT} in the cloud firewalls or change the port (menu 12)."
      fi
    else
      cause="No ESP (IP protocol 50) packets arrive from the peer. The network between the servers most likely drops protocol 50 - switch both sides to ESP-in-UDP (menu 12)."
    fi
  elif (( d_in == 0 )); then
    cause="Packets arrive from the peer but cannot be decrypted: key mismatch (Kharej was set up from a token of a different Iran install), clocks >= 1 hour apart (menu 13), or one side uses raw ESP and the other ESP-in-UDP. Re-copy the token (Iran menu 8 -> Kharej option 2)."
  else
    cause="Packets are decrypted but the ping still fails: a local firewall or sysctl (rp_filter / icmp_echo_ignore_all) is dropping traffic on ${IF_NAME}. Check: iptables -S | head -30 ; nft list ruleset | head -60"
  fi
  echo "${C_R}Verdict: no working link (${loss:-?}% packet loss).${C_0}"
  echo "Most likely cause:"
  echo "  ${cause}"
  echo
  echo "Tip: run this diagnosis on BOTH servers at the same time and compare 'ESP sent' with 'Peer -> here'."
}

sync_clock() {
  local src hdr="" d=""
  clock_status
  echo "Both servers must show the same UTC time: keys rotate hourly from the clock, so a difference"
  echo "of about an hour or more breaks the tunnel silently (NTP is often blocked in Iran)."
  have curl || { err "curl is required."; return 1; }
  for src in https://www.cloudflare.com https://www.google.com https://www.microsoft.com http://www.baidu.com; do
    hdr=$(curl -sI --max-time 6 "$src" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="date"{print $2; exit}')
    if [[ -n $hdr ]]; then d=$hdr; break; fi
  done
  [[ -n $d ]] || { err "Could not read the time from the internet (no HTTP Date header received)."; return 1; }
  echo "Internet time : $d"
  confirm "Set the system clock to this time?" y || return 0
  if date -u -s "$d" >/dev/null 2>&1; then
    have hwclock && hwclock --systohc 2>/dev/null
    ok "Clock set: $(date -u '+%F %T') UTC"
    if load_config 2>/dev/null && systemctl is-active --quiet "$APP" 2>/dev/null; then
      systemctl restart "$APP" && ok "Tunnel restarted so the keys are derived from the new time."
    fi
  else
    err "Could not set the clock."
    return 1
  fi
}

# ------------------------------------------------------------------------------
#  Menu actions
# ------------------------------------------------------------------------------
setup_iran() {
  local det
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the IRAN server side (tunnel IP ${IP_IRAN}, Backhaul server)"
  ROLE=iran; ENGINE=backhaul; BH_PORT=$DEFAULT_BH_PORT; BH_TARGET=127.0.0.1
  ask_transport
  ask_bh_transport
  ensure_deps     || { pause; return; }
  preflight_check || { pause; return; }
  check_kernel    || { pause; return; }
  ensure_backhaul || { pause; return; }
  cron_warn

  det=$(detect_public_ip)
  while true; do
    read -r -p "Iran server public IP [${det}]: " IRAN_IP
    IRAN_IP=${IRAN_IP:-$det}
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done
  while true; do
    read -r -p "Kharej (foreign) server public IP: " KHAREJ_IP
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done
  if ! route_info "$KHAREJ_IP"; then err "No route to $KHAREJ_IP from this server."; pause; return; fi
  if [[ $LOCAL_ADDR != "$IRAN_IP" ]]; then
    warn "This server's local address towards Kharej is $LOCAL_ADDR, not $IRAN_IP (NAT?)."
    warn "Raw ESP through NAT often fails - if it does, re-install using ESP-in-UDP."
  fi

  echo
  ask_ports
  ask_fwd_proto
  ask_bh_target

  ROLE=iran
  MASTER=$(rand_hex 32)
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC
  write_config
  load_config
  start_service || { pause; return; }
  print_token
  echo
  echo "Reverse tunnel: the Backhaul server on this box listens on ${IP_IRAN}:${BH_PORT} (inside the ESP tunnel only), transport: ${BH_TRANSPORT}."
  echo "Public ports [${PORTS}] (${FWD_PROTO}) are opened by Backhaul and carried through the tunnel to ${BH_TARGET}:<same port> on the Kharej server."
  echo "The Kharej side takes the transport from the token - run option 2 there with the token above."
  if [[ $BH_TRANSPORT == wss || $BH_TRANSPORT == wssmux ]]; then
    echo "TLS: a self-signed certificate was created in ${CONF_DIR} (the Kharej client does not verify it)."
  fi
  if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    warn "ufw is active here: allow the forwarded ports too (ufw allow <port>)."
  fi
  fw_hint
  echo "Next: set up the Kharej side, then run option 11 (Diagnose) on both servers if ping ${PEER_INNER} does not work."
  echo
  pause
}

setup_kharej() {
  local tok
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the KHAREJ client side (tunnel IP ${IP_KHAREJ}, Backhaul client)"
  while true; do
    read -r -p "Paste the token from the Iran server: " tok
    if parse_token "$tok"; then break; fi
    err "Invalid token (copy error?). Copy it again from the Iran server (menu option 8). Tokens made by the old Rathole version are not valid - create a new one on the Iran server."
  done
  ROLE=kharej
  MODE=$T_MODE; ENGINE=$T_ENGINE; BH_PORT=$T_BHPORT; BH_TRANSPORT=$T_BHTR; BH_TARGET=$T_BHTARGET
  ensure_deps     || { pause; return; }
  preflight_check || { pause; return; }
  check_kernel    || { pause; return; }
  if [[ $ENGINE == backhaul ]]; then
    ensure_backhaul || { pause; return; }
  fi
  cron_warn

  IRAN_IP=$T_IRAN; KHAREJ_IP=$T_KHAREJ; UDP_PORT=$T_UDP
  PORTS=$(norm_ports "$T_PORTS"); FWD_PROTO=$T_PROTO; MASTER=$T_MASTER; ROLE=kharej
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC

  if ! route_info "$IRAN_IP"; then err "No route to Iran server $IRAN_IP."; pause; return; fi
  if [[ $LOCAL_ADDR != "$KHAREJ_IP" ]]; then
    warn "This server's local address is $LOCAL_ADDR but the token says $KHAREJ_IP (NAT or wrong server?)."
    confirm "Continue anyway?" n || return
  fi
  if [[ $ENGINE == backhaul ]]; then
    info "Backhaul transport (from the token): ${BH_TRANSPORT}"
  fi

  write_config
  load_config
  start_service || { pause; return; }

  echo
  info "Waiting for the tunnel to come up (up to 20 s)..."
  if wait_link 20; then
    ok "Tunnel is UP - ${PEER_INNER} answers ping."
    if [[ $ENGINE == backhaul ]]; then
      if [[ $BH_TRANSPORT == udp ]]; then
        info "UDP transport has no connection counter - check the log: journalctl -u ${BH_UNIT} -n 30 --no-pager"
      else
        info "Waiting for the Backhaul reverse tunnel (${IP_KHAREJ} -> ${IP_IRAN}:${BH_PORT})..."
        for _ in $(seq 1 12); do
          [[ $(bh_conn_count) != 0 ]] && break
          sleep 1
        done
        if [[ $(bh_conn_count) != 0 ]]; then
          ok "Reverse tunnel is connected."
        else
          warn "Not connected yet. See: journalctl -u ${BH_UNIT} -n 30 --no-pager"
        fi
      fi
    fi
  else
    warn "No answer from ${PEER_INNER} yet - running the diagnosis..."
    echo
    diagnose
  fi
  echo
  if [[ $ENGINE == backhaul ]]; then
    echo "Ports [${PORTS}] (${FWD_PROTO}) opened on the Iran server are forwarded to ${BH_TARGET}:<same port> on THIS server."
    echo "The services must be running here and listening on ${BH_TARGET} (or 0.0.0.0)."
  else
    echo "Services for ports [${PORTS}] on this server must listen on 0.0.0.0 or ${IP_KHAREJ}."
    echo "Traffic arrives from ${IP_IRAN} (the Iran server's tunnel IP)."
  fi
  fw_hint
  echo
  pause
}

cmd_status() {
  local st epoch left line st_bh
  if ! load_config 2>/dev/null; then
    warn "Tunnel is not installed. Use menu option 1 (Iran) or 2 (Kharej)."
    return
  fi
  st=$(systemctl is-active "$APP" 2>/dev/null)
  epoch=$(( $(date +%s) / EPOCH_LEN ))
  left=$(( EPOCH_LEN - $(date +%s) % EPOCH_LEN ))

  echo "${C_B}===================== ESP Tunnel status =====================${C_0}"
  echo "Role          : $ROLE   (${LOCAL_INNER}  <->  ${PEER_INNER})"
  echo "Peer public IP: $PEER_PUB"
  if [[ $MODE == udp ]]; then echo "Transport     : ESP-in-UDP, port $UDP_PORT"
  else echo "Transport     : raw ESP (IP protocol 50)"; fi
  echo "Cipher        : AES-256-GCM, MTU $(cat "/sys/class/net/${IF_NAME}/mtu" 2>/dev/null || echo "$MTU"), next key rotation in $((left / 60)) min (epoch $epoch)"
  clock_status
  echo "Watchdog      : rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"
  if [[ $st == active ]]; then echo "Service       : ${C_G}active${C_0}"; else echo "Service       : ${C_R}${st}${C_0}"; fi
  if [[ $ENGINE == backhaul ]]; then
    st_bh=$(systemctl is-active "$BH_UNIT" 2>/dev/null)
    if [[ $st_bh == active ]]; then
      echo "Backhaul      : ${C_G}active${C_0} ($( [[ $ROLE == iran ]] && echo server || echo client ), transport ${BH_TRANSPORT}, core v$(bh_version), control ${IP_IRAN}:${BH_PORT}, live connections: $(bh_conn_count))"
    else
      echo "Backhaul      : ${C_R}${st_bh}${C_0}"
    fi
  else
    echo "Forwarding    : iptables DNAT (legacy engine - re-install to switch to Backhaul)"
  fi

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "Interface     : $(ip -br addr show "$IF_NAME" | awk '{print $1, $2, $3}')"
  else
    echo "Interface     : ${C_R}$IF_NAME missing${C_0}"
  fi
  echo "Loaded SAs    : $(wc -l < "$REG" 2>/dev/null || echo 0)  (1 outbound + 3 inbound expected)"
  echo "From the peer : $(outer_rx_count) transport packets accepted by the firewall since the rules were loaded"
  echo
  echo "--- Ping through the tunnel (10 packets) ---"
  LC_ALL=C ping -c 10 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
  echo
  echo "--- Interface counters ---"
  ip -s link show "$IF_NAME" 2>/dev/null | sed -n '3,6p'
  echo
  line=$(xfrm_nonzero_counters)
  if [[ -n $line ]]; then
    echo "XFRM counters (non-zero = drops/errors): $line"
  else
    echo "XFRM counters : clean (no errors)"
  fi
  if [[ $ENGINE == backhaul ]]; then
    echo
    echo "--- Forwarded ports (${FWD_PROTO}) : [${PORTS}] ---"
    if [[ $ROLE == iran ]]; then
      echo "Public ports listening: $(bh_listen_summary)   (Backhaul may open a port only while the Kharej client is connected)"
      echo "Target on Kharej      : ${BH_TARGET}"
    else
      echo "Target on this server : ${BH_TARGET}"
    fi
  elif [[ $ROLE == iran ]]; then
    echo
    echo "--- Forwarded ports (${FWD_PROTO}) : [${PORTS}] -> ${IP_KHAREJ} ---"
    iptables -t nat -vnL ESPT_PRE 2>/dev/null | sed -n '2,$p'
  fi
  echo
  echo "No ping? Run menu 11 (Diagnose) on both servers.   Raw ESP on the wire: tcpdump -ni $WAN_DEV 'ip proto 50'"
}

live_counters() {
  local stop=0 rx0 tx0 rp0 tp0 rx tx rp tp x0 x
  trap 'stop=1' INT
  rx0=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx0=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
  rp0=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp0=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
  x0=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
  echo "Live traffic on $IF_NAME (Ctrl+C to stop)"
  while (( ! stop )); do
    sleep 1
    rx=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
    rp=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
    x=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
    printf '%s  RX %7d kbit/s %6d pps | TX %7d kbit/s %6d pps | xfrm errors +%d\n' \
      "$(date +%T)" $(( (rx - rx0) * 8 / 1000 )) $(( rp - rp0 )) $(( (tx - tx0) * 8 / 1000 )) $(( tp - tp0 )) $(( x - x0 ))
    rx0=$rx; tx0=$tx; rp0=$rp; tp0=$tp; x0=$x
  done
  trap - INT
}

live_log() {
  local c
  if ! load_config 2>/dev/null; then warn "Tunnel is not installed."; return; fi
  echo
  echo "Live Log:"
  echo "  1) Service log (events, key rotations, up/down, forensic snapshots)"
  echo "  2) Live ping monitor (packet loss + latency/jitter through the tunnel)"
  echo "  3) Live traffic counters (kbit/s, pps, errors)"
  echo "  4) Diagnose connection now (same as menu 11)"
  echo "  5) Backhaul log (reverse tunnel)"
  read -r -p "Select [1]: " c
  case ${c:-1} in
    1) echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$APP" -f -n 40 --no-pager; trap - INT ;;
    2) echo "(Ctrl+C to stop and see the summary)"; trap ':' INT; ping -O -i 0.5 -I "$IF_NAME" "$PEER_INNER"; trap - INT ;;
    3) live_counters ;;
    4) diagnose; pause ;;
    5) if [[ $ENGINE == backhaul ]]; then
         echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$BH_UNIT" -f -n 40 --no-pager; trap - INT
       else
         warn "This install does not use Backhaul."
       fi ;;
    *) warn "Invalid choice." ;;
  esac
}

uninstall_all() {
  confirm "Remove the tunnel completely (services, Backhaul core, interface, keys, firewall rules)?" n || return
  systemctl disable --now "$BH_UNIT" >/dev/null 2>&1
  systemctl disable --now "${APP}-rathole" >/dev/null 2>&1       # unit of the old Rathole version, if any
  systemctl disable --now "$APP" >/dev/null 2>&1
  teardown_all
  tune_restore
  rm -f "$UNIT_FILE" "$BH_UNIT_FILE" "/etc/systemd/system/${APP}-rathole.service" "$SYSCTL_FILE"
  rm -rf "$CONF_DIR" "$RUN_DIR" "$LIB_DIR"
  systemctl daemon-reload
  systemctl reset-failed "$APP" "$BH_UNIT" "${APP}-rathole" 2>/dev/null
  rm -f "$BIN"
  ok "Tunnel fully removed (net.ipv4.ip_forward was left unchanged)."
}

change_ports() {
  local tok
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }

  if [[ $ENGINE != backhaul ]]; then      # legacy iptables engine
    if [[ $ROLE != iran ]]; then warn "Ports are configured on the Iran server only."; return; fi
    info "Current ports: [${PORTS}] (${FWD_PROTO})"
    ask_ports
    ask_fwd_proto
    write_config
    if systemctl is-active --quiet "$APP"; then
      "$BIN" fw && ok "New ports are active."
    fi
    warn "The token changed (ports are part of it) - the Kharej side does not need to be updated."
    return
  fi

  if [[ $ROLE == iran ]]; then
    info "Current ports: [${PORTS}] (${FWD_PROTO}), target on Kharej ${BH_TARGET}, Backhaul transport ${BH_TRANSPORT}"
    ask_ports
    ask_fwd_proto
    ask_bh_target
    write_config
    bh_write_config || return
    systemctl restart "$BH_UNIT" && ok "Backhaul restarted with the new port list."
    warn "The port list lives in the Backhaul server on THIS (Iran) server - the Kharej client needs no update."
    warn "To refresh the port list shown by the Kharej status, run this option (6) there and paste the token below."
    print_token
  else
    info "Current ports (from the Iran token): [${PORTS}] (${FWD_PROTO}), target ${BH_TARGET}"
    echo "The ports are opened by the Iran server; the Kharej Backhaul client needs no port list."
    echo "Paste the updated token from the Iran server to refresh the displayed list, or press Enter to keep it."
    read -r -p "Token: " tok
    if [[ -n $tok ]]; then
      parse_token "$tok" || { err "Invalid token."; return; }
      [[ $T_MASTER == "$MASTER" ]] || { err "That token belongs to a different tunnel (key mismatch)."; return; }
      [[ $T_ENGINE == "$ENGINE" ]] || { err "That token was made for another engine (${T_ENGINE})."; return; }
      PORTS=$(norm_ports "$T_PORTS"); FWD_PROTO=$T_PROTO; BH_TARGET=$T_BHTARGET
      [[ $T_BHTR == "$BH_TRANSPORT" ]] || warn "The token carries another Backhaul transport (${T_BHTR}) - use menu 14 to switch it."
      write_config
      ok "Port list updated."
    fi
  fi
}

# Change the Backhaul transport on an installed tunnel (Iran first, then Kharej). Same key, no re-install.
change_bh_transport() {
  local tok
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  if [[ $ENGINE != backhaul ]]; then warn "This install does not use Backhaul (legacy DNAT engine) - re-install to switch."; return; fi

  if [[ $ROLE == iran ]]; then
    info "Current Backhaul transport: ${BH_TRANSPORT}"
    ask_bh_transport
    ask_fwd_proto                      # UDP over the tunnel exists for the tcp transport only
    ensure_deps || return
    write_config
    load_config
    bh_write_config || return
    "$BIN" fw >/dev/null 2>&1          # the control-port rule depends on tcp / udp
    if systemctl is-active --quiet "$APP"; then systemctl kill --signal=HUP --kill-who=main "$APP"; fi
    systemctl restart "$BH_UNIT" && ok "Backhaul restarted with the transport ${BH_TRANSPORT}."
    print_token
    warn "Kharej server: run this option (14) and paste the token above. The reverse tunnel stays down until both sides use the same transport."
  else
    echo "Paste the NEW token shown by the Iran server after it changed the Backhaul transport (Iran: menu 14 or 8)."
    read -r -p "Token: " tok
    parse_token "$tok" || { err "Invalid token."; return; }
    [[ $T_MASTER == "$MASTER" ]] || { err "That token belongs to a different tunnel (key mismatch)."; return; }
    [[ $T_ENGINE == "$ENGINE" ]] || { err "That token was made for another engine (${T_ENGINE})."; return; }
    BH_TRANSPORT=$T_BHTR; BH_TARGET=$T_BHTARGET; PORTS=$(norm_ports "$T_PORTS"); FWD_PROTO=$T_PROTO
    write_config
    load_config
    bh_write_config || return
    if systemctl is-active --quiet "$APP"; then systemctl kill --signal=HUP --kill-who=main "$APP"; fi
    systemctl restart "$BH_UNIT" && ok "Backhaul client restarted with the transport ${BH_TRANSPORT}."
  fi
}

# Change transport (raw ESP <-> ESP-in-UDP) or the UDP port on an installed tunnel.
# Iran: choose, get a new token. Kharej: paste that token. No re-install, same key.
change_transport() {
  local tok old_port
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  old_port=$UDP_PORT

  if [[ $ROLE == iran ]]; then
    info "Current transport: $( [[ $MODE == udp ]] && echo "ESP-in-UDP, port $UDP_PORT" || echo "raw ESP (IP protocol 50)" )"
    ask_transport
    if [[ $MODE == udp && $ENGINE == backhaul ]] && ports_include "$PORTS" "$UDP_PORT"; then
      err "UDP port $UDP_PORT is in the forwarded port list - choose another transport port (nothing was changed)."
      return
    fi
    if [[ $MODE == udp && $UDP_PORT != "$old_port" && -n $(ss -Hlun "sport = :${UDP_PORT}" 2>/dev/null) ]]; then
      err "UDP port $UDP_PORT is already in use on this server (nothing was changed)."
      return
    fi
    ensure_deps || return
    write_config
    load_config
    systemctl restart "$APP" && ok "Tunnel restarted with the new transport."
    print_token
    warn "Kharej server: run this option (12) and paste the token above. The link stays down until both sides match."
    fw_hint
  else
    echo "Paste the NEW token shown by the Iran server after it changed the transport (Iran: menu 12 or 8)."
    read -r -p "Token: " tok
    parse_token "$tok" || { err "Invalid token."; return; }
    [[ $T_MASTER == "$MASTER" ]] || { err "That token belongs to a different tunnel (key mismatch)."; return; }
    [[ $T_ENGINE == "$ENGINE" ]] || { err "That token was made for another engine (${T_ENGINE})."; return; }
    MODE=$T_MODE; UDP_PORT=$T_UDP; PORTS=$(norm_ports "$T_PORTS"); FWD_PROTO=$T_PROTO
    BH_TRANSPORT=$T_BHTR; BH_TARGET=$T_BHTARGET
    ensure_deps || return
    write_config
    load_config
    restart_tunnel
    info "Waiting for the tunnel (up to 20 s)..."
    if wait_link 20; then ok "Tunnel is UP - ${PEER_INNER} answers ping."; else warn "No answer yet - running the diagnosis..."; diagnose; fi
    fw_hint
  fi
}

show_token() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  if [[ $ROLE != iran ]]; then warn "The token is created on the Iran server (it is the same key)."; return; fi
  print_token
}

restart_tunnel() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  install_self 2>/dev/null                     # picks up a newer version of this script
  write_unit
  [[ $ENGINE == backhaul ]] && write_bh_unit
  legacy_rathole_cleanup
  systemctl daemon-reload
  systemctl restart "$APP" && ok "Tunnel restarted."
  if [[ $ENGINE == backhaul ]]; then
    systemctl restart "$BH_UNIT" && ok "Backhaul restarted."
  fi
}

update_backhaul() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  if [[ $ENGINE != backhaul ]]; then warn "This install does not use Backhaul (legacy DNAT engine) - re-install to switch."; return; fi
  ensure_deps || return
  ensure_backhaul force || return
  systemctl restart "$BH_UNIT" && ok "Backhaul restarted with core v$(bh_version)."
}

change_watchdog() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  local h s m t b old_tune cur="$MTU"
  [[ -r /sys/class/net/${IF_NAME}/mtu ]] && cur=$(<"/sys/class/net/${IF_NAME}/mtu")
  echo "Current: preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled), rx-stall trigger ${RX_STALL_SEC}s"
  echo "         MTU ${cur} ($( (( MTU_SET > 0 )) && echo fixed || echo automatic )), network tuning (BBR / buffers): $( [[ $NET_TUNE == 1 ]] && echo on || echo off )"
  echo
  read -r -p "New preventive-rebuild interval in hours (0 = disable) [$((FORCE_REBUILD_SEC/3600))]: " h
  h=${h:-$((FORCE_REBUILD_SEC/3600))}
  [[ $h =~ ^[0-9]+$ ]] || { err "Invalid number."; return; }
  read -r -p "New rx-stall trigger in seconds, min 10 [$RX_STALL_SEC]: " s
  s=${s:-$RX_STALL_SEC}
  [[ $s =~ ^[0-9]+$ ]] && (( s >= 10 )) || { err "Invalid number (min 10)."; return; }
  echo "Tunnel MTU: 0 = automatic (from the WAN link), a number 576-1500, or m = measure the real path now"
  echo "(ESP-in-UDP only, the other server must be up). Too high = stalls / slow transfers, too low = a little overhead."
  read -r -p "MTU [${MTU_SET}]: " m
  m=${m:-$MTU_SET}
  if [[ $m == m || $m == M ]]; then
    route_info "$PEER_PUB" >/dev/null 2>&1
    info "Measuring the path MTU (up to ~15 s)..."
    pmtu_scan
    if (( PM_BEST > 0 )); then
      b=$MTU_UDP
      m=$PM_REC; (( m > b )) && m=$b
      ok "Largest outer packet that passes: ${PM_BEST} bytes -> tunnel MTU ${m}"
    else
      warn "Could not measure (is the peer up and ESP-in-UDP in use?) - keeping the current MTU setting."
      m=$MTU_SET
    fi
  fi
  [[ $m =~ ^[0-9]+$ ]] && { (( m == 0 || (m >= 576 && m <= 1500) )); } || { err "Invalid MTU."; return; }
  read -r -p "Network tuning (BBR, bigger buffers, MTU probing) on this server? [$( [[ $NET_TUNE == 1 ]] && echo Y/n || echo y/N )]: " t
  case ${t:-} in [Yy]*) t=1 ;; [Nn]*) t=0 ;; *) t=$NET_TUNE ;; esac

  old_tune=$NET_TUNE
  FORCE_REBUILD_SEC=$(( h * 3600 )); RX_STALL_SEC=$s; MTU_SET=$m; NET_TUNE=$t
  write_config
  route_info "$PEER_PUB" >/dev/null 2>&1
  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    calc_mtu
    ip link set dev "$IF_NAME" mtu "$MTU" && ok "MTU is now ${MTU} (applied live)."
  fi
  if [[ $t == 0 && $old_tune == 1 ]]; then tune_restore; fi
  sysctl_apply
  if systemctl is-active --quiet "$APP"; then systemctl kill --signal=HUP --kill-who=main "$APP"; fi
  ok "Saved and applied - no restart was needed, existing connections are untouched."
}

banner() {
  [[ -t 1 ]] && clear
  echo "${C_B}==============================================================${C_0}"
  echo "${C_B}   ESP Tunnel Manager v${VERSION}  -  ESP + Backhaul reverse tunnel${C_0}"
  echo "${C_B}   Iran ${IP_IRAN}  <=======  ESP  =======>  Kharej ${IP_KHAREJ}${C_0}"
  echo "${C_B}==============================================================${C_0}"
  if load_config 2>/dev/null; then
    echo " Installed role: $ROLE   |   engine: $ENGINE$( [[ $ENGINE == backhaul ]] && echo " ($BH_TRANSPORT)" )   |   service: $(systemctl is-active "$APP" 2>/dev/null)"
    if [[ $ENGINE == rathole ]]; then
      warn "This install still uses the old Rathole engine, which is no longer part of this script - run option 5, then option 1 / 2 to switch to Backhaul."
    fi
  else
    echo " Not installed yet."
  fi
  echo
}

menu() {
  local ch
  while true; do
    banner
    echo "  1) Tunnel Set Iran Server  (Backhaul server)"
    echo "  2) Tunnel Set Client (Kharej)  (Backhaul client)"
    echo "  3) Status Tunnel"
    echo "  4) Live Log"
    echo "  5) Uninstall Full Tunnel"
    echo "  ------------------------------------"
    echo "  6) Change forwarded ports + target (Iran) / sync ports (Kharej)"
    echo "  7) Restart tunnel"
    echo "  8) Show token (Iran)"
    echo "  9) Watchdog / MTU / network tuning settings"
    echo " 10) Update Backhaul core"
    echo " 11) Diagnose connection (why no ping?)"
    echo " 12) Change transport / UDP port (Iran first, then Kharej)"
    echo " 13) Sync system clock (keys depend on it)"
    echo " 14) Change Backhaul transport (Iran first, then Kharej)"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch || exit 0
    echo
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; echo; pause ;;
      4) live_log ;;
      5) uninstall_all; echo; pause ;;
      6) change_ports; echo; pause ;;
      7) restart_tunnel; echo; pause ;;
      8) show_token; echo; pause ;;
      9) change_watchdog; echo; pause ;;
      10) update_backhaul; echo; pause ;;
      11) diagnose; echo; pause ;;
      12) change_transport; echo; pause ;;
      13) sync_clock; echo; pause ;;
      14) change_bh_transport; echo; pause ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

usage() {
  echo "Usage: $0 [menu|status|diag|daemon|teardown|fw|bh-run]"
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    diag)     need_root; diagnose ;;
    daemon)   need_root; cmd_daemon ;;
    bh-run)   need_root; cmd_bh_run ;;
    rh-run)   need_root; log "the old Rathole engine was replaced by Backhaul - disabling the old unit (re-install: menu 5, then 1 / 2)"; legacy_rathole_cleanup ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    *)        usage; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
