#!/bin/sh
# merlin-audit.sh — read-only security auditor for ASUSWRT-Merlin routers
# by OSINTGH0ST
#
# Checks: firmware/component/Entware CVEs (NVD + CISA KEV), listening ports,
#         risky nvram config, Wi-Fi crypto, DNS integrity, UPnP mappings,
#         active outbound connections, guest/VLAN isolation, VPN peers,
#         TLS cert, firmware freshness, own-defenses (Skynet/Diversion),
#         known ASUS backdoor IOCs, persistence, and a baseline integrity
#         diff that flags anything that changed since the last accepted run.
#
# READ-ONLY on the router: never writes nvram, never touches iptables/DNS/
# services/SSH. Writes DATA FILES ONLY: report under /tmp/merlin-audit/ and a
# baseline snapshot under /jffs/.merlin-audit/ (so it survives reboots).
#
# Usage:
#   sh merlin-audit.sh                 full audit
#   sh merlin-audit.sh --offline       skip all network lookups (NVD/KEV/firmware)
#   sh merlin-audit.sh --kernel        also query kernel CVEs (noisy)
#   sh merlin-audit.sh --json          also write + print report.json (for Cerberus)
#   sh merlin-audit.sh --accept        accept current state as new integrity baseline
#   sh merlin-audit.sh --conntrack     include outbound connection snapshot
#   NVD_API_KEY=xxxx sh merlin-audit.sh   faster NVD (50 req/30s vs 5)
#
# jq (opkg install jq) is optional but gives CVSS scores + KEV matching.

VERSION="2.0.0"
OFFLINE=0; KERNEL=0; JSON=0; ACCEPT=0; CONNTRACK=0
for a in "$@"; do
  case "$a" in
    --offline)   OFFLINE=1 ;;
    --kernel)    KERNEL=1 ;;
    --json)      JSON=1 ;;
    --accept)    ACCEPT=1 ;;
    --conntrack) CONNTRACK=1 ;;
    -h|--help)   sed -n '2,33p' "$0"; exit 0 ;;
  esac
done

WORK=/tmp/merlin-audit
mkdir -p "$WORK"
# baseline persists across reboots on jffs; fall back to /tmp if jffs is RO
BASE=/jffs/.merlin-audit/baseline
if [ -d /jffs ] && mkdir -p "$BASE" 2>/dev/null && [ -w "$BASE" ]; then :; else BASE="$WORK/baseline"; mkdir -p "$BASE"; fi

STAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$WORK/report-$STAMP.txt"
RJSON="$WORK/report-$STAMP.json"
FIND="$WORK/findings-$STAMP.jsonl"
KEV="$WORK/kev.json"
NVD="https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GH_REL="https://api.github.com/repos/RMerl/asuswrt-merlin.ng/releases/latest"

CRIT=0; HIGH=0; MED=0; LOW=0; PASS=0
CATEGORY="general"
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

if [ -t 1 ] && [ $JSON = 0 ]; then
  R='\033[1;31m'; Y='\033[1;33m'; G='\033[1;32m'; B='\033[1;36m'; M='\033[1;35m'; N='\033[0m'
else
  R=''; Y=''; G=''; B=''; M=''; N=''
fi

: > "$REPORT"; : > "$FIND"
json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g'; }
jadd() { printf '{"sev":"%s","cat":"%s","msg":"%s"}\n' "$1" "$CATEGORY" "$(json_esc "$2")" >> "$FIND"; }

out()  { printf "%b\n" "$*"; printf "%b\n" "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT"; }
hdr()  { CATEGORY="$*"; out ""; out "${B}=== $* ===${N}"; }
crit() { CRIT=$((CRIT+1)); out "${R}[CRIT]${N} $*"; jadd crit "$*"; }
high() { HIGH=$((HIGH+1)); out "${R}[HIGH]${N} $*"; jadd high "$*"; }
med()  { MED=$((MED+1));   out "${Y}[MED ]${N} $*"; jadd med "$*"; }
low()  { LOW=$((LOW+1));   out "${M}[LOW ]${N} $*"; jadd low "$*"; }
ok()   { PASS=$((PASS+1)); out "${G}[ OK ]${N} $*"; }
info() { out "       $*"; }

nv() { nvram get "$1" 2>/dev/null; }

out "${B}merlin-audit v$VERSION — OSINTGH0ST${N}"
out "Started: $(date)"
command -v nvram >/dev/null 2>&1 || { out "${R}nvram not found — run this on the router.${N}"; exit 1; }

# ─────────────────────────────────────────────────────────────
hdr "SYSTEM"
MODEL=$(nv odmpid); [ -z "$MODEL" ] && MODEL=$(nv productid)
BUILD=$(nv buildno); EXT=$(nv extendno)
FW="${BUILD}${EXT:+_$EXT}"
info "Model:    $MODEL"
info "Firmware: $FW"
info "Kernel:   $(uname -r)"
info "WAN IP:   $(nv wan0_ipaddr)"
info "Baseline: $BASE"
info "jq:       $([ $HAVE_JQ = 1 ] && echo yes || echo 'no (opkg install jq for CVSS + KEV)')"

# ─────────────────────────────────────────────────────────────
hdr "ADMIN ACCESS"
[ "$(nv misc_http_x)" = "1" ] \
  && crit "Web UI reachable from WAN (misc_http_x=1, port $(nv misc_httpsport_x)) — disable" \
  || ok "Web UI not exposed to WAN"
case "$(nv http_enable)" in
  0) med "Web UI is HTTP only — enable HTTPS (http_enable=1)" ;;
  2) low "Web UI serves both HTTP and HTTPS — HTTPS only recommended" ;;
  1) ok "Web UI HTTPS only" ;;
esac
[ "$(nv http_username)" = "admin" ] && med "Admin username is 'admin' — rename it" || ok "Admin username not 'admin'"
case "$(nv sshd_enable)" in
  1) high "SSH enabled on LAN+WAN (sshd_enable=1) — set to LAN only" ;;
  2) ok "SSH LAN only" ;;
  0|"") ok "SSH disabled" ;;
esac
if [ "$(nv sshd_enable)" != "0" ] && [ -n "$(nv sshd_enable)" ]; then
  [ "$(nv sshd_pass)" = "1" ] && med "SSH password login allowed — use keys only (sshd_pass=0)" || ok "SSH key-only auth"
  [ "$(nv sshd_port)" = "22" ] && low "SSH on default port 22"
  [ "$(nv sshd_bfp)" = "1" ] && ok "SSH brute-force protection on" || low "SSH brute-force protection off (sshd_bfp)"
fi
[ "$(nv telnetd_enable)" = "1" ] && crit "Telnet enabled — disable immediately" || ok "Telnet disabled"

# ─────────────────────────────────────────────────────────────
hdr "KNOWN ASUS BACKDOOR IOCs"
SSHPORT=$(nv sshd_port)
[ "$SSHPORT" = "53282" ] && crit "SSH port 53282 — matches AyySSHush ASUS botnet IOC. Factory reset + rotate creds." \
                          || ok "SSH port not 53282"
AK=$(nv sshd_authkeys)
if [ -n "$AK" ]; then
  NK=$(echo "$AK" | grep -o 'ssh-[a-z0-9-]*\|ecdsa-[a-z0-9-]*' | wc -l)
  med "$NK SSH authorized key(s) in nvram — verify every one is yours:"
  echo "$AK" | sed 's/>/\n/g' | grep -v '^$' | while read -r k; do
    info "  $(echo "$k" | awk '{print $1, substr($2,1,16)"...", $3}')"
  done
else ok "No SSH authorized keys in nvram"; fi

# ─────────────────────────────────────────────────────────────
hdr "WAN EXPOSURE / SERVICES"
UPNP=$(nv wan0_upnp_enable); [ -z "$UPNP" ] && UPNP=$(nv upnp_enable)
[ "$UPNP" = "1" ] && med "UPnP enabled — LAN devices can open WAN ports" || ok "UPnP disabled"
[ "$(nv fw_enable_x)" = "1" ] && ok "Firewall enabled" || crit "Firewall DISABLED (fw_enable_x)"
[ "$(nv fw_dos_x)" = "1" ] && ok "DoS protection on" || low "DoS protection off (fw_dos_x)"
[ "$(nv misc_ping_x)" = "1" ] && low "Responds to WAN ping" || ok "No WAN ping response"
if [ "$(nv enable_ftp)" = "1" ]; then
  [ "$(nv ftp_wanac)" = "1" ] && crit "FTP enabled AND exposed to WAN" || med "FTP enabled (LAN) — plaintext"
  [ "$(nv st_ftp_mode)" = "1" ] && high "FTP allows anonymous/guest login"
else ok "FTP disabled"; fi
if [ "$(nv enable_samba)" = "1" ]; then
  [ "$(nv st_samba_mode)" = "1" ] && high "Samba allows guest access" || low "Samba enabled (LAN)"
  [ "$(nv smbd_protocol)" = "0" ] && high "Samba allows SMBv1"
else ok "Samba disabled"; fi
[ "$(nv enable_webdav)" = "1" ] && high "AiCloud/WebDAV enabled — auth-bypass CVE history, disable unless needed" || ok "AiCloud/WebDAV disabled"
[ "$(nv wps_enable)" = "1" ] && med "WPS enabled — PIN brute-forceable" || ok "WPS disabled"
[ "$(nv vts_enable_x)" = "1" ] && { low "Port forwarding active:"; nv vts_rulelist | sed 's/</\n/g' | grep -v '^$' | while read -r r; do info "  $r"; done; }

# ─────────────────────────────────────────────────────────────
hdr "DNS INTEGRITY"
DOT=$(nv dnspriv_enable)
[ "$DOT" = "1" ] && ok "DNS-over-TLS (DoT) enabled" || med "DoT disabled (dnspriv_enable) — DNS queries in plaintext"
[ "$(nv dns_norebind)" = "1" ] && ok "DNS rebind protection on" || med "DNS rebind protection off (dns_norebind)"
RESOLVERS="$(nv wan0_dns) $(nv wan_dns) $(nv ipv6_dns1)"
info "Configured WAN resolvers: $(echo $RESOLVERS | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
# flag well-known plaintext public resolvers set directly (bypasses NextDNS/stubby)
for d in $RESOLVERS; do
  case "$d" in
    8.8.8.8|8.8.4.4|1.1.1.1|1.0.0.1|9.9.9.9|208.67.222.222)
      low "Public resolver $d set directly — confirm this is intentional vs NextDNS/stubby" ;;
  esac
done
if [ "$DOT" = "1" ]; then
  info "DoT upstreams (dnspriv_rulelist):"
  nv dnspriv_rulelist | sed 's/</\n/g' | grep -v '^$' | while read -r r; do info "  $r"; done
fi
# running resolver vs config — rogue resolv.conf injection
if [ -f /etc/resolv.conf ]; then
  RC=$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
  info "dnsmasq upstream (/etc/resolv.conf): ${RC:-none}"
fi
for f in /tmp/resolv.conf /etc/resolv.dnsmasq; do
  [ -f "$f" ] && info "$f: $(grep -E '^(server|nameserver)' "$f" 2>/dev/null | awk '{print $NF}' | tr '\n' ' ')"
done

# ─────────────────────────────────────────────────────────────
hdr "WI-FI"
for IF in $(nv wl_ifnames); do
  P=$(nvram show 2>/dev/null | grep "^wl[0-9]*_ifname=$IF$" | head -1 | cut -d_ -f1)
  [ -z "$P" ] && continue
  SSID=$(nv ${P}_ssid); AUTH=$(nv ${P}_auth_mode_x); CRY=$(nv ${P}_crypto)
  case "$AUTH" in
    open)       [ "$(nv ${P}_wep_x)" != "0" ] && crit "$SSID ($P): WEP" || crit "$SSID ($P): OPEN network" ;;
    shared|wep) crit "$SSID ($P): WEP" ;;
    psk)        high "$SSID ($P): WPA1-only" ;;
    pskpsk2)    med  "$SSID ($P): WPA/WPA2 mixed — use WPA2 or WPA3" ;;
    psk2)       ok   "$SSID ($P): WPA2-PSK" ;;
    psk2sae)    ok   "$SSID ($P): WPA2/WPA3 transition" ;;
    sae)        ok   "$SSID ($P): WPA3-SAE" ;;
    owe)        ok   "$SSID ($P): OWE" ;;
    *)          info "$SSID ($P): auth=$AUTH" ;;
  esac
  case "$CRY" in *tkip*) med "$SSID ($P): TKIP cipher — AES only" ;; esac
done

# ─────────────────────────────────────────────────────────────
hdr "GUEST / VLAN ISOLATION"
FOUND_GUEST=0
for P in $(nvram show 2>/dev/null | grep -oE '^wl[0-9]\.[0-9]_bss_enabled=1' | cut -d_ -f1); do
  FOUND_GUEST=1
  GS=$(nv ${P}_ssid)
  LA=$(nv ${P}_lanaccess)   # "off" = isolated from LAN
  AI=$(nv ${P}_ap_isolate)  # 1 = clients can't see each other
  [ "$LA" = "off" ] && ok "Guest '$GS' ($P): isolated from LAN" || high "Guest '$GS' ($P): has LAN access (lanaccess=$LA) — isolate it"
  [ "$AI" = "1" ] && ok "Guest '$GS' ($P): client isolation on" || low "Guest '$GS' ($P): clients can see each other (ap_isolate=0)"
done
[ $FOUND_GUEST = 0 ] && info "No guest networks enabled"

# ─────────────────────────────────────────────────────────────
hdr "VPN PEERS"
if command -v wg >/dev/null 2>&1; then
  wg show all 2>/dev/null | grep -E 'interface|peer|endpoint|latest handshake|allowed ips' | while read -r l; do info "$l"; done
  wg show all allowed-ips 2>/dev/null | grep -q '0.0.0.0/0' && low "A WireGuard peer has allowed-ips 0.0.0.0/0 (full tunnel) — confirm intended"
else
  info "wg tool not present"
fi
for c in /tmp/etc/openvpn/*/config.ovpn /jffs/openvpn/*.ovpn; do
  [ -f "$c" ] || continue
  grep -q 'redirect-gateway\|0.0.0.0 0.0.0.0' "$c" 2>/dev/null && low "OpenVPN $c routes all traffic (redirect-gateway) — confirm intended"
  grep -qE 'cipher (BF|DES|RC4|none)' "$c" 2>/dev/null && high "OpenVPN $c uses a weak/legacy cipher"
done

# ─────────────────────────────────────────────────────────────
hdr "TLS CERTIFICATE (Web UI)"
CERT=/etc/cert.pem; [ -f /jffs/.cert/cert.pem ] && CERT=/jffs/.cert/cert.pem
if [ -f "$CERT" ] && command -v openssl >/dev/null 2>&1; then
  END=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2)
  BITS=$(openssl x509 -text -noout -in "$CERT" 2>/dev/null | grep -oE 'Public-Key: \([0-9]+ bit\)' | grep -oE '[0-9]+')
  SIG=$(openssl x509 -text -noout -in "$CERT" 2>/dev/null | grep 'Signature Algorithm' | head -1 | awk '{print $NF}')
  info "Expires:   $END"
  info "Key size:  ${BITS:-?} bit   Sig: ${SIG:-?}"
  [ -n "$BITS" ] && [ "$BITS" -lt 2048 ] && high "Web UI cert key < 2048 bit"
  case "$SIG" in *sha1*|*md5*) high "Web UI cert uses weak signature ($SIG)" ;; esac
  if [ -n "$END" ]; then
    EXP=$(date -d "$END" +%s 2>/dev/null)
    NOW=$(date +%s)
    [ -n "$EXP" ] && [ "$EXP" -lt "$NOW" ] && med "Web UI cert is EXPIRED"
  fi
else info "No local cert found at $CERT (or openssl missing)"; fi

# ─────────────────────────────────────────────────────────────
hdr "OWN DEFENSES (Skynet / Diversion / firewall-start)"
check_script() {
  for f in "$2"; do
    if [ -f "$f" ]; then ok "$1 present: $f (md5 $(md5sum "$f" | cut -c1-12))"; return; fi
  done
  info "$1 not found"
}
check_script "firewall-start" "/jffs/scripts/firewall-start"
check_script "services-start"  "/jffs/scripts/services-start"
if [ -d /jffs/addons/skynet ] || command -v firewall >/dev/null 2>&1; then
  ok "Skynet addon directory present"
  for set in Skynet-Blacklist Skynet-BlockedRanges Skynet-Whitelist; do
    if command -v ipset >/dev/null 2>&1; then
      N=$(ipset -t list "$set" 2>/dev/null | grep -i 'Number of entries' | grep -oE '[0-9]+')
      [ -n "$N" ] && info "ipset $set: $N entries loaded"
    fi
  done
else info "Skynet not detected"; fi
[ -d /jffs/addons/diversion ] && ok "Diversion addon present" || info "Diversion not detected"
# confirm firewall actually has rules loaded (defense is live, not just installed)
if command -v iptables >/dev/null 2>&1; then
  NR=$(iptables -S 2>/dev/null | wc -l)
  [ "$NR" -gt 10 ] && ok "iptables has $NR rules loaded" || high "iptables nearly empty ($NR rules) — firewall may not be active"
fi

# ─────────────────────────────────────────────────────────────
hdr "LISTENING PORTS"
risky() {
  case "$1" in
    21) echo FTP;; 23) echo Telnet;; 69) echo TFTP;; 139|445) echo SMB;;
    1900|5000|5351) echo UPnP/NAT-PMP;; 8082|8443) echo AiCloud;; 8200) echo DLNA;;
    9100) echo Printer;; 3838) echo "ASUS infosvr";; 7788|9999) echo "ASUS service";;
    53282) echo "AyySSHush IOC";; *) echo "";;
  esac
}
netstat -lntu 2>/dev/null | awk 'NR>2{print $1, $4}' | sort -u | while read -r proto addr; do
  port=${addr##*:}; ip=${addr%:*}
  name=$(netstat -lntup 2>/dev/null | awk -v a="$addr" '$4==a{print $NF}' | head -1 | cut -d/ -f2)
  tag=$(risky "$port"); scope="LAN"
  case "$ip" in 0.0.0.0|::|:::*) scope="ALL";; 127.*|::1) scope="local";; esac
  line="$proto $addr  ${name:-?}  [$scope]${tag:+  <- $tag}"
  if [ "$port" = "53282" ]; then crit "$line"
  elif [ "$scope" = "ALL" ] && [ -n "$tag" ]; then med "$line (all interfaces — confirm WAN is firewalled)"
  else info "$line"; fi
done
info "External check from a VPS:  nmap -Pn -sV --script vulners -p- $(nv wan0_ipaddr)"

# ─────────────────────────────────────────────────────────────
hdr "UPnP PORT MAPPINGS"
MAPS=""
[ -f /tmp/upnp.leases ] && MAPS=$(cat /tmp/upnp.leases 2>/dev/null)
[ -z "$MAPS" ] && [ -f /var/lib/misc/upnp.leases ] && MAPS=$(cat /var/lib/misc/upnp.leases 2>/dev/null)
if [ -n "$MAPS" ]; then
  med "Active UPnP mappings — each is a LAN device punching a WAN hole:"
  echo "$MAPS" | while read -r l; do info "  $l"; done
else ok "No active UPnP mappings"; fi

# ─────────────────────────────────────────────────────────────
if [ $CONNTRACK = 1 ]; then
  hdr "OUTBOUND CONNECTIONS (snapshot)"
  CT=/proc/net/nf_conntrack; [ -f /proc/net/ip_conntrack ] && CT=/proc/net/ip_conntrack
  if [ -f "$CT" ]; then
    LANNET=$(nv lan_ipaddr | cut -d. -f1-3)
    # established outbound to non-standard high ports — possible C2/beaconing
    grep -E 'ESTABLISHED' "$CT" 2>/dev/null | grep -oE 'dport=[0-9]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -15 | while read -r cnt port; do
      case "$port" in
        80|443|53|123|22|993|995|587|465|5228|853) info "  $cnt conns -> :$port (common)";;
        9001|9030|9050|9150) high "  $cnt conns -> :$port (Tor-associated port)";;
        *) [ "$port" -gt 1024 ] && low "  $cnt conns -> :$port (uncommon high port — inspect)" || info "  $cnt conns -> :$port";;
      esac
    done
    # cross-reference Skynet blacklist if loaded
    if command -v ipset >/dev/null 2>&1 && ipset list Skynet-Blacklist >/dev/null 2>&1; then
      grep -oE 'dst=[0-9.]+' "$CT" | cut -d= -f2 | sort -u | while read -r d; do
        ipset test Skynet-Blacklist "$d" 2>/dev/null && high "  Outbound to $d — present in Skynet blacklist"
      done
    fi
  else info "conntrack table not readable"; fi
fi

# ─────────────────────────────────────────────────────────────
hdr "PERSISTENCE / INTEGRITY"
if [ "$(nv jffs2_scripts)" = "1" ]; then
  info "Custom JFFS scripts enabled — review each:"
  for f in /jffs/scripts/*; do
    [ -f "$f" ] || continue
    info "  $(ls -l "$f" | awk '{print $1,$6,$7,$8}')  $(basename "$f")  md5:$(md5sum "$f" | cut -c1-12)"
    grep -nE 'wget|curl|nc |/dev/tcp|base64 -d|chmod \+x /tmp|telnetd|dropbear .*-p' "$f" 2>/dev/null | head -5 | while read -r l; do
      med "  suspicious line in $(basename "$f"): $l"
    done
  done
fi
if command -v cru >/dev/null 2>&1; then
  CRON=$(cru l 2>/dev/null)
  [ -n "$CRON" ] && { info "Cron jobs:"; echo "$CRON" | while read -r c; do info "  $c"; done; }
  echo "$CRON" | grep -qE '/tmp/[^ ]*\.(sh|bin)|wget|curl .*\|' && high "Cron runs files from /tmp or pipes downloads — inspect"
fi
TMPX=$(find /tmp /var/tmp -maxdepth 2 -type f -perm -u+x 2>/dev/null | grep -vE '/tmp/(merlin-audit|etc|mnt|opt|var|home|share)' | head -20)
if [ -n "$TMPX" ]; then
  low "Executables in /tmp (often normal, malware also lives here):"
  echo "$TMPX" | while read -r f; do info "  $f"; done
else ok "No stray executables in /tmp"; fi
ps w 2>/dev/null | grep -E '/tmp/[^ ]+|\./[a-z0-9]{6,}' | grep -v grep | grep -v merlin-audit | while read -r p; do
  high "Process running from /tmp: $p"
done

# ─────────────────────────────────────────────────────────────
hdr "BASELINE INTEGRITY DIFF"
CUR="$WORK/cur.$STAMP"; mkdir -p "$CUR"
netstat -lntu 2>/dev/null | awk 'NR>2{print $1,$4}' | sort -u            > "$CUR/ports"
nv sshd_authkeys | tr '>' '\n' | grep -v '^$'                            > "$CUR/authkeys"
( for f in /jffs/scripts/*; do [ -f "$f" ] && echo "$(md5sum "$f")"; done ) 2>/dev/null > "$CUR/scripts"
( command -v cru >/dev/null 2>&1 && cru l 2>/dev/null )                   > "$CUR/cron"
( echo "$RESOLVERS" | tr ' ' '\n' | grep -v '^$' | sort -u )              > "$CUR/dns"
nv sshd_port                                                             > "$CUR/sshport"

if [ -d "$BASE" ] && [ -f "$BASE/ports" ]; then
  CHANGED=0
  for item in ports authkeys scripts cron dns sshport; do
    if [ -f "$BASE/$item" ] && ! diff "$BASE/$item" "$CUR/$item" >/dev/null 2>&1; then
      CHANGED=1
      # additions are the security-relevant direction
      ADD=$(diff "$BASE/$item" "$CUR/$item" 2>/dev/null | grep '^>' | sed 's/^> //')
      REM=$(diff "$BASE/$item" "$CUR/$item" 2>/dev/null | grep '^<' | sed 's/^< //')
      case "$item" in
        authkeys|scripts|sshport) SEVFN=high ;;
        ports|dns)                SEVFN=med  ;;
        *)                        SEVFN=low  ;;
      esac
      $SEVFN "CHANGED since baseline: $item"
      [ -n "$ADD" ] && echo "$ADD" | while read -r l; do info "  + $l"; done
      [ -n "$REM" ] && echo "$REM" | while read -r l; do info "  - $l"; done
    fi
  done
  [ $CHANGED = 0 ] && ok "No changes since last accepted baseline"
  [ $CHANGED = 1 ] && [ $ACCEPT = 0 ] && info "Re-run with --accept once you've confirmed these are legitimate."
else
  info "No baseline yet — current state will be recorded as the baseline."
  ACCEPT=1
fi
if [ $ACCEPT = 1 ]; then
  cp -f "$CUR"/* "$BASE"/ 2>/dev/null && info "Baseline updated: $BASE"
fi
rm -rf "$CUR"

# ─────────────────────────────────────────────────────────────
hdr "COMPONENT VERSIONS"
COMPS="$WORK/comps.txt"; : > "$COMPS"
add() { [ -n "$3" ] && { echo "$1|$2|$3" >> "$COMPS"; info "$(printf '%-12s %s' "$1" "$3")"; }; }
v=$(dnsmasq -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+[0-9.]*' | head -1);        add dnsmasq   "thekelleys:dnsmasq" "$v"
v=$(dropbear -V 2>&1 | grep -oE '20[0-9]{2}\.[0-9]+' | head -1);                           add dropbear  "dropbear_ssh_project:dropbear_ssh" "$v"
v=$(openssl version 2>/dev/null | awk '{print $2}' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+[a-z]?'); add openssl "openssl:openssl" "$v"
v=$(curl -V 2>/dev/null | head -1 | awk '{print $2}');                                       add curl      "haxx:curl" "$v"
v=$(busybox 2>&1 | head -1 | grep -oE 'v[0-9.]+' | tr -d v);                                 add busybox   "busybox:busybox" "$v"
v=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}');                             add openvpn   "openvpn:openvpn" "$v"
v=$(miniupnpd --version 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1);              add miniupnpd "miniupnp_project:miniupnpd" "$v"
v=$(smbd -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1);                      add samba     "samba:samba" "$v"
v=$(lighttpd -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1);                  add lighttpd  "lighttpd:lighttpd" "$v"
[ $KERNEL = 1 ] && { v=$(uname -r | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+'); add kernel "linux:linux_kernel" "$v"; }

# Entware packages — CVE-scan a curated network-facing allowlist only
if command -v opkg >/dev/null 2>&1; then
  info "Entware packages installed: $(opkg list-installed 2>/dev/null | wc -l)"
  opkg list-installed 2>/dev/null | while read -r pkg _ ver; do
    cpe=""
    case "$pkg" in
      unbound)      cpe="nlnetlabs:unbound" ;;
      stubby)       cpe="getdnsapi:stubby" ;;
      adguardhome)  cpe="adguard:adguardhome" ;;
      tor)          cpe="torproject:tor" ;;
      nginx)        cpe="f5:nginx" ;;
      wireguard*)   cpe="wireguard:wireguard" ;;
      python3)      cpe="python:python" ;;
      openssl*)     cpe="openssl:openssl" ;;
      tinyproxy)    cpe="banu:tinyproxy" ;;
    esac
    [ -n "$cpe" ] && { cv=$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+[0-9.]*'); [ -n "$cv" ] && echo "$pkg|$cpe|$cv" >> "$COMPS"; }
  done
fi

# ─────────────────────────────────────────────────────────────
if [ $OFFLINE = 0 ]; then
  hdr "FIRMWARE FRESHNESS"
  LATEST=$(curl -fsSL --max-time 30 "$GH_REL" 2>/dev/null | grep -oE '"tag_name":"[^"]+"' | head -1 | cut -d'"' -f4)
  if [ -n "$LATEST" ]; then
    info "Installed: $FW    Latest Merlin tag: $LATEST"
    echo "$LATEST" | grep -q "$BUILD" && ok "Firmware appears current" || med "Newer Merlin release exists ($LATEST) — review changelog"
  else info "Could not reach GitHub for latest Merlin release"; fi

  hdr "CVE LOOKUP (NVD + CISA KEV)"
  info "Merlin/ASUS backport some fixes — treat hits as candidates, verify against changelog."
  if [ ! -s "$KEV" ] || [ -n "$(find "$KEV" -mmin +1440 2>/dev/null)" ]; then
    curl -fsSL --max-time 60 "$KEV_URL" -o "$KEV.tmp" 2>/dev/null && mv "$KEV.tmp" "$KEV"
  fi
  [ -s "$KEV" ] && info "CISA KEV catalog loaded" || info "KEV download failed — exploited-in-wild flags unavailable"
  HDRK=""; DELAY=7
  [ -n "$NVD_API_KEY" ] && { HDRK="apiKey: $NVD_API_KEY"; DELAY=1; }
  while IFS='|' read -r name cpe ver; do
    J="$WORK/nvd-$name.json"
    URL="$NVD?virtualMatchString=cpe:2.3:a:$cpe:$ver&noRejected"
    [ "$name" = kernel ] && URL="$NVD?virtualMatchString=cpe:2.3:o:$cpe:$ver&noRejected"
    if [ -n "$HDRK" ]; then curl -fsS --max-time 60 -H "$HDRK" "$URL" -o "$J" 2>/dev/null
    else curl -fsS --max-time 60 "$URL" -o "$J" 2>/dev/null; fi
    if [ ! -s "$J" ]; then info "$name $ver: NVD query failed (rate limit / no internet)"; sleep "$DELAY"; continue; fi
    if [ $HAVE_JQ = 1 ]; then
      TOTAL=$(jq '.totalResults' "$J")
      if [ "$TOTAL" = "0" ]; then ok "$name $ver: no known CVEs"; sleep "$DELAY"; continue; fi
      out "${B}$name $ver — $TOTAL CVE(s):${N}"
      jq -r '.vulnerabilities[].cve | [.id,((.metrics.cvssMetricV31[0].cvssData.baseScore // .metrics.cvssMetricV30[0].cvssData.baseScore // .metrics.cvssMetricV2[0].cvssData.baseScore // 0)|tostring)] | @tsv' "$J" \
        | sort -t"$(printf '\t')" -k2 -rn | while IFS="$(printf '\t')" read -r id score; do
          kev=""; [ -s "$KEV" ] && grep -q "\"$id\"" "$KEV" && kev=" ${R}[EXPLOITED-KEV]${N}"
          s=${score%.*}
          if [ -n "$kev" ] || [ "$s" -ge 9 ]; then crit "$name: $id  CVSS $score$kev"
          elif [ "$s" -ge 7 ]; then high "$name: $id  CVSS $score"
          elif [ "$s" -ge 4 ]; then med  "$name: $id  CVSS $score"
          else low "$name: $id  CVSS $score"; fi
        done
    else
      IDS=$(grep -oE '"id":"CVE-[0-9]+-[0-9]+"' "$J" | cut -d'"' -f4 | sort -u)
      if [ -z "$IDS" ]; then ok "$name $ver: no known CVEs"
      else
        out "${B}$name $ver — $(echo "$IDS" | wc -l) CVE(s) (install jq for scores):${N}"
        for id in $IDS; do
          if [ -s "$KEV" ] && grep -q "\"$id\"" "$KEV"; then crit "$name: $id [EXPLOITED-KEV]"
          else med "$name: $id"; fi
        done
      fi
    fi
    sleep "$DELAY"
  done < "$COMPS"
  if [ -s "$KEV" ] && [ $HAVE_JQ = 1 ]; then
    hdr "ASUS ENTRIES IN CISA KEV (actively exploited)"
    info "Confirm each is fixed in firmware $FW:"
    jq -r '.vulnerabilities[] | select(.vendorProject|test("asus";"i")) | "\(.dateAdded)  \(.cveID)  \(.product): \(.vulnerabilityName)"' "$KEV" \
      | sort -r | while read -r l; do info "  $l"; done
  fi
fi

# ─────────────────────────────────────────────────────────────
hdr "SUMMARY"
SCORE=$((100 - CRIT*20 - HIGH*8 - MED*3 - LOW*1)); [ $SCORE -lt 0 ] && SCORE=0
out "${R}Critical: $CRIT${N}   ${R}High: $HIGH${N}   ${Y}Medium: $MED${N}   ${M}Low: $LOW${N}   ${G}Pass: $PASS${N}"
out "Hardening score: $SCORE/100"
out "Report saved: $REPORT"

if [ $JSON = 1 ]; then
  {
    printf '{"tool":"merlin-audit","version":"%s","ts":"%s","model":"%s","firmware":"%s",' "$VERSION" "$STAMP" "$MODEL" "$FW"
    printf '"summary":{"critical":%d,"high":%d,"medium":%d,"low":%d,"pass":%d,"score":%d},"findings":[' "$CRIT" "$HIGH" "$MED" "$LOW" "$PASS" "$SCORE"
    paste -sd, "$FIND" 2>/dev/null || (tr '\n' ',' < "$FIND" | sed 's/,$//')
    printf ']}\n'
  } > "$RJSON"
  cat "$RJSON"
  out "JSON saved: $RJSON"
fi
