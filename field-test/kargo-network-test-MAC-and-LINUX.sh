#!/usr/bin/env bash
# =============================================================================
#  Kargo Network Test  -  macOS / Linux
#  Version 2.1  (2026-10-09)
#
#  Run this from a laptop that is ON THE SAME NETWORK AND VLAN the Kargo
#  devices will use, physically at the dock doors where the towers will be
#  installed.
#
#  Usage:   bash kargo-network-test-MAC-and-LINUX.sh
#  Output:  console summary + kargo-network-test-results.txt
#           Email the results file back to your Kargo contact.
#
#  This script only makes OUTBOUND connections. It changes nothing on the
#  machine or the network, and installs nothing.
#
#  Changes in 2.1 (from 2.0)
#    - Certificates are VALIDATED, not just read: chain and hostname are checked,
#      and the issuer check is kept on top. Both are needed - on a managed
#      laptop an intercepted connection validates fine and only the issuer name
#      gives it away; without the corporate CA installed, validation fails.
#    - A TLS-layer failure is no longer reported as a blocked port. The two are
#      distinguished and named separately.
#    - Each TLS check prints the protocol and cipher actually negotiated, so a
#      report can be compared against another site's without re-testing.
#    - DNS, TCP and UDP checks are retried. A single dropped packet used to be
#      reported as a blocked port.
#    - UDP 3478 is checked with a Tailscale-format STUN request (SOFTWARE
#      "tailnode" plus FINGERPRINT); the server drops anything else silently.
#      "No reply" and "a reply that was not valid STUN" are now reported
#      separately - the second means UDP egress works and is not a firewall
#      problem. On success a bare RFC 5389 request is also sent, to show on the
#      customer's own network why generic STUN tools call this port closed.
# =============================================================================

set -u

RESULTS="kargo-network-test-results.txt"
PASS_N=0; FAIL_N=0; WARN_N=0

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  G=$(tput setaf 2); R=$(tput setaf 1); Y=$(tput setaf 3); B=$(tput setaf 4); D=$(tput sgr0); BOLD=$(tput bold)
else
  G=""; R=""; Y=""; B=""; D=""; BOLD=""
fi

log()  { printf '%s\n' "$*" | tee -a "$RESULTS" >/dev/null; }
say()  { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$RESULTS"; }
hdr()  { printf '\n%s%s%s\n' "$BOLD$B" "$*" "$D"; printf '\n%s\n' "$*" >> "$RESULTS"; }

result() { # result <status> <label> <detail>
  local st="$1" label="$2" detail="${3:-}"
  case "$st" in
    PASS)   PASS_N=$((PASS_N+1));   printf '  %s[ PASS ]%s %-46s %s\n' "$G" "$D" "$label" "$detail" ;;
    FAIL)   FAIL_N=$((FAIL_N+1));   printf '  %s[ FAIL ]%s %-46s %s\n' "$R" "$D" "$label" "$detail" ;;
    WARN)   WARN_N=$((WARN_N+1));   printf '  %s[ WARN ]%s %-46s %s\n' "$Y" "$D" "$label" "$detail" ;;
  esac
  printf '  [ %-6s ] %-46s %s\n' "$st" "$label" "$detail" >> "$RESULTS"
}

# ---------- helpers ---------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

# tcp_check <host> <port>  -> 0 open, 1 closed/blocked
#
# Retried, because a single dropped SYN on a busy warehouse link would otherwise
# be reported as a blocked port. A confident FAIL that sends a network team
# looking for a rule that was never the problem is the most expensive kind of
# wrong answer this script can give.
tcp_check() {
  local n=0
  while [ $n -lt 2 ]; do
    if tcp_once "$1" "$2"; then return 0; fi
    n=$((n+1))
  done
  return 1
}

tcp_once() {
  local h="$1" p="$2"
  if have nc; then
    nc -z -w 6 "$h" "$p" >/dev/null 2>&1
  else
    ( exec 3<>"/dev/tcp/$h/$p" ) >/dev/null 2>&1 &
    local pid=$!; local n=0
    while kill -0 $pid 2>/dev/null && [ $n -lt 6 ]; do sleep 1; n=$((n+1)); done
    if kill -0 $pid 2>/dev/null; then kill $pid 2>/dev/null; return 1; fi
    wait $pid 2>/dev/null
  fi
}

# tls_probe <host> <port> [novrfy]
#   -> sets TLS_ISSUER (subject and issuer, or empty), TLS_NEG and TLS_VERIFIED.
#
# Uses curl rather than `openssl s_client`, deliberately: openssl has no connect
# timeout, and macOS has no `timeout` command to wrap it with, so on a silently
# dropped port it would hang forever - which is precisely the case being tested.
# --noproxy '*' is intentional too: a Kargo device does not use an HTTP proxy, so
# borrowing the laptop's proxy settings would test a path the device will not have.
#
# The certificate is VALIDATED first, not just read. An earlier version connected
# with -k and judged the issuer string alone, which would accept an expired
# certificate, one issued for a different hostname, or one that simply claims to
# be Let's Encrypt. Only if validation fails do we reconnect with -k, so we can
# still report the certificate that was actually presented - normally the
# inspection CA, which is the single most useful line in the whole report.
#
# Validation and the issuer check catch different faults and both are needed. On
# a managed laptop the corporate inspection CA is usually installed in the trust
# store, so an intercepted connection validates perfectly - only the issuer name
# gives it away. Conversely a laptop without that CA fails validation, which the
# issuer check alone would not explain.
#
# The negotiated protocol and cipher are captured from the same run and left in
# TLS_NEG. A host can serve a different certificate per TLS version - t01 serves
# an ECDSA cert at TLS 1.2 and an RSA cert at TLS 1.3 - so a client whose cipher
# policy excludes ECDHE-ECDSA fails at 1.2 and succeeds at 1.3 on the very same
# open port. Recording what was negotiated makes that visible instead of leaving
# it to be reconstructed later from a bare pass or fail.
#
# Results are left in the globals TLS_ISSUER and TLS_NEG rather than printed.
# Printing them and capturing with $(...) would run this in a subshell, where an
# assignment to TLS_NEG is discarded the moment the subshell exits - so the caller
# would silently see an empty string with no error to explain it.
TLS_ISSUER=""
TLS_NEG=""
TLS_VERIFIED=0
tls_probe() {
  local raw
  TLS_ISSUER=""; TLS_NEG=""; TLS_VERIFIED=0

  if [ -z "${3:-}" ]; then
    raw=$(curl -sv --noproxy '*' --max-time 12 "https://$1:$2/" -o /dev/null 2>&1)
    # curl prints this line only after the chain and the hostname both check out.
    if printf '%s' "$raw" | grep -qi 'SSL certificate verify ok'; then
      TLS_VERIFIED=1
    fi
  fi

  # Reconnect unverified when validation failed, or when the caller already knows
  # the endpoint uses a private CA (the Digi one on 3199 is not publicly trusted
  # and never will be, so attempting validation there just wastes 12 seconds).
  if [ "$TLS_VERIFIED" -eq 0 ]; then
    raw=$(curl -sv -k --noproxy '*' --max-time 12 "https://$1:$2/" -o /dev/null 2>&1)
  fi

  TLS_NEG=$(printf '%s\n' "$raw" | grep -iE 'SSL connection using|SSL re-using' \
    | head -1 | sed 's/^[*[:space:]]*//')
  TLS_ISSUER=$(printf '%s\n' "$raw" | grep -iE '^\** *(subject|issuer):' \
    | sed 's/^[*[:space:]]*//' | tr '\n' ' ')
  return 0
}

# timeout_run <secs> <cmd...>   (portable-ish; macOS has no `timeout` by default)
timeout_run() {
  local secs="$1"; shift
  if have timeout; then timeout "$secs" "$@"
  elif have gtimeout; then gtimeout "$secs" "$@"
  else "$@"
  fi
}

# stun_probe <host> <port>
#   prints "<public ip> <public port>" as seen by the server.
#   returns 0 valid reply | 1 silence | 2 nc unavailable | 3 reply that is not STUN
#
# Return 3 matters. Silence means the port is blocked. A reply that is not a valid
# STUN response means UDP egress works and something is answering on 3478 - a
# completely different thing to tell a firewall team, and one this script used to
# collapse into the same FAIL as silence.
stun_probe() {
  have nc || return 2
  # Capture the arguments BEFORE anything calls `set --`, which replaces them.
  local host="$1" port="$2"

  # 32-byte prefix: header + SOFTWARE attribute. The CRC covers exactly this.
  local PRE='\x00\x01\x00\x14\x21\x12\xa4\x42KargoTest123\x80\x22\x00\x08tailnode'
  set -- $(printf "$PRE" | gzip -c | tail -c 8 | od -An -tu1)
  local CRC=$(( $1 | ($2 << 8) | ($3 << 16) | ($4 << 24) ))
  local FP=$(( (CRC ^ 0x5354554E) & 0xFFFFFFFF ))
  local PKT="$PRE"'\x80\x28\x00\x04'
  PKT="$PKT$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
       $(( (FP>>24)&255 )) $(( (FP>>16)&255 )) $(( (FP>>8)&255 )) $(( FP&255 )))"

  # Retried: UDP is lossy, and one dropped datagram reported as "port blocked"
  # is exactly the false FAIL this test exists to avoid.
  local attempt=0 RESP=""
  while [ $attempt -lt 3 ]; do
    attempt=$((attempt + 1))
    RESP=$(printf "$PKT" | nc -u -w 5 "$host" "$port" 2>/dev/null | od -An -tu1)
    [ -n "$RESP" ] && break
  done
  [ -z "$RESP" ] && return 1

  set -- $RESP

  # Something answered. From here a failure is "not a valid STUN response", not
  # "blocked" - we have proof the datagram got out and something came back.
  # The transaction ID is checked, not merely noted: without it any stray UDP
  # datagram that happens to carry the magic cookie would count as a pass.
  [ "$#" -ge 20 ] || return 3
  [ "$1" = "1" ] && [ "$2" = "1" ] || return 3
  [ "$5" = "33" ] && [ "$6" = "18" ] && [ "$7" = "164" ] && [ "$8" = "66" ] || return 3
  [ "${9}" = "75" ] && [ "${20}" = "51" ] || return 3

  # XOR mask for the mapped address: magic cookie followed by the transaction
  # ID. IPv4 uses the first 4 bytes; IPv6 uses all 16.
  local MASK="33 18 164 66 75 97 114 103 111 84 101 115 116 49 50 51"

  # Walk the attributes. Offsets are 1-based positional parameters, so byte N
  # of the packet is ${N+1}.
  local n=$#
  local i=21 tp lp at al vs fam k b m out prt
  while [ $((i + 3)) -le $n ]; do
    tp=$i;     lp=$((i + 1))
    at=$(( ${!tp} * 256 + ${!lp} ))
    tp=$((i + 2)); lp=$((i + 3))
    al=$(( ${!tp} * 256 + ${!lp} ))
    vs=$((i + 4))                              # first byte of the value
    if [ "$at" = "32" ] || [ "$at" = "32800" ]; then     # 0x0020 / 0x8020
      tp=$((vs + 1)); fam=${!tp}
      # The port is XORed with the top half of the magic cookie (0x2112 = 8466).
      tp=$((vs + 2)); lp=$((vs + 3))
      prt=$(( ((${!tp} * 256 + ${!lp}) ^ 8466) & 65535 ))
      if [ "$fam" = "1" ]; then
        out=""
        for k in 0 1 2 3; do
          tp=$((vs + 4 + k)); b=${!tp}
          m=$(echo $MASK | cut -d' ' -f$((k + 1)))
          out="${out:+$out.}$(( b ^ m ))"
        done
        printf '%s %s\n' "$out" "$prt"; return 0
      elif [ "$fam" = "2" ]; then
        out=""
        for k in 12 13 14 15; do                # ::ffff:a.b.c.d -> last 4 bytes
          tp=$((vs + 4 + k)); b=${!tp}
          m=$(echo $MASK | cut -d' ' -f$((k + 1)))
          out="${out:+$out.}$(( b ^ m ))"
        done
        printf '%s %s\n' "$out" "$prt"; return 0
      fi
    elif [ "$at" = "1" ]; then                  # plain MAPPED-ADDRESS fallback
      tp=$((vs + 2)); lp=$((vs + 3))
      prt=$(( ${!tp} * 256 + ${!lp} ))          # not XORed in MAPPED-ADDRESS
      out=""
      for k in 0 1 2 3; do tp=$((vs + 4 + k)); out="${out:+$out.}${!tp}"; done
      printf '%s %s\n' "$out" "$prt"; return 0
    fi
    i=$(( i + 4 + al + ((4 - al % 4) % 4) ))
  done
  return 0        # valid reply, address attribute not recognised
}

# stun_bare_silent <host> <port> -> 0 if a bare RFC 5389 request gets no answer.
#
# 20 bytes: header only, no SOFTWARE, no FINGERPRINT - exactly what a stock
# stunclient, nmap --script stun-info or a web port checker sends. Run only after
# the real probe has already succeeded, so the report can show, from the
# customer's own network, that a generic tool calls this port closed while it is
# demonstrably open. That argument otherwise has to be made in a meeting.
stun_bare_silent() {
  have nc || return 1
  local B='\x00\x01\x00\x00\x21\x12\xa4\x42KargoBare456'
  local R
  R=$(printf "$B" | nc -u -w 3 "$1" "$2" 2>/dev/null | od -An -tu1)
  [ -z "$R" ]
}

# ---------- start -----------------------------------------------------------

: > "$RESULTS"
say "==============================================================="
say " KARGO NETWORK TEST v2.1"
say " Run at : $(date)"
say " Host   : $(hostname 2>/dev/null)"
say " OS     : $(uname -srm 2>/dev/null)"
say "==============================================================="
say ""
say "Site / customer name : ______________________________________"
say "Dock door(s) tested  : ______________________________________"
say "SSID or switch port  : ______________________________________"
say "VLAN ID              : ______________________________________"
say "Tested by            : ______________________________________"
say ""

# ---------- 0. Test environment sanity -------------------------------------
hdr "0. TEST ENVIRONMENT"

IP4=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[ -z "${IP4:-}" ] && IP4=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | head -1)
if [ -n "${IP4:-}" ]; then
  result PASS "Local IP address obtained (DHCP/static)" "$IP4"
else
  result FAIL "Local IP address obtained (DHCP/static)" "no IPv4 address - check DHCP / cabling / Wi-Fi"
fi

GW=$(ip route 2>/dev/null | awk '/default/{print $3; exit}')
[ -z "${GW:-}" ] && GW=$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')
say "  Default gateway  : ${GW:-unknown}"

RESOLVERS=$( (cat /etc/resolv.conf 2>/dev/null | awk '/^nameserver/{print $2}' ; scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/{print $3}') | sort -u | tr '\n' ' ')
say "  Site DNS servers : ${RESOLVERS:-unknown}"

# One probe, two jobs. sdn.kargo.zone runs a Tailscale-format STUN server on
# UDP 3478, so a single tailnode-format binding request both proves that port is
# open (section 6 below) and reports the public address the server saw us from -
# which is how we know the technician is really on the site's network.
#
# The address comes from a host that is already on the Kargo whitelist, so this
# needs no extra firewall permission and no third-party service.
STUN_OUT=$(stun_probe sdn.kargo.zone 3478); STUN_RC=$?
STUN_IP=$(printf '%s' "${STUN_OUT:-}" | awk '{print $1}')
STUN_PORT=$(printf '%s' "${STUN_OUT:-}" | awk '{print $2}')
if [ "$STUN_RC" -eq 0 ] && [ -n "${STUN_IP:-}" ]; then
  say "  Public egress IP : $STUN_IP   (as seen by sdn.kargo.zone${STUN_PORT:+, source port $STUN_PORT})"
  say "      ^ Confirm with your IT team that this is THIS SITE's public IP. If it"
  say "        is not, a VPN, proxy or exit node is in the path and every result"
  say "        below describes the wrong network."
else
  say "  Public egress IP : could not determine (see the UDP 3478 result below)"
fi

# Local VPN detection. This is the check that actually gates the run, because it
# does not depend on any external service being reachable.
VPN_WHY=""
if have scutil && scutil --nc list 2>/dev/null | grep -q '(Connected)'; then
  VPN_WHY="a VPN service is CONNECTED (scutil)"
elif ip link show 2>/dev/null | grep -qE ': (tun|tailscale|utun|wg|ppp)[0-9]*:'; then
  VPN_WHY="a VPN/tunnel interface is up"
elif ifconfig 2>/dev/null \
     | awk '/^(utun|tun|tap|wg|ppp)[0-9]*:/{f=1;next} /^[a-z]/{f=0} f && /inet /{print}' \
     | grep -q 'inet '; then
  # macOS: a tunnel interface that has actually been assigned an address.
  # (Bare utun devices with no inet are normal on macOS and are not a VPN.)
  VPN_WHY="a tunnel interface has an IP address"
fi

# Tailscale leaves fingerprints even when the generic checks miss it.
if printf '%s' "${RESOLVERS:-}" | grep -q '100\.100\.100\.100'; then
  VPN_WHY="${VPN_WHY:+$VPN_WHY; }Tailscale MagicDNS (100.100.100.100) is this machine's resolver"
fi
if ifconfig 2>/dev/null | grep -qE 'inet 100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.'; then
  VPN_WHY="${VPN_WHY:+$VPN_WHY; }this machine holds a Tailscale/CGNAT 100.64.0.0/10 address"
fi
if have tailscale && tailscale status >/dev/null 2>&1; then
  VPN_WHY="${VPN_WHY:+$VPN_WHY; }the tailscale CLI reports an active tailnet"
fi

if [ -n "${VPN_WHY:-}" ]; then
  result FAIL "No VPN active on test machine" "$VPN_WHY - disconnect it and re-run, these results are not valid"
else
  result PASS "No VPN detected on test machine" "note: proxy-based clients (Zscaler, Netskope) leave no interface - check the egress IP above"
fi

# ---------- 1. Captive portal ----------------------------------------------
hdr "1. CAPTIVE PORTAL CHECK  (Kargo devices cannot use captive-portal networks)"

CP=$(timeout_run 12 curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 8 http://connectivitycheck.gstatic.com/generate_204 2>/dev/null)
case "$CP" in
  204) result PASS "No captive portal on this network" "HTTP 204 as expected" ;;
  000) result WARN "Captive portal check" "no response - plain HTTP egress may be blocked entirely" ;;
  *)   result FAIL "No captive portal on this network" "got HTTP $CP instead of 204 - portal / interception present" ;;
esac

# ---------- 2. DNS (8.8.8.8 UDP 53) ----------------------------------------
hdr "2. DNS RESOLUTION   what matters is correct answers, not which resolver"

resolve_via() { # resolve_via <server|"" for default> <name>  (retried twice)
  local a n=0
  while [ $n -lt 2 ]; do
    a=$(resolve_once "$1" "$2")
    [ -n "${a:-}" ] && { printf '%s\n' "$a"; return 0; }
    n=$((n + 1))
  done
  return 1
}

resolve_once() {
  local srv="$1" name="$2"
  if have dig; then
    if [ -n "$srv" ]; then dig +short +time=4 +tries=1 "@$srv" "$name" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1
    else dig +short +time=4 +tries=1 "$name" A 2>/dev/null | grep -E '^[0-9.]+$' | head -1; fi
  elif have nslookup; then
    if [ -n "$srv" ]; then nslookup "$name" "$srv" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1
    else nslookup "$name" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1; fi
  elif have python3 && [ -z "$srv" ]; then
    python3 -c "import socket,sys;print(socket.gethostbyname(sys.argv[1]))" "$name" 2>/dev/null
  fi
}

# PRIMARY: whatever resolver this machine is configured with must return correct answers.
SITE_DNS_OK=1
for pair in "sdn.kargo.zone 13.56.25.183" "t01.tunnel.kargo.zone 54.153.23.224"; do
  set -- $pair; NAME=$1; EXPECT=$2
  GOT=$(resolve_via "" "$NAME")
  if [ -z "${GOT:-}" ]; then
    result FAIL "Configured resolver resolves $NAME" "no answer - DNS is not working on this network"
    SITE_DNS_OK=0
  elif [ "$GOT" = "$EXPECT" ]; then
    result PASS "Configured resolver resolves $NAME" "$GOT"
  else
    result FAIL "Configured resolver resolves $NAME" "got $GOT, expected $EXPECT - resolver is returning a modified answer"
    SITE_DNS_OK=0
  fi
done

GOT=$(resolve_via "" "edp12.devicecloud.com")
if [ -n "${GOT:-}" ]; then result PASS "Configured resolver resolves edp12.devicecloud.com" "$GOT"
else result FAIL "Configured resolver resolves edp12.devicecloud.com" "site resolver cannot resolve this name"; SITE_DNS_OK=0; fi

# SECONDARY: 8.8.8.8 is only required as a fallback when the site resolver is unusable.
GOT=$(resolve_via 8.8.8.8 "sdn.kargo.zone")
if [ "${GOT:-}" = "13.56.25.183" ]; then
  result PASS "8.8.8.8 reachable (optional fallback)" "$GOT"
elif [ -n "${GOT:-}" ]; then
  # An answer came back, but the wrong one - outbound DNS is being intercepted and
  # rewritten. That is a real fault, never "acceptable".
  result FAIL "8.8.8.8 returns a modified answer" "got $GOT, expected 13.56.25.183 - external DNS is being intercepted and rewritten"
elif [ "$SITE_DNS_OK" -eq 1 ]; then
  result WARN "8.8.8.8 reachable (optional fallback)" "blocked - acceptable, because the configured resolver is answering correctly"
else
  result FAIL "8.8.8.8 reachable (required here)" "the configured resolver is not answering correctly AND 8.8.8.8 is blocked - one of the two must work"
fi

# ---------- 3. TCP endpoints -----------------------------------------------
hdr "3. TCP ENDPOINTS"

tcp_case() { # tcp_case <label> <host> <port>
  if tcp_check "$2" "$3"; then result PASS "$1" "$2:$3 open"
  else result FAIL "$1" "$2:$3 unreachable - firewall / whitelist"; fi
}

tcp_case "t01 tunnel  (TCP 443)"            t01.tunnel.kargo.zone 443
tcp_case "54.153.23.224 SSH tunnel (TCP 8022)" 54.153.23.224        8022
tcp_case "Digi Remote Manager (TCP 3199)"   edp12.devicecloud.com 3199
tcp_case "sdn.kargo.zone (TCP 443)"         sdn.kargo.zone        443
tcp_case "sdn.kargo.zone (TCP 80)"          sdn.kargo.zone        80

# ---------- 4. Application-level HTTPS -------------------------------------
hdr "4. APPLICATION-LEVEL HTTPS"

BODY=$(timeout_run 15 curl -s --noproxy '*' --max-time 12 https://t01.tunnel.kargo.zone/robots.txt 2>/dev/null)
if printf '%s' "$BODY" | grep -qi 'Disallow'; then
  result PASS "https://t01.tunnel.kargo.zone/robots.txt" "returned expected robots.txt body"
else
  result FAIL "https://t01.tunnel.kargo.zone/robots.txt" "unexpected/empty body: $(printf '%s' "$BODY" | head -c 60 | tr '\n' ' ')"
fi

CODE=$(timeout_run 15 curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 12 https://sdn.kargo.zone/ 2>/dev/null)
if [ "$CODE" != "000" ] && [ -n "$CODE" ]; then
  result PASS "https://sdn.kargo.zone/ responds" "HTTP $CODE (any status = TLS reached the server)"
else
  result FAIL "https://sdn.kargo.zone/ responds" "no HTTPS response"
fi

# ---------- 5. TLS inspection ----------------------------------------------
hdr "5. TLS / HTTPS INSPECTION   (must be DISABLED for these hosts)"

check_issuer() { # check_issuer <label> <host> <port> <expected-substring>
  tls_probe "$2" "$3"
  local out="$TLS_ISSUER"
  if [ -z "$out" ]; then
    # Deliberately does NOT say "port blocked": the TCP section of this same report
    # may well show the port open, and blaming the firewall for a TLS-layer failure
    # sends network teams hunting a rule that is not the problem.
    if tcp_check "$2" "$3"; then
      result FAIL "$1" "TCP connected but no certificate was returned - TLS handshake failed"
    else
      result FAIL "$1" "TCP connect failed - port blocked or dropped"
    fi
    return
  fi
  # Detail line goes AFTER its own result row - printed before, it reads as if it
  # belongs to the previous test's verdict.
  if printf '%s' "$out" | grep -qi "$4"; then
    if [ "$TLS_VERIFIED" -eq 1 ]; then
      result PASS "$1" "issuer OK, chain and hostname verified - no interception"
    else
      # The issuer name is right but the certificate does not actually validate.
      # That is either an inspection product copying the name, or a genuine
      # certificate fault. This check cannot tell which, so it does not claim to.
      result FAIL "$1" "issuer name looks correct but the certificate did NOT validate - see detail below"
    fi
  else
    result FAIL "$1" "UNEXPECTED ISSUER - TLS inspection is intercepting this host"
  fi
  say "           ^ $2 $out"
  [ -n "$TLS_NEG" ] && say "           ^ $2 $TLS_NEG"
  if [ "$TLS_VERIFIED" -eq 1 ]; then
    say "           ^ $2 certificate chain and hostname validated against the system trust store"
  else
    say "           ^ $2 certificate did NOT validate (expired, wrong hostname, or an untrusted issuer)"
  fi
  return 0
}

check_issuer "t01.tunnel.kargo.zone cert issuer"  t01.tunnel.kargo.zone 443  "Let's Encrypt"
check_issuer "sdn.kargo.zone cert issuer"         sdn.kargo.zone        443  "Let's Encrypt"

# novrfy: the Digi certificate is issued by Digi's own CA and is not in any public
# trust store, so attempting validation here would always fail and tell us nothing.
# Identity is judged from the subject/issuer instead.
tls_probe edp12.devicecloud.com 3199 novrfy
DIGI="$TLS_ISSUER"
if [ -z "$DIGI" ]; then
  result FAIL "Digi EDP TLS handshake (port 3199)" "no certificate returned - blocked, dropped or refused"
else
  if printf '%s' "$DIGI" | grep -qiE 'digi|devicecloud'; then
    result PASS "Digi EDP TLS handshake (port 3199)" "genuine Digi certificate presented"
  else
    result FAIL "Digi EDP TLS handshake (port 3199)" "NON-DIGI certificate - inspection on port 3199"
  fi
  say "           ^ edp12.devicecloud.com $DIGI"
  [ -n "$TLS_NEG" ] && say "           ^ edp12.devicecloud.com $TLS_NEG"
fi

# ---------- 6. UDP -----------------------------------------------------------
hdr "6. UDP ENDPOINTS"

# UDP 3478 IS conclusively testable, but only with a Tailscale-format request:
# the server requires SOFTWARE="tailnode" plus a valid FINGERPRINT and drops
# anything else silently. A generic STUN client sees nothing and wrongly
# concludes the port is blocked. See the stun_probe comment at the top.
case "$STUN_RC" in
  0)
    result PASS "sdn.kargo.zone UDP 3478" "valid STUN response${STUN_IP:+, egress IP $STUN_IP}"
    # Now demonstrate, on this network, why generic tools disagree.
    if stun_bare_silent sdn.kargo.zone 3478; then
      say "           ^ a bare RFC 5389 request to the same port got NO reply, which is"
      say "             why stunclient, nmap and web port checkers call 3478 closed here."
      say "             The port is open. Only Tailscale-format requests are answered."
    fi
    ;;
  2) result WARN "sdn.kargo.zone UDP 3478" "nc not available - could not test" ;;
  3)
    # Something answered, so the datagram left the building. Saying "blocked"
    # here would send the firewall team after a rule that is already correct.
    result WARN "sdn.kargo.zone UDP 3478" "a reply came back but it was not a valid STUN response - UDP egress works, something unexpected is answering on 3478"
    ;;
  *) result FAIL "sdn.kargo.zone UDP 3478" "no reply after 3 attempts - UDP 3478 blocked" ;;
esac

# ---------- 7. Link health --------------------------------------------------
hdr "7. LINK HEALTH"

TOTAL=0; N=0; MAXV=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  T=$(timeout_run 10 curl -o /dev/null -s --noproxy '*' -w '%{time_connect}' --max-time 8 https://sdn.kargo.zone/ 2>/dev/null)
  case "$T" in ''|0.000000) continue ;; esac
  MS=$(awk -v t="$T" 'BEGIN{printf "%.0f", t*1000}')
  TOTAL=$((TOTAL+MS)); N=$((N+1))
  [ "$MS" -gt "$MAXV" ] && MAXV=$MS
done
if [ "$N" -gt 0 ]; then
  AVG=$((TOTAL/N))
  LOSS=$(( (10-N)*10 ))
  say "  TCP connect samples: $N/10   avg ${AVG}ms   worst ${MAXV}ms   failed ${LOSS}%"
  if [ "$N" -lt 10 ];    then result FAIL "Connection stability to sdn.kargo.zone" "${LOSS}% of connections failed - packet loss or flapping"
  elif [ "$AVG" -gt 250 ]; then result WARN "Latency to sdn.kargo.zone" "${AVG}ms avg - above the 250ms comfort threshold"
  else result PASS "Latency & stability to sdn.kargo.zone" "${AVG}ms avg, 10/10 connections"; fi
else
  result FAIL "Latency & stability to sdn.kargo.zone" "no successful connections"
fi

# ---------- summary ---------------------------------------------------------
hdr "SUMMARY"
say "  PASS: $PASS_N    FAIL: $FAIL_N    WARN: $WARN_N"
say ""
if [ "$FAIL_N" -eq 0 ] && [ "$WARN_N" -eq 0 ]; then
  say "  Everything this script can verify passed."
elif [ "$FAIL_N" -eq 0 ]; then
  say "  No failures. Review the WARN lines above - they are usually acceptable."
else
  say "  $FAIL_N check(s) FAILED. Send $RESULTS to your Kargo contact and to your"
  say "  network/firewall team - each failing line names the exact host, port and"
  say "  protocol that needs to be allowed."
fi

hdr "STILL TO DO - NOT CHECKED BY THIS SCRIPT"
say "  These three requirements cannot be proven from a laptop. They are on the"
say "  results sheet in the Kargo Network Test PDF and still need completing:"
say ""
say "    1. UDP 41641 to 13.56.25.183, 3.151.242.46"
say "       and 54.176.130.49                           firewall rule review"
say "    2. Upload bandwidth, 20 Mbps per active dock   measure at the dock"
say "    3. Wi-Fi at least -67 dBm at each tower"
say "       position, or LTE 1-2 bars                   measure at the dock"
say ""
say "Results written to: $RESULTS"
printf '\n%sResults written to %s%s\n\n' "$BOLD" "$RESULTS" "$D"

