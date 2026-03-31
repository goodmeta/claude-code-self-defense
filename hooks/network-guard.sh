#!/usr/bin/env bash
# network-guard.sh — Claude Code PreToolUse hook
# Blocks SSRF patterns and suspicious network access:
# 1. Internal/private IP ranges (RFC 1918, link-local, loopback)
# 2. Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
# 3. DNS rebinding via suspicious hostnames
# 4. Suspicious protocols (gopher, file, dict, ftp)
# 5. Encoded/obfuscated URLs designed to bypass filters
#
# Applies to: Bash (curl/wget/fetch commands), WebFetch

set -euo pipefail

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')
CMD=""
URLS=""

# Extract URLs based on tool type
case "$TOOL" in
  Bash)
    CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    [ -z "$CMD" ] && exit 0
    # Strip heredoc/quoted content from git commits to avoid false positives
    if echo "$CMD" | grep -qE '(git\s+commit|cat\s+<<)'; then
      CMD=$(echo "$CMD" | sed '/<<.*EOF/,/^[[:space:]]*EOF/d')
      CMD=$(echo "$CMD" | sed -E "s/-m[[:space:]]+\"[^\"]*\"//g; s/-m[[:space:]]+'[^']*'//g")
    fi
    # Only check commands that make network requests
    echo "$CMD" | grep -qEi '(curl|wget|fetch|http|nc |ncat |ssh |scp |rsync |ftp )' || exit 0
    # Extract URLs from the command
    URLS=$(echo "$CMD" | grep -oE '(https?|ftp|gopher|file|dict|ldap|tftp)://[^ "'"'"'>]+' || true)
    # Also extract bare IPs with ports (e.g., curl 10.0.0.1:8080)
    URLS="$URLS $(echo "$CMD" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?' || true)"
    ;;
  WebFetch)
    URLS=$(echo "$INPUT" | jq -r '.tool_input.url // empty')
    ;;
  *)
    exit 0
    ;;
esac

[ -z "$URLS" ] && exit 0

BLOCKED=""
WARNINGS=""

check_url() {
  local url="$1"
  local host=""

  # Check suspicious protocols BEFORE extracting host (file:// has no host)
  if echo "$url" | grep -qEi '^(gopher|dict|file|ldap|tftp)://'; then
    BLOCKED="${BLOCKED}BLOCKED: Suspicious protocol in URL ($url) — common SSRF vector.\n"
    return 0
  fi

  # Extract hostname/IP from URL
  host=$(echo "$url" | sed -E 's|^[a-zA-Z]+://||' | sed -E 's|[/:?#].*||' | sed 's/@.*@//' | sed 's/.*@//')

  [ -z "$host" ] && return 0

  # ----------------------------------------------------------
  # PRIVATE / INTERNAL IP RANGES
  # ----------------------------------------------------------

  # 127.x.x.x (loopback)
  if echo "$host" | grep -qE '^127\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Loopback address $host — possible SSRF.\n"
    return 0
  fi

  # localhost variants
  if echo "$host" | grep -qEi '^(localhost|0\.0\.0\.0|0x7f|2130706433|\[::1\]|::1)$'; then
    BLOCKED="${BLOCKED}BLOCKED: Localhost access ($host) — possible SSRF.\n"
    return 0
  fi

  # 10.x.x.x (Class A private)
  if echo "$host" | grep -qE '^10\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Private IP range 10.x ($host) — possible SSRF.\n"
    return 0
  fi

  # 172.16-31.x.x (Class B private)
  if echo "$host" | grep -qE '^172\.(1[6-9]|2[0-9]|3[01])\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Private IP range 172.16-31.x ($host) — possible SSRF.\n"
    return 0
  fi

  # 192.168.x.x (Class C private)
  if echo "$host" | grep -qE '^192\.168\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Private IP range 192.168.x ($host) — possible SSRF.\n"
    return 0
  fi

  # 169.254.x.x (link-local / cloud metadata)
  if echo "$host" | grep -qE '^169\.254\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Link-local/metadata address $host — SSRF to cloud metadata.\n"
    return 0
  fi

  # fd00::/8 (IPv6 private)
  if echo "$host" | grep -qEi '^fd[0-9a-f]{2}:'; then
    BLOCKED="${BLOCKED}BLOCKED: IPv6 private address ($host).\n"
    return 0
  fi

  # ----------------------------------------------------------
  # CLOUD METADATA ENDPOINTS
  # ----------------------------------------------------------

  # AWS metadata
  if echo "$url" | grep -qE '169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|metadata\.digitalocean\.com'; then
    BLOCKED="${BLOCKED}BLOCKED: Cloud metadata endpoint detected — SSRF attack vector.\n"
    return 0
  fi

  # AWS IMDSv1/v2 paths
  if echo "$url" | grep -qE '/latest/meta-data|/latest/user-data|/latest/api/token|/computeMetadata/v1'; then
    BLOCKED="${BLOCKED}BLOCKED: Cloud metadata API path detected.\n"
    return 0
  fi

  # ----------------------------------------------------------
  # ENCODED / OBFUSCATED URLS
  # ----------------------------------------------------------

  # Decimal IP encoding (e.g., http://2130706433 = 127.0.0.1)
  if echo "$host" | grep -qE '^[0-9]{8,10}$'; then
    BLOCKED="${BLOCKED}BLOCKED: Decimal-encoded IP ($host) — SSRF obfuscation.\n"
    return 0
  fi

  # Hex-encoded IP (e.g., 0x7f000001)
  if echo "$host" | grep -qEi '^0x[0-9a-f]+$'; then
    BLOCKED="${BLOCKED}BLOCKED: Hex-encoded IP ($host) — SSRF obfuscation.\n"
    return 0
  fi

  # Octal IP encoding (e.g., 0177.0.0.1)
  if echo "$host" | grep -qE '^0[0-7]+\.'; then
    BLOCKED="${BLOCKED}BLOCKED: Octal-encoded IP ($host) — SSRF obfuscation.\n"
    return 0
  fi

  # URL with @ for redirect (e.g., http://safe.com@evil.com)
  if echo "$url" | grep -qE '://[^/]*@[^/]*@'; then
    BLOCKED="${BLOCKED}BLOCKED: Double-@ URL obfuscation — redirect attack.\n"
    return 0
  fi

  # ----------------------------------------------------------
  # DNS REBINDING CHECK — resolve hostname, check for private IPs
  # ----------------------------------------------------------

  # Only resolve if it looks like a hostname (not an IP)
  if echo "$host" | grep -qE '^[a-zA-Z]'; then
    RESOLVED_IP=""
    if command -v dig >/dev/null 2>&1; then
      RESOLVED_IP=$(dig +short +time=1 +tries=1 "$host" 2>/dev/null | grep -E '^[0-9]+\.' | head -1 || true)
    elif command -v getent >/dev/null 2>&1; then
      RESOLVED_IP=$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | head -1)
    elif command -v python3 >/dev/null 2>&1; then
      RESOLVED_IP=$(python3 -c "import socket; print(socket.gethostbyname('$host'))" 2>/dev/null)
    fi

    if [ -n "$RESOLVED_IP" ]; then
      if echo "$RESOLVED_IP" | grep -qE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0)'; then
        BLOCKED="${BLOCKED}BLOCKED: DNS rebinding — $host resolves to private IP $RESOLVED_IP.\n"
        return 0
      fi
    fi
  fi

  # ----------------------------------------------------------
  # SUSPICIOUS OUTBOUND PATTERNS
  # ----------------------------------------------------------

  # DNS exfil patterns (long subdomains with encoded data)
  if echo "$host" | grep -qE '^[a-zA-Z0-9]{30,}\.'; then
    WARNINGS="${WARNINGS}WARNING: Unusually long subdomain ($host) — possible DNS exfiltration.\n"
  fi

  # Known webhook/exfil services used in attacks
  if echo "$host" | grep -qEi '(burpcollaborator|interact\.sh|requestbin|webhook\.site|hookbin|pipedream\.net|ngrok\.io|serveo\.net|localtunnel\.me)'; then
    WARNINGS="${WARNINGS}WARNING: Request to known pentesting/webhook service ($host). Verify this is intentional.\n"
  fi
}

# Check each URL found
for url in $URLS; do
  check_url "$url"
done

# ============================================================
# OUTPUT
# ============================================================
if [ -n "$BLOCKED" ]; then
  reason=$(printf '%b' "${BLOCKED}${WARNINGS}" | jq -Rs .)
  cat <<ENDJSON
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": $reason
  }
}
ENDJSON
  exit 0
fi

if [ -n "$WARNINGS" ]; then
  context=$(printf '%b' "$WARNINGS" | jq -Rs .)
  cat <<ENDJSON
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "additionalContext": $context
  }
}
ENDJSON
  exit 0
fi

exit 0
