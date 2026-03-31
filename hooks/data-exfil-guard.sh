#!/usr/bin/env bash
# data-exfil-guard.sh — Claude Code PreToolUse hook
# Detects data exfiltration patterns in outbound commands:
# 1. Markdown image tags encoding data in URLs
# 2. Base64/hex-encoded secrets piped to curl/wget
# 3. DNS exfiltration via dig/nslookup with encoded subdomains
# 4. File content piped to external services
# 5. Environment variable / secret dumping to network
#
# Applies to: Bash commands

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

BLOCKED=""
WARNINGS=""

# ============================================================
# 1. SENSITIVE DATA PIPED TO NETWORK
# ============================================================

# env/printenv/set piped to curl/wget/nc
if echo "$CMD" | grep -qE '(env|printenv|set)\s*\|.*\s*(curl|wget|nc|ncat)'; then
  BLOCKED="${BLOCKED}BLOCKED: Environment variables piped to network command — data exfiltration.\n"
fi

# cat of sensitive files piped to network
if echo "$CMD" | grep -qE 'cat\s+[^\|]*\.(env|pem|key|crt|p12|pfx|jks|credentials|secret|token)[^\|]*\|.*\s*(curl|wget|nc|base64)'; then
  BLOCKED="${BLOCKED}BLOCKED: Sensitive file piped to network/encoding command.\n"
fi

# Reading and posting secrets
if echo "$CMD" | grep -qE '(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_ACCESS|DATABASE_URL).*\|\s*(curl|wget|nc)'; then
  BLOCKED="${BLOCKED}BLOCKED: Secret/credential variable piped to network.\n"
fi

# ============================================================
# 2. DNS EXFILTRATION
# ============================================================

# Long subdomain queries (data encoded in DNS)
if echo "$CMD" | grep -qE '(dig|nslookup|host)\s+[a-zA-Z0-9]{20,}\.'; then
  WARNINGS="${WARNINGS}WARNING: DNS query with long subdomain — possible DNS exfiltration.\n"
fi

# Variable interpolation in DNS queries
if echo "$CMD" | grep -qE '(dig|nslookup|host)\s+.*\$[\({]'; then
  WARNINGS="${WARNINGS}WARNING: DNS query with variable interpolation — possible DNS exfiltration.\n"
fi

# ============================================================
# 3. BASE64 ENCODING + EXFIL
# ============================================================

# base64 encode piped to curl
if echo "$CMD" | grep -qE 'base64.*\|\s*(curl|wget|nc)'; then
  BLOCKED="${BLOCKED}BLOCKED: Base64-encoded data piped to network — exfiltration pattern.\n"
fi

# xxd/od piped to curl (hex encoding exfil)
if echo "$CMD" | grep -qE '(xxd|od\s).*\|\s*(curl|wget|nc)'; then
  BLOCKED="${BLOCKED}BLOCKED: Hex-encoded data piped to network.\n"
fi

# ============================================================
# 4. STEGANOGRAPHIC / COVERT CHANNELS
# ============================================================

# Embedding data in image EXIF then uploading
if echo "$CMD" | grep -qE '(exiftool|identify|convert).*&&.*(curl|wget|scp|rsync)'; then
  WARNINGS="${WARNINGS}WARNING: Image metadata manipulation followed by upload — possible stego exfil.\n"
fi

# tar/zip then upload in one command
if echo "$CMD" | grep -qE '(tar|zip|gzip).*\|\s*(curl|wget|nc)'; then
  WARNINGS="${WARNINGS}WARNING: Archive creation piped directly to network upload.\n"
fi

# ============================================================
# 5. CLIPBOARD / PASTEBOARD EXFIL (macOS)
# ============================================================

if echo "$CMD" | grep -qE 'pbpaste\s*\|\s*(curl|wget|nc)'; then
  BLOCKED="${BLOCKED}BLOCKED: Clipboard contents piped to network.\n"
fi

if echo "$CMD" | grep -qE 'pbcopy.*&&.*(curl|wget)'; then
  WARNINGS="${WARNINGS}WARNING: Clipboard manipulation followed by network request.\n"
fi

# ============================================================
# 6. BULK FILE EXFILTRATION
# ============================================================

# find + tar/zip + curl in one pipeline
if echo "$CMD" | grep -qE 'find\s.*\|\s*(tar|zip|cpio).*\|\s*(curl|wget|nc|scp)'; then
  BLOCKED="${BLOCKED}BLOCKED: Bulk file discovery, archival, and upload in one pipeline — exfiltration.\n"
fi

# rsync/scp to unknown external hosts with broad paths
if echo "$CMD" | grep -qE '(rsync|scp)\s+(-[a-zA-Z]+\s+)*(\/|~\/|\.\/).*@[^:]+:'; then
  WARNINGS="${WARNINGS}WARNING: Broad file transfer to external host. Verify the destination.\n"
fi

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
