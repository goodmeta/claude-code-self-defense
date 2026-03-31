#!/usr/bin/env bash
# dangerous-command-guard.sh — Claude Code PreToolUse hook
# Blocks dangerous shell patterns that could indicate:
# - Destructive operations (rm -rf /, format disk)
# - Reverse shells / backdoors
# - Piped remote code execution (curl|sh)
# - Credential theft / keylogging
# - Sandbox escape attempts
# - Cryptocurrency miners
# - Kernel/system-level tampering

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

# Strip heredoc content and quoted strings from git commit messages.
# Commit message text is not executable — scanning it causes false positives
# when messages describe attack patterns (e.g., "catches base64 -d | bash").
CMD_SAFE="$CMD"
if echo "$CMD_SAFE" | grep -qE '(git\s+commit|cat\s+<<)'; then
  # Remove heredoc blocks: <<'EOF' ... EOF and <<EOF ... EOF
  CMD_SAFE=$(echo "$CMD_SAFE" | sed '/<<.*EOF/,/^[[:space:]]*EOF/d')
  # Remove -m "..." or -m '...' arguments
  CMD_SAFE=$(echo "$CMD_SAFE" | sed -E "s/-m[[:space:]]+\"[^\"]*\"//g; s/-m[[:space:]]+'[^']*'//g")
fi

# Use sanitized command for all pattern matching
CMD="$CMD_SAFE"

BLOCKED=""
WARNINGS=""

# Normalize: collapse whitespace, lowercase for matching
CMD_LOWER=$(echo "$CMD" | tr '[:upper:]' '[:lower:]' | tr -s ' ')

# ============================================================
# 1. DESTRUCTIVE FILESYSTEM OPERATIONS
# ============================================================

# rm -rf on root or critical paths (but not /tmp/somefile.txt)
if echo "$CMD" | grep -qE 'rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*(\/$|\/\*|\/etc|\/usr|\/var|\/System|\/Library|\/Applications)(\s|$)'; then
  BLOCKED="${BLOCKED}BLOCKED: Destructive rm targeting critical system path.\n"
elif echo "$CMD" | grep -qE 'rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*~\/\s*$'; then
  BLOCKED="${BLOCKED}BLOCKED: Destructive rm targeting home directory.\n"
fi

# rm -rf with wildcard at dangerous scope
if echo "$CMD" | grep -qE 'rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+\.\.\/' ; then
  BLOCKED="${BLOCKED}BLOCKED: rm -rf traversing parent directories.\n"
fi

# mkfs / format disk
if echo "$CMD_LOWER" | grep -qE '(mkfs|format)[.\s]'; then
  BLOCKED="${BLOCKED}BLOCKED: Disk format command detected.\n"
fi

# dd writing to disk devices
if echo "$CMD" | grep -qE 'dd\s.*of=\/dev\/(sd|hd|nvme|disk|rdisk)'; then
  BLOCKED="${BLOCKED}BLOCKED: dd writing directly to disk device.\n"
fi

# ============================================================
# 2. REVERSE SHELLS / BACKDOORS
# ============================================================

# Common reverse shell patterns
if echo "$CMD" | grep -qE '(bash|sh|zsh|python|perl|ruby|nc|ncat)\s.*-[ie]\s.*/dev/tcp'; then
  BLOCKED="${BLOCKED}BLOCKED: Reverse shell pattern detected (/dev/tcp).\n"
fi

if echo "$CMD" | grep -qE 'mkfifo.*/tmp.*nc\s'; then
  BLOCKED="${BLOCKED}BLOCKED: Named pipe reverse shell pattern.\n"
fi

if echo "$CMD" | grep -qE '(nc|ncat|netcat)\s.*-[elp]'; then
  BLOCKED="${BLOCKED}BLOCKED: Netcat listener/exec — possible reverse shell.\n"
fi

# Python/perl/ruby reverse shell one-liners
if echo "$CMD_LOWER" | grep -qE "(python|perl|ruby).*socket.*connect.*exec"; then
  BLOCKED="${BLOCKED}BLOCKED: Scripted reverse shell pattern.\n"
fi

# socat reverse shell
if echo "$CMD_LOWER" | grep -qE 'socat.*exec.*tcp'; then
  BLOCKED="${BLOCKED}BLOCKED: socat reverse shell pattern.\n"
fi

# ============================================================
# 3. REMOTE CODE EXECUTION (pipe to shell)
# ============================================================

# curl/wget piped to shell
if echo "$CMD" | grep -qE '(curl|wget)\s.*\|\s*(bash|sh|zsh|python|perl|ruby|node)'; then
  BLOCKED="${BLOCKED}BLOCKED: Remote code piped to shell interpreter. Download first, inspect, then run.\n"
fi

# curl/wget with -o piped or executed
if echo "$CMD" | grep -qE '(curl|wget)\s.*&&\s*(bash|sh|chmod\s+\+x)'; then
  WARNINGS="${WARNINGS}WARNING: Download-and-execute pattern. Verify the source URL is trusted.\n"
fi

# eval with command substitution from network
if echo "$CMD" | grep -qE 'eval\s.*\$\((curl|wget)'; then
  BLOCKED="${BLOCKED}BLOCKED: eval of remote content.\n"
fi

# Decode-and-execute: base64/openssl decoded output piped to shell
if echo "$CMD" | grep -qE '(base64\s+(-d|--decode)|openssl\s.*(enc|base64).*-d|-d.*base64)\s*.*\|\s*(bash|sh|zsh|python|perl|ruby|node)'; then
  BLOCKED="${BLOCKED}BLOCKED: Decoded payload piped to shell interpreter — obfuscated code execution.\n"
fi

# Python exec(base64.b64decode(...)) and similar inline decode-exec
if echo "$CMD" | grep -qE 'python[23]?\s+-c\s.*\b(exec|eval)\s*\(.*\b(b64decode|decode|decompress)'; then
  BLOCKED="${BLOCKED}BLOCKED: Python inline decode-and-execute — obfuscated code execution.\n"
fi

# Variable capture + eval: x=$(base64 -d ...); eval $x
if echo "$CMD" | grep -qE '(base64\s+(-d|--decode)|openssl\s.*-d).*;\s*(eval|source|\.)\s'; then
  BLOCKED="${BLOCKED}BLOCKED: Decoded content captured and evaluated — obfuscated code execution.\n"
fi

# xxd/printf decode piped to shell
if echo "$CMD" | grep -qE '(xxd\s+-r|printf\s.*\\x)\s*.*\|\s*(bash|sh|zsh)'; then
  BLOCKED="${BLOCKED}BLOCKED: Hex-decoded payload piped to shell.\n"
fi

# ============================================================
# 4. CREDENTIAL / SECRET THEFT
# ============================================================

# Reading SSH keys, AWS creds, etc. and sending externally
if echo "$CMD" | grep -qE 'cat\s.*(\.ssh\/|\.aws\/|\.gnupg\/|\.env|credentials|\.netrc).*\|\s*(curl|nc|base64)'; then
  BLOCKED="${BLOCKED}BLOCKED: Credential file read piped to exfil command.\n"
fi

# Keylogger patterns
if echo "$CMD_LOWER" | grep -qE '(xinput|logkeys|script.*typescript|strace.*read)'; then
  WARNINGS="${WARNINGS}WARNING: Possible keylogger/input capture command.\n"
fi

# Dumping keychain
if echo "$CMD_LOWER" | grep -qE 'security\s+(find|dump|export).*keychain'; then
  BLOCKED="${BLOCKED}BLOCKED: macOS Keychain dump attempt.\n"
fi

# ============================================================
# 5. SANDBOX ESCAPE / PRIVILEGE ESCALATION
# ============================================================

# Modifying sudoers
if echo "$CMD" | grep -qE '(visudo|\/etc\/sudoers)'; then
  BLOCKED="${BLOCKED}BLOCKED: sudoers modification attempt.\n"
fi

# setuid bit manipulation
if echo "$CMD" | grep -qE 'chmod\s+[0-7]*[4-7][0-7]{2}\s|chmod\s+[ug]\+s'; then
  BLOCKED="${BLOCKED}BLOCKED: setuid/setgid bit manipulation.\n"
fi

# Loading kernel modules
if echo "$CMD_LOWER" | grep -qE '(insmod|modprobe|rmmod)\s'; then
  BLOCKED="${BLOCKED}BLOCKED: Kernel module manipulation.\n"
fi

# Docker escape patterns
if echo "$CMD" | grep -qE 'docker.*--privileged|docker.*-v\s*/:/'; then
  WARNINGS="${WARNINGS}WARNING: Privileged docker or root filesystem mount.\n"
fi

# ============================================================
# 6. CRYPTO MINERS / RESOURCE ABUSE
# ============================================================

if echo "$CMD_LOWER" | grep -qE '(xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|stratum\+tcp|cryptonight)'; then
  BLOCKED="${BLOCKED}BLOCKED: Cryptocurrency miner detected.\n"
fi

# ============================================================
# 7. SYSTEM INTEGRITY
# ============================================================

# Disabling firewall
if echo "$CMD_LOWER" | grep -qE '(ufw\s+disable|iptables\s+-F|pfctl\s+-d)'; then
  BLOCKED="${BLOCKED}BLOCKED: Firewall disable command.\n"
fi

# Disabling macOS security
if echo "$CMD_LOWER" | grep -qE '(csrutil\s+disable|spctl\s+--master-disable)'; then
  BLOCKED="${BLOCKED}BLOCKED: macOS security disable attempt.\n"
fi

# Modifying /etc/hosts, /etc/passwd
if echo "$CMD" | grep -qE '(>>?|tee)\s*\/etc\/(hosts|passwd|shadow|resolv.conf)'; then
  BLOCKED="${BLOCKED}BLOCKED: System file modification attempt.\n"
fi

# crontab injection from remote
if echo "$CMD" | grep -qE '(curl|wget).*crontab|crontab.*\|\s*(curl|wget)'; then
  BLOCKED="${BLOCKED}BLOCKED: Remote crontab injection.\n"
fi

# ============================================================
# 8. SPAWNED SCRIPT PRE-SCAN
# ============================================================

# When running a script file, check if it contains dangerous imports/calls
# This catches: python3 evil.py, node evil.js, ruby evil.rb, bash evil.sh
SCRIPT_FILE=""
if echo "$CMD" | grep -qE '^(python[23]?|node|ruby|bash|sh|zsh|perl) +[^\-]'; then
  # Extract the script path: skip the interpreter name, take the first non-flag argument
  SCRIPT_FILE=$(echo "$CMD" | awk '{for(i=2;i<=NF;i++){if($i !~ /^-/){print $i; exit}}}')
fi

if [ -n "$SCRIPT_FILE" ] && [ -f "$SCRIPT_FILE" ]; then
  SCRIPT_CONTENT=$(head -c 5000 "$SCRIPT_FILE" 2>/dev/null || true)
  if [ -n "$SCRIPT_CONTENT" ]; then
    SCRIPT_LOWER=$(echo "$SCRIPT_CONTENT" | tr '[:upper:]' '[:lower:]')

    # Python: socket reverse shells, os.system, subprocess with shell
    # Check independently since import and connect are typically on different lines
    if echo "$SCRIPT_LOWER" | grep -qE '(import socket|socket\.socket)'; then
      if echo "$SCRIPT_LOWER" | grep -qE '(connect|dup2|exec|popen|system|subprocess)'; then
        BLOCKED="${BLOCKED}BLOCKED: Script $SCRIPT_FILE contains socket+exec pattern — likely reverse shell.\n"
      fi
    fi

    # Any script: downloads + executes
    if echo "$SCRIPT_LOWER" | grep -qE '(urllib|requests|http\.client|wget|curl)' && echo "$SCRIPT_LOWER" | grep -qE '(exec|eval|system|popen|subprocess|spawn)'; then
      WARNINGS="${WARNINGS}WARNING: Script $SCRIPT_FILE downloads content and executes code. Review before running.\n"
    fi

    # Bash scripts: check for the same patterns we check in commands
    if echo "$SCRIPT_CONTENT" | grep -qE '(\/dev\/tcp|nc\s.*-e|mkfifo.*nc|curl.*\|\s*bash)'; then
      BLOCKED="${BLOCKED}BLOCKED: Script $SCRIPT_FILE contains reverse shell / RCE patterns.\n"
    fi
  fi
fi

# ============================================================
# 9. HISTORY / LOG TAMPERING
# ============================================================

if echo "$CMD" | grep -qE '(history\s+-c|>.*\.bash_history|>.*\.zsh_history|unset\s+HISTFILE|HISTSIZE=0)'; then
  WARNINGS="${WARNINGS}WARNING: Shell history clearing/tampering.\n"
fi

if echo "$CMD" | grep -qE '>\s*\/var\/log\/'; then
  WARNINGS="${WARNINGS}WARNING: Log file truncation.\n"
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
