#!/usr/bin/env bash
# post-install-audit.sh — Claude Code PostToolUse hook
# Runs npm/pnpm audit after any install command modifies a lock file.
# Also checks for unpinned versions of critical packages.

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

# Only trigger on install/add commands
echo "$CMD" | grep -qE '(npm|pnpm|yarn|bun)\s+(install|i|add)\b' || exit 0

# Determine project dir from the command (look for cd or use cwd)
PROJECT_DIR=$(echo "$CMD" | grep -oE 'cd\s+[^ ;&]+' | head -1 | sed 's/cd\s*//' || true)
[ -z "$PROJECT_DIR" ] && PROJECT_DIR="$PWD"

# Expand ~ if present
PROJECT_DIR="${PROJECT_DIR/#\~/$HOME}"

# Find lock file
LOCKFILE=""
if [ -f "$PROJECT_DIR/package-lock.json" ]; then
  LOCKFILE="$PROJECT_DIR/package-lock.json"
elif [ -f "$PROJECT_DIR/pnpm-lock.yaml" ]; then
  LOCKFILE="$PROJECT_DIR/pnpm-lock.yaml"
elif [ -f "$PROJECT_DIR/yarn.lock" ]; then
  LOCKFILE="$PROJECT_DIR/yarn.lock"
fi

[ -z "$LOCKFILE" ] && exit 0

# ============================================================
# CRITICAL PACKAGES — warn if not pinned (exact version)
# These have been targets of supply chain attacks
# ============================================================
CRITICAL_PACKAGES="axios ua-parser-js coa rc colors faker event-stream node-ipc minimist"

WARNINGS=""

# Check package.json for unpinned critical deps
PKGJSON="$PROJECT_DIR/package.json"
if [ -f "$PKGJSON" ]; then
  for pkg in $CRITICAL_PACKAGES; do
    # Check if package is in deps and whether version is pinned (no ^ or ~ or *)
    version=$(python3 -c "
import json, sys
try:
    with open('$PKGJSON') as f:
        data = json.load(f)
    for section in ['dependencies', 'devDependencies']:
        v = data.get(section, {}).get('$pkg')
        if v:
            print(v)
            break
except:
    pass
" 2>/dev/null)
    if [ -n "$version" ]; then
      if echo "$version" | grep -qE '^[~^*>]|\.x'; then
        WARNINGS="${WARNINGS}UNPINNED: '$pkg' version '$version' in package.json. Critical packages should use exact versions (e.g., \"1.7.9\" not \"^1.7.9\") to prevent supply chain attacks.\n"
      fi
    fi
  done
fi

# ============================================================
# RUN AUDIT (quick, production deps only)
# ============================================================
AUDIT_RESULT=""
if echo "$CMD" | grep -qE '^(npm|bun)\s'; then
  AUDIT_RESULT=$(cd "$PROJECT_DIR" && npm audit --omit=dev --json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    vulns = data.get('vulnerabilities', {})
    high_crit = [(k, v['severity']) for k, v in vulns.items() if v.get('severity') in ('high', 'critical')]
    if high_crit:
        for name, sev in high_crit[:5]:
            print(f'AUDIT: {name} has {sev} severity vulnerability')
except:
    pass
" 2>/dev/null) || true
elif echo "$CMD" | grep -qE '^pnpm\s'; then
  AUDIT_RESULT=$(cd "$PROJECT_DIR" && pnpm audit --prod --json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    advisories = data.get('advisories', {})
    for aid, info in advisories.items():
        sev = info.get('severity', '')
        if sev in ('high', 'critical'):
            print(f'AUDIT: {info.get(\"module_name\",\"?\")} has {sev} severity vulnerability')
except:
    pass
" 2>/dev/null) || true
fi

if [ -n "$AUDIT_RESULT" ]; then
  WARNINGS="${WARNINGS}${AUDIT_RESULT}\n"
fi

# ============================================================
# OUTPUT
# ============================================================
if [ -n "$WARNINGS" ]; then
  context=$(echo -e "$WARNINGS" | sed 's/"/\\"/g' | tr '\n' ' ')
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PostToolUse\",\"additionalContext\":\"Post-install security check: ${context}\"}}"
  exit 0
fi

exit 0
