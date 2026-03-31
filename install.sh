#!/usr/bin/env bash
# install.sh — Claude Code Self-Defense Hooks installer
# Copies hook scripts to ~/.claude/scripts/ and merges hook config into settings.json
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/goodmeta/claude-code-self-defense/main/install.sh | bash
#   # or
#   git clone https://github.com/goodmeta/claude-code-self-defense.git && cd claude-code-self-defense && ./install.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$HOME/.claude/scripts"
SETTINGS_FILE="$HOME/.claude/settings.json"

echo "Claude Code Self-Defense Hooks Installer"
echo "========================================="
echo ""

# Check dependencies
for dep in jq bash; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: '$dep' is required but not installed."
    exit 1
  fi
done

# Create scripts directory
mkdir -p "$SCRIPTS_DIR"

# Copy hooks
HOOKS=(
  "dangerous-command-guard.sh"
  "network-guard.sh"
  "data-exfil-guard.sh"
  "prompt-injection-scanner.sh"
  "pkg-security-check.sh"
)

echo "Installing hooks to $SCRIPTS_DIR..."
for hook in "${HOOKS[@]}"; do
  if [ -f "$SCRIPTS_DIR/$hook" ]; then
    echo "  Backing up existing $hook -> ${hook}.bak"
    cp "$SCRIPTS_DIR/$hook" "$SCRIPTS_DIR/${hook}.bak"
  fi
  cp "$REPO_DIR/hooks/$hook" "$SCRIPTS_DIR/$hook"
  chmod +x "$SCRIPTS_DIR/$hook"
  echo "  Installed $hook"
done

echo ""

# Merge settings
if [ ! -f "$SETTINGS_FILE" ]; then
  echo "Creating $SETTINGS_FILE..."
  # Replace $HOME with actual path in the example
  sed "s|\$HOME|$HOME|g" "$REPO_DIR/settings.example.json" > "$SETTINGS_FILE"
  echo "  Created settings.json with all hooks configured."
else
  echo "Existing settings.json found."
  echo ""
  echo "To add the hooks manually, merge the PreToolUse entries from"
  echo "settings.example.json into your existing settings.json."
  echo ""
  echo "The hooks expect scripts at: $SCRIPTS_DIR/"
  echo ""

  # Check if hooks are already configured
  if grep -q "dangerous-command-guard" "$SETTINGS_FILE" 2>/dev/null; then
    echo "  It looks like some hooks are already configured. Updating paths..."
    # Update paths in case they changed
    for hook in "${HOOKS[@]}"; do
      # Use | as sed delimiter since paths contain /
      if grep -q "$hook" "$SETTINGS_FILE"; then
        echo "  $hook already referenced in settings.json"
      fi
    done
  else
    echo "  Run the following to see what needs to be added:"
    echo "  cat $REPO_DIR/settings.example.json"
    echo ""
    echo "  Or to auto-merge (backs up existing settings first):"
    echo "  $0 --merge"

    if [ "${1:-}" = "--merge" ]; then
      echo ""
      echo "  Backing up settings.json -> settings.json.bak"
      cp "$SETTINGS_FILE" "${SETTINGS_FILE}.bak"

      # Read existing hooks and merge
      EXAMPLE=$(sed "s|\$HOME|$HOME|g" "$REPO_DIR/settings.example.json")
      MERGED=$(jq -s '
        .[0] as $existing |
        .[1] as $new |
        $existing * {
          hooks: {
            PreToolUse: (
              ($existing.hooks.PreToolUse // []) +
              ($new.hooks.PreToolUse // []) |
              unique_by(.matcher)
            )
          }
        }
      ' "$SETTINGS_FILE" <(echo "$EXAMPLE"))

      echo "$MERGED" > "$SETTINGS_FILE"
      echo "  Merged hooks into settings.json."
      echo "  Review: cat $SETTINGS_FILE"
    fi
  fi
fi

echo ""
echo "Installation complete."
echo ""
echo "Hooks installed:"
echo "  1. dangerous-command-guard.sh  — Blocks destructive commands, reverse shells, RCE"
echo "  2. network-guard.sh            — Blocks SSRF, internal IP access, metadata endpoints"
echo "  3. data-exfil-guard.sh         — Blocks data exfiltration patterns"
echo "  4. prompt-injection-scanner.sh — Scans files for prompt injection before reading"
echo "  5. pkg-security-check.sh       — Checks packages for malware, typosquats, vulns"
echo ""
echo "To verify: python3 $(dirname "$0")/tests/test-hooks.py"
echo ""
echo "Restart Claude Code for hooks to take effect."
