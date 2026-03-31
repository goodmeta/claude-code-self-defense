#!/usr/bin/env bash
# pkg-security-check.sh — Claude Code PreToolUse hook
# Intercepts package install commands and checks for security issues:
# 1. Known malicious packages (curated blocklist, all ecosystems)
# 2. Node.js built-in shims (unnecessary npm packages)
# 3. Version-specific compromises (e.g. axios@1.14.1)
# 4. Typosquat detection via Levenshtein distance (python3)
# 5. OSV.dev real-time vulnerability check (best-effort)

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$CMD" ] && exit 0

# ============================================================
# DETECT PACKAGE MANAGER + EXTRACT PACKAGES
# ============================================================
PKG_MANAGER=""
PACKAGES=""

if echo "$CMD" | grep -qE '^(npm|pnpm|bun)\s+(install|i|add)\b'; then
  PKG_MANAGER="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^(npm|pnpm|bun)\s+(install|i|add)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^yarn\s+add\b'; then
  PKG_MANAGER="npm"
  PACKAGES=$(echo "$CMD" | sed -E 's/^yarn\s+add\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^(pip3?|pipx|uv(\s+pip)?)\s+(install|add)\b'; then
  PKG_MANAGER="pip"
  PACKAGES=$(echo "$CMD" | sed -E 's/^(pip3?|pipx|uv(\s+pip)?)\s+(install|add)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^uv\s+add\b'; then
  PKG_MANAGER="pip"
  PACKAGES=$(echo "$CMD" | sed -E 's/^uv\s+add\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^cargo\s+(add|install)\b'; then
  PKG_MANAGER="cargo"
  PACKAGES=$(echo "$CMD" | sed -E 's/^cargo\s+(add|install)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^gem\s+install\b'; then
  PKG_MANAGER="gem"
  PACKAGES=$(echo "$CMD" | sed -E 's/^gem\s+install\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^go\s+(get|install)\b'; then
  PKG_MANAGER="go"
  PACKAGES=$(echo "$CMD" | sed -E 's/^go\s+(get|install)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^composer\s+(require|install)\b'; then
  PKG_MANAGER="composer"
  PACKAGES=$(echo "$CMD" | sed -E 's/^composer\s+(require|install)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^brew\s+install\b'; then
  PKG_MANAGER="brew"
  PACKAGES=$(echo "$CMD" | sed -E 's/^brew\s+install\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^(apt-get|apt)\s+install\b'; then
  PKG_MANAGER="apt"
  PACKAGES=$(echo "$CMD" | sed -E 's/^(apt-get|apt)\s+install\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^apk\s+add\b'; then
  PKG_MANAGER="apk"
  PACKAGES=$(echo "$CMD" | sed -E 's/^apk\s+add\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
elif echo "$CMD" | grep -qE '^(dotnet\s+add\s+package|nuget\s+install)\b'; then
  PKG_MANAGER="dotnet"
  PACKAGES=$(echo "$CMD" | sed -E 's/^(dotnet\s+add\s+package|nuget\s+install)\s+//' | tr ' ' '\n' | grep -v '^-' | grep -v '^$' || true)
else
  exit 0
fi

[ -z "$PACKAGES" ] && exit 0

# ============================================================
# BLOCKLISTS
# ============================================================

# --- Known malicious: npm ---
MALICIOUS_NPM="event-stream flatmap-stream plain-crypto-js crossenv cross-env.js babelcli babel-cli.js gruntcli grunt-cli.js mongose ffmpegs http-proxy.js proxy.js shadowsock smb nodesass nodefabric node-opencv nodecaffe nodemailer-js nodemailer.js nodemaiIer discord.js-user discordi.js eslint-scope-util load-from-cwd-or-npm lolip0p-json peacenotwar node-ipc-malicious colors.js faker.js electorn electronjs loadyaml lodashs lodahs loadash aabquerys acloud-dl"

# --- Known malicious: pip ---
MALICIOUS_PIP="python-dateutil2 python3-dateutil jeIlyfish python-sqlite colourslib requestslib beautifulsoup requesocks pyqt-application nmap-python smtplib-python urllib-python python-binance2 discordpy openai-python pip-install pipinstall reqeusts reequests djanga djanggo flasck falsk numpyy numppy panddas pandaas sckit-learn tenserflow tesnorflow pytorche keraas matplotlb"

# --- Known malicious: cargo ---
MALICIOUS_CARGO="rustdecimal rust_decimal-macros-fake"

# --- Known malicious: gem ---
MALICIOUS_GEM="atlas-client rspec-mock_server rest-client-wrapper strong_password_generator logkos ruby-hierarchical"

# --- Known malicious: composer ---
MALICIOUS_COMPOSER="phpunit-backdoor phpass-fake"

# --- Node.js built-in shims ---
BUILTIN_SHIMS="crypto readline path fs os util stream http https net dns tls child_process cluster events buffer string_decoder querystring url assert zlib punycode timers console"

# --- Version-specific compromises (pkg@version) ---
COMPROMISED_VERSIONS="axios@1.14.1 axios@0.30.4 ua-parser-js@0.7.29 ua-parser-js@0.8.0 ua-parser-js@1.0.0 coa@2.0.3 coa@2.0.4 coa@2.1.1 coa@2.1.3 coa@3.0.1 coa@3.1.3 rc@1.2.9 rc@1.3.9 rc@2.3.9 colors@1.4.1 colors@1.4.2 faker@6.6.6 event-stream@3.3.6 node-ipc@10.1.1 node-ipc@10.1.2 node-ipc@10.1.3"

# --- Deprecated with known vulns ---
declare -A DEPRECATED_NPM=(
  ["request"]="deprecated since 2020, use got/axios/node-fetch"
  ["nomnom"]="unmaintained, use commander/yargs"
  ["node-uuid"]="renamed to uuid"
  ["merge"]="prototype pollution CVE-2020-28499"
  ["minimist"]="prototype pollution CVE-2021-44906 (use >=1.2.6)"
)

# ============================================================
# TYPOSQUAT DETECTION (python3, best-effort)
# ============================================================
typosquat_check() {
  local pkg="$1"
  local ecosystem="$2"
  command -v python3 >/dev/null 2>&1 || return 0

  python3 -c "
import sys

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]

pkg = '$pkg'
ecosystem = '$ecosystem'

popular = {
    'npm': ['react','express','lodash','axios','chalk','commander','dotenv','webpack',
            'babel','jest','mocha','typescript','vite','next','tailwindcss','prisma',
            'zod','eslint','prettier','nodemon','fastify','mongoose','sequelize','knex',
            'redis','pg','mysql2','cors','helmet','jsonwebtoken','bcrypt','uuid','dayjs',
            'moment','underscore','async','debug','minimist','yargs','inquirer','ora',
            'glob','rimraf','mkdirp','semver','luxon','socket.io','webpack-cli',
            'ts-node','tsx','vitest','esbuild','rollup','postcss','autoprefixer',
            'nodemailer','passport','express-session','body-parser','multer','sharp',
            'cheerio','puppeteer','playwright','electron','three','d3','chart.js'],
    'pip': ['requests','numpy','pandas','flask','django','tensorflow','pytorch',
            'scikit-learn','matplotlib','pillow','beautifulsoup4','selenium','scrapy',
            'celery','fastapi','sqlalchemy','pydantic','httpx','aiohttp','boto3',
            'cryptography','paramiko','fabric','ansible','pytest','black','mypy',
            'ruff','uvicorn','gunicorn','openai','langchain','transformers','torch',
            'keras','scipy','seaborn','plotly','streamlit','gradio','click','typer',
            'rich','httptools','pyyaml','toml','Pillow','opencv-python'],
    'cargo': ['serde','tokio','clap','reqwest','rand','anyhow','thiserror','tracing',
              'hyper','actix-web','axum','diesel','sqlx','warp','tower','tonic',
              'prost','bytes','futures','async-trait','chrono','regex','log','env_logger',
              'serde_json','toml','config','rustls','ring'],
    'gem': ['rails','sinatra','puma','sidekiq','devise','nokogiri','rspec','rubocop',
            'bundler','rake','activerecord','actionpack','activesupport','faraday',
            'httparty','rest-client','pg','redis','resque','capistrano','thor'],
    'go': [],
    'composer': ['laravel','symfony','guzzlehttp','monolog','phpunit','doctrine',
                 'twig','carbon','predis','flysystem','intervention'],
}

pkgs = popular.get(ecosystem, [])
if not pkgs or pkg in pkgs:
    sys.exit(0)

# Only check packages with length > 3 to avoid false positives
if len(pkg) <= 3:
    sys.exit(0)

matches = []
for p in pkgs:
    d = levenshtein(pkg, p)
    if d == 1:
        matches.append((p, d))
    elif d == 2 and len(pkg) > 5:
        matches.append((p, d))

if matches:
    closest = matches[0]
    print(f'TYPOSQUAT WARNING: \"{pkg}\" is {closest[1]} edit(s) from popular package \"{closest[0]}\". Possible typosquat.')
    sys.exit(1)

sys.exit(0)
" 2>/dev/null
}

# ============================================================
# OSV.dev REAL-TIME CHECK (best-effort, non-blocking)
# ============================================================
osv_check() {
  local pkg="$1"
  local version="$2"
  local ecosystem="$3"

  [ -z "$version" ] && return 0
  command -v curl >/dev/null 2>&1 || return 0

  local osv_ecosystem=""
  case "$ecosystem" in
    npm) osv_ecosystem="npm" ;;
    pip) osv_ecosystem="PyPI" ;;
    cargo) osv_ecosystem="crates.io" ;;
    gem) osv_ecosystem="RubyGems" ;;
    go) osv_ecosystem="Go" ;;
    composer) osv_ecosystem="Packagist" ;;
    *) return 0 ;;
  esac

  local response
  response=$(curl -sf --max-time 5 -X POST "https://api.osv.dev/v1/query" \
    -H "Content-Type: application/json" \
    -d "{\"version\":\"$version\",\"package\":{\"name\":\"$pkg\",\"ecosystem\":\"$osv_ecosystem\"}}" 2>/dev/null) || return 0

  local vuln_count
  vuln_count=$(echo "$response" | jq -r '.vulns | length // 0' 2>/dev/null) || return 0

  if [ "$vuln_count" -gt 0 ]; then
    local vuln_ids
    vuln_ids=$(echo "$response" | jq -r '[.vulns[].id] | join(", ")' 2>/dev/null)
    echo "OSV: $pkg@$version has $vuln_count known vulnerability(ies): $vuln_ids"
    return 1
  fi
  return 0
}

# ============================================================
# CHECK EACH PACKAGE
# ============================================================
BLOCKED=""
WARNINGS=""

for pkg in $PACKAGES; do
  # Parse name and version
  pkg_name=$(echo "$pkg" | sed 's/[@=><^~].*//')
  pkg_version=$(echo "$pkg" | grep -oE '@[0-9][0-9.]*' | sed 's/^@//' || true)

  # --- Version-specific compromises ---
  if [ -n "$pkg_version" ]; then
    for cv in $COMPROMISED_VERSIONS; do
      if [ "${pkg_name}@${pkg_version}" = "$cv" ]; then
        BLOCKED="${BLOCKED}BLOCKED: ${pkg_name}@${pkg_version} is a known compromised version. Do NOT install.\n"
      fi
    done
  fi

  case "$PKG_MANAGER" in
    npm)
      # Malicious check
      for mal in $MALICIOUS_NPM; do
        [ "$pkg_name" = "$mal" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a known malicious npm package.\n"
      done
      # Built-in shim check
      for shim in $BUILTIN_SHIMS; do
        [ "$pkg_name" = "$shim" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a Node.js built-in. Use require('${pkg_name}') directly, the npm package is an attack vector.\n"
      done
      # Deprecated check
      if [[ -v "DEPRECATED_NPM[$pkg_name]" ]]; then
        WARNINGS="${WARNINGS}WARNING: '${pkg_name}' — ${DEPRECATED_NPM[$pkg_name]}\n"
      fi
      ;;
    pip)
      for mal in $MALICIOUS_PIP; do
        [ "$pkg_name" = "$mal" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a known malicious Python package.\n"
      done
      ;;
    cargo)
      for mal in $MALICIOUS_CARGO; do
        [ "$pkg_name" = "$mal" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a known malicious Rust crate.\n"
      done
      ;;
    gem)
      for mal in $MALICIOUS_GEM; do
        [ "$pkg_name" = "$mal" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a known malicious Ruby gem.\n"
      done
      ;;
    composer)
      for mal in $MALICIOUS_COMPOSER; do
        [ "$pkg_name" = "$mal" ] && BLOCKED="${BLOCKED}BLOCKED: '${pkg_name}' is a known malicious Composer package.\n"
      done
      ;;
  esac

  # --- Typosquat detection ---
  typo_result=$(typosquat_check "$pkg_name" "$PKG_MANAGER" 2>/dev/null) || true
  if [ -n "$typo_result" ]; then
    WARNINGS="${WARNINGS}${typo_result}\n"
  fi

  # --- OSV.dev real-time check (only if version specified) ---
  if [ -n "$pkg_version" ]; then
    osv_result=$(osv_check "$pkg_name" "$pkg_version" "$PKG_MANAGER" 2>/dev/null) || true
    if [ -n "$osv_result" ]; then
      WARNINGS="${WARNINGS}${osv_result}\n"
    fi
  fi
done

# ============================================================
# OUTPUT
# ============================================================
if [ -n "$BLOCKED" ]; then
  reason=$(echo -e "${BLOCKED}${WARNINGS}" | sed 's/"/\\"/g' | tr '\n' ' ')
  echo "{\"decision\":\"block\",\"reason\":\"${reason}\"}"
  exit 0
fi

if [ -n "$WARNINGS" ]; then
  context=$(echo -e "$WARNINGS" | sed 's/"/\\"/g' | tr '\n' ' ')
  echo "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"Package security warnings: ${context}\"}}"
  exit 0
fi

exit 0
