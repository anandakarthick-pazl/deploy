#!/usr/bin/env bash
# Boot/recovery helper for the packworx testing stack.
#
# The system is already wired to auto-start at boot via pm2-root.service and
# nginx/packwork-deploy.service systemd units, so on a normal reboot you do
# not need to run this. Use it when:
#   - a service is showing 'errored' or 'stopped' in `pm2 list`
#   - you've manually edited ecosystem.config.js and want a clean restart
#   - something looks off and you want to re-verify the full stack
#
# Usage:  sudo /srv/code/Source_Code/packworx/deploy/start-all.sh

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BE_TESTING_DIR="/srv/code/Source_Code/packworx/packworx_testing/docker-packworx-be"
BE_DEV_DIR="/srv/code/Source_Code/packworx/packworx_dev/docker-packworx-be"
PORTS_TESTING=(8001 8002 8003 8004 8005 8006 8007 8008 8009 8010 8011 8012 8013 8014 8015)
PORTS_DEV=(7001 7002 7003 7004 7005 7006 7007 7008 7009 7010 7011 7012 7013 7014 7015)
PORTS=("${PORTS_TESTING[@]}" "${PORTS_DEV[@]}")
DOMAINS=(api-testing-packworx.pazl.info testing-packworx.pazl.info api-dev-packworx.pazl.info dev-packworx.pazl.info deploy.pazl.info)

# ------- pretty printers
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
ok()   { printf "  ${GREEN}[OK]${RESET}   %s\n" "$*"; }
warn() { printf "  ${YELLOW}[WARN]${RESET} %s\n" "$*"; }
fail() { printf "  ${RED}[FAIL]${RESET} %s\n" "$*"; }
step() { printf "\n${BLUE}== %s ==${RESET}\n" "$*"; }

[ "$(id -u)" -ne 0 ] && warn "Not running as root — pm2/systemd commands may fail."

# ------- 1. systemd units
step "systemd units"
for svc in pm2-root nginx packwork-deploy; do
  if systemctl is-active --quiet "$svc"; then
    ok "$svc active"
  else
    warn "$svc not active — starting..."
    systemctl start "$svc" && ok "$svc started" || fail "$svc failed to start"
  fi
done

# ------- 2. PM2 resurrect testing + development (no-op if already running)
ensure_env() {
  local suffix="$1" be_dir="$2"
  step "PM2 ${suffix} processes"
  local names running errored
  names=$(node -e "console.log(require('$be_dir/ecosystem.config.js').apps.filter(a=>a.name.endsWith('-${suffix}')).map(a=>a.name).join(','))" 2>/dev/null)
  running=$(pm2 jlist 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{console.log(JSON.parse(d).filter(p=>p.name.endsWith('-${suffix}')&&p.pm2_env.status==='online').length)}catch(e){console.log(0)}})")

  if [ "${running:-0}" -eq 0 ]; then
    warn "No -${suffix} processes online — resurrecting from saved dump..."
    pm2 resurrect 2>&1 | sed 's/^/    /' | tail -3
    sleep 5
    running=$(pm2 jlist 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{console.log(JSON.parse(d).filter(p=>p.name.endsWith('-${suffix}')&&p.pm2_env.status==='online').length)}catch(e){console.log(0)}})")
  fi

  if [ "${running:-0}" -eq 0 ] && [ -n "$names" ]; then
    warn "Starting -${suffix} from ecosystem.config.js..."
    ( cd "$be_dir" && pm2 start ecosystem.config.js --only "$names" 2>&1 | sed 's/^/    /' | tail -3 )
    sleep 5
  fi

  errored=$(pm2 jlist 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const e=JSON.parse(d).filter(p=>p.name.endsWith('-${suffix}')&&p.pm2_env.status!=='online');console.log(e.map(p=>p.name).join(' '))})")
  if [ -n "${errored:-}" ]; then
    warn "Restarting errored: $errored"
    for n in $errored; do pm2 restart "$n" --update-env >/dev/null 2>&1; done
    sleep 3
  fi
}

ensure_env "testing" "$BE_TESTING_DIR"
ensure_env "development" "$BE_DEV_DIR"

# ------- 3. Port check
step "Ports 7001-7015 (dev) + 8001-8015 (testing)"
MISSING=()
for p in "${PORTS[@]}"; do
  if ss -tnlp 2>/dev/null | grep -q ":$p "; then
    ok "$p listening"
  else
    fail "$p NOT listening"
    MISSING+=("$p")
  fi
done

# ------- 4. HTTPS endpoint check
step "HTTPS health"
for d in "${DOMAINS[@]}"; do
  code=$(curl -sk --resolve "$d:443:127.0.0.1" -o /dev/null -w "%{http_code}" --max-time 5 "https://$d/" 2>/dev/null)
  case "$code" in
    200|301|302) ok "$d -> $code" ;;
    *)           fail "$d -> ${code:-no response}" ;;
  esac
done

# ------- 5. Summary
step "Summary"
pm2 jlist 2>/dev/null | node -e '
let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{
  const all=JSON.parse(d);
  for (const suf of ["testing","development"]) {
    const list=all.filter(p=>p.name.endsWith("-"+suf));
    const ok=list.filter(p=>p.pm2_env.status==="online").length;
    console.log(`  PM2 ${suf}: ${ok}/${list.length} online`);
  }
})'

if [ "${#MISSING[@]}" -eq 0 ]; then
  printf "\n${GREEN}All services up.${RESET} Run \`pm2 list\` for details.\n"
  exit 0
else
  printf "\n${RED}Missing ports: ${MISSING[*]}${RESET} — check \`pm2 logs <name>-testing\`.\n"
  exit 1
fi
