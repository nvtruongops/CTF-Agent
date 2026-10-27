#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mode=${1:?Expected prerequisites or install}

check_account() {
  [ "$(id -u ctfagent)" != 0 ] || { echo 'ctfagent must not be root.' >&2; exit 1; }
  if id -nG ctfagent | grep -Eq '(^| )(sudo|wheel|root)( |$)'; then
    echo 'ctfagent must not belong to sudo/wheel/root; existing membership was not changed.' >&2
    exit 1
  fi
}

if [ "$mode" = prerequisites ]; then
  [ "$(id -u)" = 0 ] || { echo 'Prerequisite installation requires root.' >&2; exit 1; }
  . /etc/os-release
  [ "$ID" = kali ] || { echo 'This setup supports Kali Linux WSL2.' >&2; exit 1; }
  if ! /usr/bin/node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>24||a===24&&b>=11?0:1)' 2>/dev/null || ! test -x /usr/bin/npm || ! dpkg-query -W -f='${Status}' python3-venv 2>/dev/null | grep -q 'install ok installed'; then
    apt-get update
    candidate=$(apt-cache policy nodejs | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p')
    if [ -z "$candidate" ] || [ "$candidate" = '(none)' ] || ! dpkg --compare-versions "$candidate" ge 24.11; then
      echo 'Kali APT must offer Linux Node >=24.11; refresh/configure the Kali mirror and rerun.' >&2
      exit 1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Use-Pty=0 install --yes --no-remove --no-install-recommends nodejs npm python3 python3-venv
  fi
  /usr/bin/node -e 'const [a,b]=process.versions.node.split(".").map(Number);if(!(a>24||a===24&&b>=11))throw Error("Kali repository must provide Linux Node >=24.11")'
  /usr/bin/npm --version
  /usr/bin/python3 -I -c 'import venv,sys;print(sys.version.split()[0])'
  if ! id ctfagent >/dev/null 2>&1; then useradd --create-home --shell /bin/bash ctfagent; fi
  check_account
  for directory in /home/ctfagent /home/ctfagent/.local /home/ctfagent/.local/share /home/ctfagent/.local/share/ctf-agent /home/ctfagent/ctf-workspaces; do
    [ ! -L "$directory" ] || { echo "Refusing redirected setup directory: $directory" >&2; exit 1; }
  done
  install -d -m 700 -o ctfagent -g ctfagent /home/ctfagent/.local/share/ctf-agent /home/ctfagent/ctf-workspaces
  exit 0
fi

if [ "$mode" = tools ]; then
  [ "$(id -u)" = 0 ] || { echo 'Tool provisioning requires root.' >&2; exit 1; }
  check_account
  repo=${2:?Expected reviewed checkout path}
  profile=${3:?Expected profile}
  # Read only package data from the reviewed checkout; never run the installed runtime as root.
  spec=$(/usr/bin/python3 -I - "$repo/ctf_mcp/tool-manifest.json" "$profile" <<'PY'
import json,re,sys
with open(sys.argv[1], encoding="utf-8") as f:
    profiles=json.load(f)["profiles"]
selected=profiles[sys.argv[2]]
assert sys.argv[2] != "base"
for name in dict.fromkeys(profiles["base"]["apt"] + selected["apt"]):
    assert re.fullmatch(r"[a-z0-9][a-z0-9+.-]*",name)
    print("apt:"+name)
for name in selected.get("python",[]):
    assert re.fullmatch(r"frida==[0-9]+\.[0-9]+\.[0-9]+",name)
    print("python:"+name)
PY
  )
  packages=()
  python_packages=()
  missing=0
  while IFS=: read -r kind name; do
    if [ "$kind" = apt ]; then
      packages+=("$name")
      if [ "$(dpkg-query -W -f='${Status}' "$name" 2>/dev/null || true)" != 'install ok installed' ]; then missing=1; fi
    elif [ "$kind" = python ]; then python_packages+=("$name"); fi
  done <<< "$spec"
  if [ "$missing" = 1 ]; then
    apt-get update
    for package in "${packages[@]}"; do
      candidate=$(apt-cache policy "$package" | sed -n 's/^[[:space:]]*Candidate:[[:space:]]*//p')
      [ -n "$candidate" ] && [ "$candidate" != '(none)' ] || { echo "No Kali APT candidate for $package" >&2; exit 1; }
    done
    DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Use-Pty=0 install --yes --no-remove --no-install-recommends "${packages[@]}"
  fi
  if [ "${#python_packages[@]}" != 0 ]; then
    python=/home/ctfagent/.local/share/ctf-agent/frida-venv/bin/python
    # pip and all imports run without root in the existing installer environment.
    if ! /usr/sbin/runuser -u ctfagent -- "$python" -I -c 'import frida,sys;assert frida.__version__ == sys.argv[1].split("==")[1]' "${python_packages[0]}" 2>/dev/null; then
      /usr/sbin/runuser -u ctfagent -- /usr/bin/python3 -m venv "$(dirname "$(dirname "$python")")"
      /usr/sbin/runuser -u ctfagent -- "$python" -m pip install --require-virtualenv --no-input --disable-pip-version-check "${python_packages[@]}"
    fi
  fi
  exit 0
fi

[ "$mode" = install ] || { echo 'Unknown setup mode.' >&2; exit 1; }
[ "$(id -un)" = ctfagent ] || { echo 'Package installation must run as ctfagent.' >&2; exit 1; }
check_account
repo=${2:?Expected checkout path}
prefix=/home/ctfagent/.local/share/ctf-agent
[ ! -L "$prefix/runtime" ] || { echo 'Refusing redirected runtime directory.' >&2; exit 1; }
temp=$(mktemp -d "$prefix/install-XXXXXXXX")
trap 'rm -rf -- "$temp"' EXIT
unset NODE_AUTH_TOKEN NPM_TOKEN
export NPM_CONFIG_USERCONFIG=/dev/null NPM_CONFIG_REGISTRY=https://registry.npmjs.org
/usr/bin/node "$repo/scripts/package-audit.js"
/usr/bin/npm pack "$repo" --pack-destination "$temp" --json > "$temp/pack.json"
archive="$temp/ctf-agent-0.1.0.tgz"
[ -f "$archive" ] || { echo 'Expected ctf-agent@0.1.0 archive was not produced.' >&2; exit 1; }
digest=$(sha256sum "$archive" | cut -d' ' -f1)
if [ -f "$prefix/archive.sha256" ] && [ "$(cat "$prefix/archive.sha256")" = "$digest" ] && [ -f "$prefix/runtime/node_modules/ctf-agent/ctf_mcp/cli.js" ]; then
  echo 'Installed runtime already matches this checkout.'
  exit 0
fi
/usr/bin/npm install --prefix "$temp/runtime" --omit=dev --no-audit --no-fund --package-lock=false "$archive"
/usr/bin/node "$temp/runtime/node_modules/ctf-agent/ctf_mcp/cli.js" --help >/dev/null
if [ -e "$prefix/runtime" ]; then mv -- "$prefix/runtime" "$prefix/runtime.backup-$(date +%s)-$$"; fi
mv -- "$temp/runtime" "$prefix/runtime"
printf '%s\n' "$digest" > "$prefix/archive.sha256"
echo 'Installed local ctf-agent@0.1.0 in Kali; no public ctf-agent download was used.'
