#!/usr/bin/env bash
# ARL_PRIVATE_BOOTSTRAP_VERSION=2026.07.17-final.3
set -Eeuo pipefail
umask 077

REPO_URL="${REPO_URL:-https://github.com/koneat/ARL-plus-docker.git}"
RELEASE_BRANCH="${RELEASE_BRANCH:-release/2026.07.17-final}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPLETE_BOOTSTRAP="${SCRIPT_DIR}/private-bootstrap-complete.sh"
TMP_DIR=""

cleanup() {
  local status=$?
  [[ -z "$TMP_DIR" || ! -d "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT

if [[ -r "$COMPLETE_BOOTSTRAP" ]]; then
  bash "$COMPLETE_BOOTSTRAP" "$@"
  exit $?
fi

[[ "$(id -u)" -eq 0 ]] || {
  echo '[FATAL] 请使用 root 运行本脚本' >&2
  exit 1
}
command -v git >/dev/null 2>&1 || {
  apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=5 update
  apt-get -o DPkg::Lock::Timeout=300 -o Acquire::Retries=5 install -y git ca-certificates
}

TMP_DIR="$(mktemp -d /tmp/arl-bootstrap-entry.XXXXXX)"
git -c http.version=HTTP/1.1 clone --depth 1 --single-branch \
  --branch "$RELEASE_BRANCH" "$REPO_URL" "$TMP_DIR/repo"
COMPLETE_BOOTSTRAP="$TMP_DIR/repo/installer/private-bootstrap-complete.sh"
[[ -r "$COMPLETE_BOOTSTRAP" ]] || {
  echo '[FATAL] 发布分支缺少完整私密启动器' >&2
  exit 1
}
bash "$COMPLETE_BOOTSTRAP" "$@"
