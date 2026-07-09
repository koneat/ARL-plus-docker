# shellcheck shell=bash

clone_or_update_repo() {
  if [[ -d "$ARL_DIR/.git" ]]; then
    log "更新现有仓库：$ARL_DIR"

    local dirty unexpected path preserved_config
    dirty="$(git -C "$ARL_DIR" status --porcelain --untracked-files=no || true)"
    unexpected=""
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      path="${line:3}"
      case "$path" in
        config-docker.yaml|docker-compose.yml) ;;
        *) unexpected+="${line}"$'\n' ;;
      esac
    done <<< "$dirty"

    if [[ -n "$unexpected" ]]; then
      printf '%s' "$unexpected" >&2
      die "仓库存在非安装脚本产生的未提交修改，请先备份或提交"
    fi

    preserved_config="${ARL_DIR}/config-docker.yaml.preserved.${RUN_ID}"
    if [[ -f "${ARL_DIR}/config-docker.yaml" ]]; then
      cp -a "${ARL_DIR}/config-docker.yaml" "$preserved_config"
      cp -a "${ARL_DIR}/config-docker.yaml" \
        "${ARL_DIR}/config-docker.yaml.bak.${RUN_ID}"
    fi
    if [[ -f "${ARL_DIR}/docker-compose.yml" ]]; then
      cp -a "${ARL_DIR}/docker-compose.yml" \
        "${ARL_DIR}/docker-compose.yml.bak.${RUN_ID}"
    fi

    git -C "$ARL_DIR" checkout -- config-docker.yaml docker-compose.yml 2>/dev/null || true
    git -C "$ARL_DIR" fetch --prune origin
    git -C "$ARL_DIR" checkout "$REPO_BRANCH"
    git -C "$ARL_DIR" pull --ff-only origin "$REPO_BRANCH"

    if [[ -f "$preserved_config" ]]; then
      cp -a "$preserved_config" "${ARL_DIR}/config-docker.yaml"
      rm -f "$preserved_config"
      ok "已保留原 config-docker.yaml，未重置 MongoDB 或 ARL 配置"
    fi
  elif [[ -e "$ARL_DIR" ]]; then
    die "$ARL_DIR 已存在但不是 Git 仓库"
  else
    log "克隆仓库：$REPO_URL"
    git clone --branch "$REPO_BRANCH" --single-branch "$REPO_URL" "$ARL_DIR"
  fi

  ok "仓库准备完成"
}

backup_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  cp -a "$path" "${path}.bak.${RUN_ID}"
}
