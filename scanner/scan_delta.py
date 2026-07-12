#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from intelligence_common import dump_jsonl, jsonl, lines, load

def finding_key(item: dict[str, Any]) -> str:
    n=item.get("_normalized") if isinstance(item.get("_normalized"),dict) else {}; info=item.get("info") if isinstance(item.get("info"),dict) else {}; poc=item.get("pocinfo") if isinstance(item.get("pocinfo"),dict) else {}
    return "\t".join(str(x or "") for x in (n.get("severity") or info.get("severity") or item.get("vuln_severity") or poc.get("infoseg") or "unknown", n.get("template_id") or item.get("template-id") or item.get("poc_id") or poc.get("id"), n.get("matched_at") or item.get("matched-at") or item.get("fulltarget") or item.get("vuln_url") or item.get("host") or item.get("target"), n.get("name") or info.get("name") or item.get("vuln_name") or poc.get("infoname") or item.get("name")))


def all_findings(root: Path) -> dict[str,dict[str,Any]]:
    out={finding_key(x):{"scanner":"nuclei","key":finding_key(x),"item":x} for x in jsonl(root/"nuclei.jsonl")}
    data=load(root/"afrog.json",[])
    if isinstance(data,dict): data=data.get("results") or data.get("data") or data.get("vulnerabilities") or []
    for x in data if isinstance(data,list) else []:
        if isinstance(x,dict): out[finding_key(x)]={"scanner":"afrog","key":finding_key(x),"item":x}
    return out


def cmd_delta(args: argparse.Namespace) -> int:
    current=args.current.resolve(); results=args.results_root.resolve(); explicit=os.getenv("SCAN_DELTA_BASE","").strip(); previous=Path(explicit).resolve() if explicit else None
    if not previous or not previous.is_dir() or previous==current:
        latest=results/"latest"
        if latest.exists() or latest.is_symlink():
            try: previous=latest.resolve()
            except OSError: previous=None
    delta={"status":"no-baseline","current":current.name,"baseline":None,"sets":{},"new_items_total":0,"new_api_operations":0,"new_findings":0}; new_assets=[]; new_api=[]; new_findings=[]
    if previous and previous.is_dir() and previous!=current:
        delta.update(status="compared",baseline=previous.name)
        sets={"domains":("domains.all.txt","domains.txt"),"live_urls":("live-urls.txt",),"priority_urls":("urls-priority.txt",),"api_urls":("urls-api.txt",),"sensitive_urls":("urls-sensitive.txt",),"sourcemaps":("sourcemaps.v2.urls.txt",),"actionable_targets":("actionable-targets.txt",)}
        for label,names in sets.items():
            def values(root):
                for name in names:
                    if (root/name).is_file(): return set(lines(root/name))
                return set()
            now,old=values(current),values(previous); added=sorted(now-old); removed=sorted(old-now); delta["sets"][label]={"current":len(now),"baseline":len(old),"added":len(added),"removed":len(removed),"added_sample":added[:100],"removed_sample":removed[:50]}; delta["new_items_total"]+=len(added); new_assets.extend(f"{label}\t{x}\n" for x in added)
        key=lambda x:f"{x.get('method')}\t{x.get('path')}\t{((x.get('urls') or [x.get('document_url') or ''])[0])}"
        now={key(x):x for x in jsonl(current/"api-operations.jsonl")}; old={key(x):x for x in jsonl(previous/"api-operations.jsonl")}
        for k in sorted(set(now)-set(old)): x=now[k]; new_api.append(f"{x.get('priority','')}\t{x.get('method','')}\t{x.get('path','')}\t{(x.get('urls') or [x.get('document_url') or ''])[0]}\n")
        delta["new_api_operations"]=len(new_api); nf=all_findings(current); of=all_findings(previous); new_findings=[nf[k] for k in sorted(set(nf)-set(of))]; delta["new_findings"]=len(new_findings)
    (current/"scan-delta.json").write_text(json.dumps(delta,ensure_ascii=False,indent=2)+"\n",encoding="utf-8"); (current/"new-assets.txt").write_text("".join(new_assets),encoding="utf-8"); (current/"new-api-operations.txt").write_text("".join(new_api),encoding="utf-8"); dump_jsonl(current/"new-findings.jsonl",new_findings)
    md=["# 扫描增量","",f"- 状态：{'已比较' if delta['status']=='compared' else '无历史基线'}",f"- 基线：`{delta.get('baseline') or '-'}`",f"- 新增资产/URL：{delta['new_items_total']}",f"- 新增 API 操作：{delta['new_api_operations']}",f"- 新增扫描器命中：{delta['new_findings']}",""]
    (current/"scan-delta.md").write_text("\n".join(md),encoding="utf-8"); return 0
