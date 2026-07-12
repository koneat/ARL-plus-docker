#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from actionable_assets import cmd_actionable
from api_schema_intel import cmd_api
from report_enrichment import cmd_report
from scan_delta import cmd_delta

def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="ARL actionable asset, API schema and scan delta intelligence"); sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("api"); a.add_argument("output_dir",type=Path); a.add_argument("inputs",nargs="+",type=Path); a.add_argument("--scope-roots",type=Path); a.add_argument("--max-candidates",type=int,default=int(os.getenv("API_SCHEMA_MAX_CANDIDATES","200"))); a.add_argument("--workers",type=int,default=int(os.getenv("API_SCHEMA_WORKERS","8"))); a.add_argument("--timeout",type=int,default=int(os.getenv("API_SCHEMA_TIMEOUT","8"))); a.add_argument("--max-bytes",type=int,default=int(os.getenv("API_SCHEMA_MAX_BYTES","4194304"))); a.add_argument("--verify-tls",action="store_true"); a.set_defaults(func=cmd_api)
    a=sub.add_parser("actionable"); a.add_argument("result_dir",type=Path); a.add_argument("--max-assets",type=int,default=int(os.getenv("ACTIONABLE_MAX_ASSETS","10000"))); a.set_defaults(func=cmd_actionable)
    a=sub.add_parser("delta"); a.add_argument("current",type=Path); a.add_argument("results_root",type=Path); a.set_defaults(func=cmd_delta)
    a=sub.add_parser("report"); a.add_argument("result_dir",type=Path); a.set_defaults(func=cmd_report)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    raise SystemExit(args.func(args))
