#!/usr/bin/env python3
"""
prowler_formatter.py
--------------------
Converts Prowler CSV output → styled XLSX report.
Supports Prowler v3 (semicolon-separated, SERVICE_NAME columns)
and Prowler v4 (comma-separated, SERVICENAME / FINDING_STATUS columns).

Usage:
    python prowler_formatter.py --input <prowler.csv> --output <report.xlsx>
                                [--customer <n>] [--account <id>]
"""

import argparse
import os
import sys
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import xlsxwriter

warnings.simplefilter(action="ignore", category=pd.errors.DtypeWarning)

# ── Column name normalisation (v3 & v4 → unified schema) ───────────────────
_COL_ALIASES = {
    # v3 native
    "SERVICE_NAME": "SERVICE_NAME", "CHECK_TITLE": "CHECK_TITLE",
    "STATUS": "STATUS", "REGION": "REGION",
    "RESOURCE_ARN": "RESOURCE_ARN", "RESOURCE_ID": "RESOURCE_ID",
    "STATUS_EXTENDED": "STATUS_EXTENDED", "SEVERITY": "SEVERITY",
    # v4 variants
    "SERVICENAME": "SERVICE_NAME",
    "CHECKTITLE": "CHECK_TITLE", "CHECKID": "CHECK_TITLE", "CHECK_ID": "CHECK_TITLE",
    "FINDING_STATUS": "STATUS", "STATUS_CODE": "STATUS",
    "RESOURCE_UID": "RESOURCE_ID", "RESOURCEID": "RESOURCE_ID",
    "RESOURCEARN": "RESOURCE_ARN",
    "EXTENDED_STATUS": "STATUS_EXTENDED", "FINDING_DESCRIPTION": "STATUS_EXTENDED",
    "RISK": "SEVERITY", "SEVERITY_LEVEL": "SEVERITY",
    # lowercase
    "service_name": "SERVICE_NAME", "check_title": "CHECK_TITLE",
    "status": "STATUS", "region": "REGION",
    "resource_arn": "RESOURCE_ARN", "resource_id": "RESOURCE_ID",
    "status_extended": "STATUS_EXTENDED", "severity": "SEVERITY",
}

def _to_series(obj):
    """Guarantee a flat 1-D string Series — guards against duplicate-column DataFrames."""
    if isinstance(obj, pd.DataFrame):
        obj = obj.iloc[:, 0]
    if hasattr(obj, "ndim") and obj.ndim > 1:
        obj = obj.iloc[:, 0]
    return obj.fillna("").astype(str).replace("nan", "").replace("None", "")


def _normalise_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rename Prowler v3/v4/v5 columns to unified schema.
    Bulletproof against duplicate column names (root cause of
    'DataFrame object has no attribute str').
    """
    # Step 1: Flatten MultiIndex columns
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = ["_".join(str(c) for c in col).strip() for col in df.columns]
    # Step 2: Strip column name whitespace
    df.columns = [str(c).strip() for c in df.columns]
    # Step 3: Drop duplicate column names BEFORE rename
    df = df.loc[:, ~df.columns.duplicated(keep="first")]
    # Step 4: Force every column to flat 1-D string Series
    for col in list(df.columns):
        df[col] = _to_series(df[col])
    # Step 5: Rename to normalised names
    rename_map = {}
    for col in list(df.columns):
        norm = _COL_ALIASES.get(col) or _COL_ALIASES.get(col.upper())
        if norm and col != norm:
            rename_map[col] = norm
    df = df.rename(columns=rename_map)
    # Step 6: Drop NEW duplicates created by rename (multiple sources → same target)
    df = df.loc[:, ~df.columns.duplicated(keep="first")]
    # Step 7: Force flat Series again after rename
    for col in list(df.columns):
        df[col] = _to_series(df[col])
    # Step 8: Ensure all required columns exist
    for req in ["STATUS", "SERVICE_NAME", "CHECK_TITLE", "SEVERITY",
                "REGION", "RESOURCE_ARN", "RESOURCE_ID", "STATUS_EXTENDED"]:
        if req not in df.columns:
            df[req] = pd.Series([""] * len(df), dtype=str)
        df[req] = _to_series(df[req])
    # Step 9: Normalise STATUS — v3/v4/v5 variants
    STATUS_MAP = {
        "PASS": "PASS", "PASSED": "PASS",
        "FAIL": "FAIL", "FAILED": "FAIL",
        "WARNING": "FAIL", "MUTED": "PASS", "MANUAL": "PASS",
    }
    df["STATUS"] = (_to_series(df["STATUS"]).str.strip().str.upper()
                    .map(lambda x: STATUS_MAP.get(x, "FAIL" if x not in ("", "nan") else "PASS")))
    # Step 10: Normalise SEVERITY to lowercase
    df["SEVERITY"] = _to_series(df["SEVERITY"]).str.strip().str.lower()
    # Step 11: Normalise SERVICE_NAME
    svc = _to_series(df["SERVICE_NAME"]).str.strip()
    svc = svc.where(~svc.isin(["", "nan", "None", "none"]), "Other")
    df["SERVICE_NAME"] = svc
    return df

# ── Colour palette ──────────────────────────────────────────────────────────
SEV_COLOURS = {
    "critical":      {"bg": "C62828", "fg": "FFFFFF"},
    "high":          {"bg": "EF6C00", "fg": "FFFFFF"},
    "medium":        {"bg": "F9A825", "fg": "000000"},
    "low":           {"bg": "2E7D32", "fg": "FFFFFF"},
    "informational": {"bg": "1565C0", "fg": "FFFFFF"},
}
DETAIL_COLS = [
    "CHECK_TITLE", "SEVERITY", "STATUS",
    "RESOURCE_ID", "RESOURCE_ARN",
    "REGION", "SERVICE_NAME", "STATUS_EXTENDED", "Remark",
]
SVC_HDR_COLOURS = [
    "#1A3A6B", "#243C72", "#1C3560", "#2A4880",
    "#16305A", "#0F2850", "#2E4A7A", "#1F3A5F",
]
COL_WIDTHS = {
    "CHECK_TITLE": 55, "SEVERITY": 14, "STATUS": 10,
    "RESOURCE_ID": 32, "RESOURCE_ARN": 55,
    "REGION": 18, "SERVICE_NAME": 22, "STATUS_EXTENDED": 60, "Remark": 30,
}


def _make_formats(wb, sh_colour="#1A3A6B"):
    h = lambda c: c.lstrip("#")
    f = {}
    f["title"]  = wb.add_format({"bold":True,"font_name":"Arial","font_size":13,
        "bg_color":"#0C1929","font_color":"#FFFFFF","border":1,"align":"left","valign":"vcenter"})
    f["label"]  = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,
        "bg_color":"#112238","font_color":"#AEC9F0","border":1,"align":"left","valign":"vcenter"})
    f["value"]  = wb.add_format({"font_name":"Arial","font_size":10,
        "bg_color":"#162B45","font_color":"#E2E8F0","border":1,"align":"left","valign":"vcenter"})
    f["hdr"]    = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,
        "bg_color":h(sh_colour),"font_color":"#FFFFFF","border":1,
        "align":"center","valign":"vcenter","text_wrap":True})
    f["merge"]  = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,
        "bg_color":"#E8EFF8","font_color":"#1E293B","border":1,
        "align":"center","valign":"vcenter","text_wrap":True})
    f["odd"]    = wb.add_format({"font_name":"Arial","font_size":10,
        "bg_color":"#FFFFFF","font_color":"#1E293B","border":1,"align":"left","valign":"vcenter"})
    f["even"]   = wb.add_format({"font_name":"Arial","font_size":10,
        "bg_color":"#F0F4F8","font_color":"#1E293B","border":1,"align":"left","valign":"vcenter"})
    f["remark"] = wb.add_format({"font_name":"Arial","font_size":10,
        "bg_color":"#FFFDE7","font_color":"#33691E","border":1,"align":"left","valign":"vcenter"})
    f["fail"]   = wb.add_format({"bold":True,"font_name":"Arial","font_size":10,
        "bg_color":"#C62828","font_color":"#FFFFFF","border":1,"align":"center","valign":"vcenter"})
    return f


def _sev_fmt_fn(wb):
    cache = {}
    def get(sev_str):
        key = (sev_str or "").lower()
        if key not in cache:
            c = SEV_COLOURS.get(key, {"bg": "475569", "fg": "FFFFFF"})
            cache[key] = wb.add_format({
                "bold":True,"font_name":"Arial","font_size":10,
                "bg_color":f"#{c['bg']}","font_color":f"#{c['fg']}",
                "border":1,"align":"center","valign":"vcenter"})
        return cache[key]
    return get


def convert(input_csv: str, output_xlsx: str,
            customer: str = "Report", account_id: str = "") -> None:

    if not os.path.exists(input_csv):
        print(f"[ERROR] Input file not found: {input_csv}")
        sys.exit(1)

    # Try semicolon (v3) then comma (v4)
    df = None
    for sep in [";", ","]:
        try:
            _df = pd.read_csv(input_csv, encoding="ISO-8859-1", sep=sep,
                              on_bad_lines="skip", low_memory=False)
            if len(_df.columns) > 3:
                df = _df; break
        except Exception:
            continue
    if df is None:
        print("[ERROR] Could not parse CSV file with ; or , separator")
        sys.exit(1)

    df = _normalise_df(df)

    if "STATUS" not in df.columns:
        print(f"[ERROR] STATUS column missing after normalisation. Columns: {list(df.columns)}")
        sys.exit(1)

    df_fail = df[df["STATUS"] == "FAIL"].copy()
    total_checks = len(df)
    total_fails  = len(df_fail)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"informational":4}
    sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"informational":0}

    summary_items, details = [], {}

    for svc, grp in df_fail.groupby("SERVICE_NAME"):
        svc = str(svc).strip() or "Other"
        unique_checks = (
            grp[["CHECK_TITLE","SEVERITY"]].drop_duplicates()
            .sort_values("SEVERITY",
                key=lambda s: s.str.lower().map(lambda x: sev_order.get(x,9)))
        )
        checks = unique_checks.to_dict("records")
        summary_items.append({"service": svc, "checks": checks, "count": len(grp)})
        src = [c for c in DETAIL_COLS if c != "Remark" and c in grp.columns]
        rows = grp[src].fillna("").replace([np.inf,-np.inf],"").to_dict("records")
        for row in rows:
            row["Remark"] = ""
            sv = str(row.get("SEVERITY","")).lower()
            if sv in sev_counts:
                sev_counts[sv] += 1
        details[svc] = rows

    with xlsxwriter.Workbook(output_xlsx) as wb:
        base = _make_formats(wb, "#1A3A6B")
        sev  = _sev_fmt_fn(wb)

        # ══ SUMMARY SHEET ══
        ws = wb.add_worksheet("Summary")
        ws.set_column(0,0,28); ws.set_column(1,1,60); ws.set_column(2,2,16)
        r = 0
        ws.set_row(r,30)
        ws.merge_range(r,0,r,2,
            f"AWS Security Audit Report  |  Customer: {customer}", base["title"])
        r += 1
        meta = [
            ("Customer",         customer),
            ("Account ID",       account_id or "—"),
            ("Report Date",      now_str),
            ("Total Checks Run", str(total_checks)),
            ("Total Failures",   str(total_fails)),
            ("Services Affected",str(len(summary_items))),
            ("Critical",         str(sev_counts["critical"])),
            ("High",             str(sev_counts["high"])),
            ("Medium",           str(sev_counts["medium"])),
            ("Low",              str(sev_counts["low"])),
            ("Informational",    str(sev_counts["informational"])),
            ("Source CSV",       input_csv),
        ]
        for k,v in meta:
            ws.set_row(r,16)
            ws.write(r,0,k,base["label"])
            ws.merge_range(r,1,r,2,v,base["value"])
            r += 1
        r += 1  # spacer
        ws.set_row(r,20)
        ws.write(r,0,"SERVICE NAME",base["hdr"])
        ws.write(r,1,"CHECK TITLE", base["hdr"])
        ws.write(r,2,"SEVERITY",    base["hdr"])
        r += 1
        for item in summary_items:
            sv_name = item["service"]
            chks    = item["checks"]
            n       = len(chks)
            if n>1: ws.merge_range(r,0,r+n-1,0,sv_name,base["merge"])
            else:   ws.write(r,0,sv_name,base["merge"])
            for chk in chks:
                rf = base["odd"] if r%2==0 else base["even"]
                ws.write(r,1,chk.get("CHECK_TITLE",""),rf)
                ws.write(r,2,chk.get("SEVERITY",""),sev(chk.get("SEVERITY","")))
                r += 1

        # ══ PER-SERVICE SUB-SHEETS ══
        for sh_idx, item in enumerate(summary_items):
            sv_name   = item["service"]
            rows_data = details.get(sv_name,[])
            if not rows_data: continue
            sh_colour = SVC_HDR_COLOURS[sh_idx % len(SVC_HDR_COLOURS)]
            sh_fmts   = _make_formats(wb, sh_colour)
            sh_sev    = _sev_fmt_fn(wb)
            sws       = wb.add_worksheet(sv_name[:31])

            avail  = [c for c in DETAIL_COLS if c in rows_data[0] or c=="Remark"]
            n_cols = len(avail)
            sws.set_row(0,26)
            sws.merge_range(0,0,0,n_cols-1,
                f"{sv_name}  ·  {len(rows_data)} failures  |  Account: {account_id}  |  {now_str}",
                sh_fmts["title"])
            sws.set_row(1,20)
            for ci,col in enumerate(avail):
                sws.write(1,ci,col.replace("_"," "),sh_fmts["hdr"])
            sws.autofilter(1,0,1+len(rows_data),n_cols-1)

            for ri,row_d in enumerate(rows_data):
                dr = ri+2
                cf = sh_fmts["odd"] if ri%2==0 else sh_fmts["even"]
                sws.set_row(dr,16)
                for ci,col in enumerate(avail):
                    val = row_d.get(col,"")
                    try:
                        if isinstance(val,float) and (np.isnan(val) or np.isinf(val)):
                            val=""
                    except Exception: pass
                    if   col=="Remark":   sws.write(dr,ci,"",sh_fmts["remark"])
                    elif col=="SEVERITY": sws.write(dr,ci,str(val),sh_sev(str(val)))
                    elif col=="STATUS":   sws.write(dr,ci,str(val),sh_fmts["fail"])
                    else:                 sws.write(dr,ci,str(val),cf)

            for ci,col in enumerate(avail):
                sws.set_column(ci,ci,COL_WIDTHS.get(col,22))

    print(f"[OK] XLSX written → {output_xlsx}")
    print(f"     Checks: {total_checks}  |  Failures: {total_fails}  |  Services: {len(summary_items)}")


def main():
    p = argparse.ArgumentParser(description="Convert Prowler CSV → styled XLSX.")
    p.add_argument("--input",    "-i", required=True, help="Prowler CSV file")
    p.add_argument("--output",   "-o", default="prowler_security_report.xlsx")
    p.add_argument("--customer", "-c", default="Report")
    p.add_argument("--account",  "-a", default="")
    a = p.parse_args()
    convert(a.input, a.output, a.customer, a.account)

if __name__ == "__main__":
    main()
