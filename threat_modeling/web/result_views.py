"""
Counts behind the result screens (analysis, TMT comparison, coverage).

The screens used to show numbers in different units side by side -- pairs next to
threats -- and left the reader to reconcile them. Each function here returns a
total together with the parts that make it up, in a single unit, so the templates
can draw them as bars that visibly add up.
"""
from collections import Counter, OrderedDict
from typing import Dict, Iterable, List, Optional

STRIDE = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
          "Denial of Service", "Elevation of Privilege"]
STRIDE_SHORT = {"Spoofing": "S", "Tampering": "T", "Repudiation": "R",
                "Information Disclosure": "I", "Denial of Service": "D",
                "Elevation of Privilege": "E"}
OTHER = "Other"
_CANONICAL = {c.lower(): c for c in STRIDE}


def canonical_category(category) -> str:
    """'Denial Of Service' (TMT) and 'Denial of Service' (LLM) -> 'Denial of Service'."""
    return _CANONICAL.get(str(category or "").strip().lower(), OTHER)


def _key(flow, category):
    # Same normalisation as ComparisonService, so the grid matches the pairing.
    return str(flow or "").strip().lower(), str(category or "").strip().lower()


def _percent(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def analysis_overview(analysis_rows: List[Dict], flow_names: Iterable[str]) -> Dict:
    """Totals of the AI analysis: by STRIDE category and by data flow of the DFD."""
    flows = list(OrderedDict.fromkeys(str(f).strip() for f in flow_names if f))
    by_cat = Counter(canonical_category(r.get("category")) for r in analysis_rows)
    by_flow = Counter(str(r.get("data_flow_name") or "").strip() for r in analysis_rows)
    categories = [{"name": c, "short": STRIDE_SHORT[c], "count": by_cat.get(c, 0)} for c in STRIDE]
    if by_cat.get(OTHER):
        categories.append({"name": OTHER, "short": "?", "count": by_cat[OTHER]})
    biggest = max([c["count"] for c in categories] + [1])
    for c in categories:
        c["width"] = _percent(c["count"], biggest)
    flow_rows = [{"name": f, "count": by_flow.get(f, 0)} for f in flows]
    return {
        "total": len(analysis_rows),
        "categories": categories,
        "categories_with_threats": sum(1 for c in categories if c["count"] and c["name"] != OTHER),
        "flows": flow_rows,
        "flows_total": len(flows),
        "flows_with_threats": sum(1 for f in flow_rows if f["count"]),
        "flows_without_threats": [f["name"] for f in flow_rows if not f["count"]],
    }


def comparison_overview(tmt_rows: List[Dict], ai_rows: List[Dict], comparison_rows: List[Dict],
                        flow_names: Iterable[str], threshold: float = 0.7) -> Dict:
    """
    Reconcile the TMT x AI comparison in threats and in pairs.

    A threat 'has a match' when the other side has at least one threat in the same
    data flow and STRIDE category. Inside such a group every TMT threat is judged
    against every AI threat, so pairs are counted apart from threats.
    """
    tmt_keys = Counter(_key(r.get("DataFlow"), r.get("Category")) for r in tmt_rows)
    ai_keys = Counter(_key(r.get("data_flow_name"), r.get("category")) for r in ai_rows)
    pairs = [r for r in comparison_rows if r.get("source") == "both"]
    approved = [r for r in pairs if bool(r.get("is_similar"))]

    tmt_matched = sum(n for k, n in tmt_keys.items() if k in ai_keys)
    ai_matched = sum(n for k, n in ai_keys.items() if k in tmt_keys)
    n_tmt, n_ai = sum(tmt_keys.values()), sum(ai_keys.values())

    # Grid: data flows of the DFD (in order) x STRIDE categories.
    display = {}
    for f in flow_names:
        display.setdefault(str(f).strip().lower(), str(f).strip())
    for r in tmt_rows:
        display.setdefault(str(r.get("DataFlow") or "").strip().lower(), str(r.get("DataFlow") or "(no data flow)").strip())
    for r in ai_rows:
        display.setdefault(str(r.get("data_flow_name") or "").strip().lower(), str(r.get("data_flow_name") or "").strip())
    approved_by_key = Counter(_key(r.get("dataflow_name"), r.get("category")) for r in approved)

    columns = list(STRIDE)
    all_cats = {canonical_category(k[1]) for k in list(tmt_keys) + list(ai_keys)}
    if OTHER in all_cats:
        columns.append(OTHER)

    grid = []
    for flow_key, flow_name in display.items():
        cells = []
        for col in columns:
            keys = [k for k in set(tmt_keys) | set(ai_keys)
                    if k[0] == flow_key and canonical_category(k[1]) == col]
            m = sum(tmt_keys.get(k, 0) for k in keys)
            a = sum(ai_keys.get(k, 0) for k in keys)
            n_pairs = sum(tmt_keys.get(k, 0) * ai_keys.get(k, 0) for k in keys)
            ok = sum(approved_by_key.get(k, 0) for k in keys)
            state = "both" if n_pairs else ("tmt" if m else ("ai" if a else "none"))
            cells.append({"tmt": m, "ai": a, "pairs": n_pairs, "approved": ok, "state": state})
        if any(c["state"] != "none" for c in cells):
            grid.append({"flow": flow_name, "cells": cells})

    return {
        "threshold": threshold,
        "tmt_total": n_tmt, "tmt_matched": tmt_matched, "tmt_unmatched": n_tmt - tmt_matched,
        "ai_total": n_ai, "ai_matched": ai_matched, "ai_unmatched": n_ai - ai_matched,
        "pairs_total": len(pairs), "pairs_approved": len(approved), "pairs_rejected": len(pairs) - len(approved),
        "groups_both": sum(1 for row in grid for c in row["cells"] if c["state"] == "both"),
        # Each bar fills its own width: an empty tail on a shared scale read as a third part.
        "w_tmt_matched": _percent(tmt_matched, n_tmt), "w_tmt_unmatched": _percent(n_tmt - tmt_matched, n_tmt),
        "w_ai_matched": _percent(ai_matched, n_ai), "w_ai_unmatched": _percent(n_ai - ai_matched, n_ai),
        "w_pairs_approved": _percent(len(approved), max(len(pairs), 1)),
        "w_pairs_rejected": _percent(len(pairs) - len(approved), max(len(pairs), 1)),
        "pct_tmt_matched": round(_percent(tmt_matched, n_tmt)),
        "pct_ai_matched": round(_percent(ai_matched, n_ai)),
        "columns": [{"name": c, "short": STRIDE_SHORT.get(c, "?")} for c in columns],
        "grid": grid,
        "consistent": sum(c["pairs"] for row in grid for c in row["cells"]) == len(pairs),
    }


def coverage_tiles(rows: List[Dict], summary: List[Dict], threshold: float) -> List[Dict]:
    """
    One row of tiles (one per reference threat) for each source of a coverage run.

    Tile states: 'counted' (covered and credited), 'reused' (best score passes the
    threshold, but only through a threat already credited to another reference
    threat, so it is not counted), 'missed' (best score below the threshold).
    """
    by_source = OrderedDict()
    for r in rows:
        by_source.setdefault(r["source"], []).append(r)
    resumo = {s["source"]: s for s in summary}
    out = []
    for source, items in by_source.items():
        s = resumo.get(source, {})
        ids = s.get("covered_unique_ids")
        tiles = []
        for r in sorted(items, key=lambda x: int(x["expected_index"])):
            idx = int(r["expected_index"])
            if not r.get("covered"):
                state = "missed"
            elif ids is None or idx in ids:
                state = "counted"
            else:
                state = "reused"
            tiles.append({"index": idx, "score": float(r.get("best_score") or 0), "state": state,
                          "candidate": r.get("best_candidate") or "", "explanation": r.get("best_explanation") or ""})
        candidates = int(max([int(r.get("candidates") or 0) for r in items] + [0]))
        out.append({
            "source": source,
            "tiles": tiles,
            "counted": sum(1 for t in tiles if t["state"] == "counted"),
            "reused": sum(1 for t in tiles if t["state"] == "reused"),
            "total": len(tiles),
            "candidates": candidates,
            "judgments": candidates * len(tiles),
        })
    return out
