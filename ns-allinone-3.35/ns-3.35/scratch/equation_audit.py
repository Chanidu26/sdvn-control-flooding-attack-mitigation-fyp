#!/usr/bin/env python3
"""
Equation & Algorithm Presence Audit
------------------------------------
Builds the full catalog of equations and algorithms directly from the
thesis LaTeX source (doc/latex.tex) -- not the PDF, since chapter-scoped
equation numbering (report class default: "chapter.n") is only reliably
recovered from the source, and cross-references each one against the
implementation source files (routing.cc, ppmds_baseline.h,
edcf_inference_api.py, edcf_api.go, ...) looking for a matching
"Eq X.Y" / "Algorithm N" citation comment.

PASS   = the concept is implemented somewhere in source -- either an exact
       "Eq X.Y" / "Algorithm N" citation matching the CURRENT LaTeX
       numbering was found (strong evidence), or every keyword token
       derived from the equation's LaTeX \\label (e.g. eq:rep_update ->
       "rep","update") -- or a manually curated alias -- was found
       together on one line somewhere (weaker evidence: the concept looks
       implemented, but either the citation number is stale, written
       against an earlier draft of the report before equations were
       inserted/reordered, or was never annotated with a number at all).
       Both tiers print as PASS; the evidence shown on the line (exact
       citation vs. matched keywords vs. manual alias) tells you which.
FAIL   = neither an exact number nor the concept's keywords/aliases were
       found anywhere -- a real candidate "specified but not implemented"
       gap.

IMPORTANT CAVEAT this script surfaced on itself: equation numbers cited
in the code are NOT guaranteed to match the CURRENT report numbering.
Example -- edcf_api.go comments "Eq 3.23" for the reputation-decay
update, but that equation is eq:rep_update, which is Eq 3.33 in the
current doc/latex.tex (a +10 drift versus the rest of the smart-contract
section, i.e. ~10 equations were inserted/reordered upstream of it after
that code was written). A pure exact-number match would wrongly report
that as FAIL. The keyword/alias fallback exists specifically to catch
this class of false negative -- a PASS backed only by matched keywords or
a manual alias (visible in the line's parenthetical) is "probably
implemented, re-check the citation number", not a clean bill of health.

This is a presence/traceability check only (does *something* exist in
code for this concept), not a correctness check (whether it's right).

Usage:
    python3 equation_audit.py
    python3 equation_audit.py --tex /path/to/latex.tex
"""
import argparse
import re
import sys
from pathlib import Path

SCRATCH_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRATCH_DIR.parents[2]  # .../control-flooding-g14
DEFAULT_TEX = PROJECT_ROOT / "doc" / "latex.tex"

TRAINING_DIR = PROJECT_ROOT / "edcf_traning"

SOURCE_FILES = [
    SCRATCH_DIR / "routing.cc",
    *sorted(SCRATCH_DIR.glob("*.h")),
    *sorted(SCRATCH_DIR.glob("*.cc")),
    *sorted(TRAINING_DIR.glob("*.py")),
    PROJECT_ROOT / "ns-allinone-3.35" / "edcf-blockchain-api" / "edcf_api.go",
]
# de-dupe while preserving order (routing.cc would otherwise appear twice
# via the *.cc glob)
_seen = set()
SOURCE_FILES = [f for f in SOURCE_FILES if not (f in _seen or _seen.add(f))]

# Generic tokens that appear in tons of unrelated lines -- requiring them
# alone would make WEAK PASS meaningless (near-100% match rate).
_STOPWORDS = {"eq", "state", "set", "score", "load", "path", "rule",
              "net", "score", "feat", "update", "th"}

# Manual concept aliases -- for equations whose LaTeX label vocabulary does
# NOT overlap with the implementation's identifier vocabulary at all (so no
# tokenizer can bridge them automatically), verified by hand against the
# actual source. Each value is a list of alternative substrings; a match on
# ANY one counts (OR, not AND -- these are direct synonym links, not
# decomposed keyword fragments). This is exactly what a manual traceability
# audit maintains by hand; encoding it here keeps that verification work
# reproducible instead of living only in a chat transcript.
#
# eq:hoeffding_bound is a proof, not runtime code -- its alias points at the
# threshold mechanism the bound is a guarantee ABOUT (edcf_v2_homomorphic_
# mitigation's Sj >= ceil(theta*Nj) check), not an "implementation" of the
# bound itself. eq:raw_attn/spatial_embed/gru_cand are standard GAT/GRU
# math delegated to PyTorch(Geometric) library calls, never hand-derived in
# this codebase, so their alias points at the library call site.
MANUAL_ALIASES = {
    "eq:sc_state":       ["Isolated", "EVT_ISOLATION", "StableWindows"],
    "eq:flowrule":       ["FlowRevocation", "EVT_FLOW_REVOKE", "triggerFlowRevocation"],
    "eq:hoeffding_bound": ["EDCF_V2_THETA", "threshold_met"],
    "eq:raw_attn":       ["GATConv"],
    "eq:spatial_embed":  ["GATConv"],
    "eq:gru_cand":       ["nn.GRU", "GRUCell"],
    "eq:llm_finetune":   ["fine_tune_model", "SFTTrainer", "Trainer("],
}

LABEL_RE   = re.compile(r'\\label\{(eq:[a-zA-Z0-9_]+)\}')
CHAPTER_RE = re.compile(r'\\chapter\{([^}]*)\}')
ALG_BEGIN_RE = re.compile(r'\\begin\{algorithm\}')
CAPTION_RE   = re.compile(r'\\caption\{([^}]*(?:\{[^}]*\}[^}]*)*)\}')

_LATEX_NOISE = re.compile(r'\\ref\{[^}]*\}|\\label\{[^}]*\}')


def clean_desc(line: str) -> str:
    line = _LATEX_NOISE.sub("", line)
    line = line.replace("~", " ").strip()
    return line[:100]


def parse_equation_catalog(tex_path: Path):
    """Chapter-scoped equation numbering, matching LaTeX 'report' class
    default (\\theequation = chapter.number), which is what the code
    comments actually cite ("Eq 3.11", "Eq 3.72", ...)."""
    lines = tex_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    chapter = 0
    eq_counter = 0
    catalog = []
    for i, line in enumerate(lines):
        m = CHAPTER_RE.search(line)
        if m:
            chapter += 1
            eq_counter = 0
            continue
        m = LABEL_RE.search(line)
        if m:
            eq_counter += 1
            desc = ""
            for j in range(i - 1, max(i - 15, 0), -1):
                cand = lines[j].strip()
                if cand and not cand.startswith("\\begin") and not cand.startswith("\\end") \
                        and not re.match(r'^[\\%]', cand):
                    desc = clean_desc(cand)
                    if desc and not desc.lower().startswith("equation"):
                        break
                    if not desc:
                        continue
            catalog.append({
                "kind": "Eq",
                "number": f"{chapter}.{eq_counter}",
                "label": m.group(1),
                "desc": desc,
                "line": i + 1,
            })
    return catalog


def parse_algorithm_catalog(tex_path: Path):
    """Algorithm environments use a single document-wide counter (the
    algorithm package's default), matching the "Algorithm 1..4" citations
    seen in code comments."""
    lines = tex_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    counter = 0
    catalog = []
    for i, line in enumerate(lines):
        if ALG_BEGIN_RE.search(line):
            counter += 1
            caption = ""
            for j in range(i + 1, min(i + 6, len(lines))):
                cm = CAPTION_RE.search(lines[j])
                if cm:
                    caption = clean_desc(cm.group(1))
                    break
            catalog.append({
                "kind": "Algorithm",
                "number": str(counter),
                "label": f"algorithm:{counter}",
                "desc": caption,
                "line": i + 1,
            })
    return catalog


def load_source_cache(files):
    cache = {}
    for f in files:
        if not f.exists():
            continue
        try:
            cache[f] = f.read_text(errors="ignore").splitlines()
        except OSError:
            continue
    return cache


def find_exact_citation(kind: str, number: str, label: str, cache):
    """Returns list of (file, line_no, line_text) citing this Eq/Algorithm,
    either by its exact CURRENT-numbering citation string ("Eq 3.28") OR
    by its LaTeX label name directly ("Eq tx_obs") -- both styles are used
    interchangeably in this codebase's comments (e.g. routing.cc:139503
    says "Eq tx_obs", never "Eq 3.28"), so a number-only matcher silently
    misses every label-style citation."""
    if kind == "Eq":
        base_pat = re.compile(r'\bEq\.?\s?' + re.escape(number) + r'\b')
        ch, n = number.split(".")
        range_pat = re.compile(r'\bEq\.?\s?(\d+)\.(\d+)\s*-\s*(\d+)\b')
        label_suffix = label[3:] if label.startswith("eq:") else None
        label_pat = re.compile(r'\bEq\.?\s?' + re.escape(label_suffix) + r'\b') if label_suffix else None
    else:
        base_pat = re.compile(r'\bAlgorithm\s+' + re.escape(number) + r'\b', re.IGNORECASE)
        range_pat = None
        label_pat = None

    hits = []
    for f, lines in cache.items():
        for i, line in enumerate(lines, start=1):
            if base_pat.search(line) or (label_pat and label_pat.search(line)):
                hits.append((f, i, line.strip()))
                continue
            if range_pat and kind == "Eq":
                for rm in range_pat.finditer(line):
                    if rm.group(1) == ch and int(rm.group(2)) <= int(n) <= int(rm.group(3)):
                        hits.append((f, i, line.strip()))
                        break
    return hits


def label_keywords(label: str):
    """eq:rep_update -> ['rep','update']; algorithm:2 -> [] (no fallback
    for algorithms, their captions are matched separately)."""
    if not label.startswith("eq:"):
        return []
    tokens = re.split(r'[_\d]+', label[3:])
    return [t for t in tokens if len(t) >= 3 and t.lower() not in _STOPWORDS]


def find_keyword_matches(label: str, cache):
    """Fallback for when the exact citation number doesn't hit anywhere:
    require every non-stopword token from the LaTeX \\label to appear
    together on the same line, case-insensitive. Catches implementations
    whose comments cite a stale/pre-revision equation number, or never
    cited a number at all -- at the cost of being a weaker signal than an
    exact citation match."""
    tokens = label_keywords(label)
    if not tokens:
        return []
    pats = [re.compile(re.escape(t), re.IGNORECASE) for t in tokens]
    hits = []
    for f, lines in cache.items():
        for i, line in enumerate(lines, start=1):
            if all(p.search(line) for p in pats):
                hits.append((f, i, line.strip()))
    return hits


def find_alias_matches(label: str, cache):
    """Last-resort tier: manually curated synonym list (MANUAL_ALIASES)
    for labels whose report vocabulary doesn't overlap the implementation's
    naming at all. Any ONE alias hitting counts (OR)."""
    aliases = MANUAL_ALIASES.get(label)
    if not aliases:
        return []
    pats = [re.compile(re.escape(a)) for a in aliases]  # case-sensitive: these are real identifiers
    hits = []
    for f, lines in cache.items():
        for i, line in enumerate(lines, start=1):
            if any(p.search(line) for p in pats):
                hits.append((f, i, line.strip()))
    return hits


def sort_key(item):
    kind_order = 0 if item["kind"] == "Eq" else 1
    parts = item["number"].split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    return (kind_order, major, minor)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tex", type=Path, default=DEFAULT_TEX,
                     help=f"Path to the thesis LaTeX source (default: {DEFAULT_TEX})")
    ap.add_argument("--log", type=Path, default=SCRATCH_DIR / "equation_audit.log",
                     help="Where to write the audit log (default: scratch/equation_audit.log)")
    ap.add_argument("-v", "--verbose", action="store_true",
                     help="Show the description text for every item, not just failures")
    args = ap.parse_args()

    if not args.tex.exists():
        sys.exit(f"[FATAL] LaTeX source not found: {args.tex}")

    print(f"[equation_audit] LaTeX source : {args.tex}")
    found_files = [f for f in SOURCE_FILES if f.exists()]
    print(f"[equation_audit] Impl sources : {len(found_files)}/{len(SOURCE_FILES)} files found")
    for f in [f for f in SOURCE_FILES if not f.exists()]:
        print(f"[equation_audit]   (missing, skipped: {f})")
    print()

    catalog = parse_equation_catalog(args.tex) + parse_algorithm_catalog(args.tex)
    catalog.sort(key=sort_key)

    if not catalog:
        sys.exit("[FATAL] No \\label{eq:...} or \\begin{algorithm} found -- wrong file?")

    cache = load_source_cache(SOURCE_FILES)

    log_lines = []
    passed = failed = 0
    fails = []
    for item in catalog:
        tag = f"{item['kind']} {item['number']}"
        hits = find_exact_citation(item["kind"], item["number"], item["label"], cache)
        if hits:
            passed += 1
            loc = hits[0]
            extra = f" (+{len(hits)-1} more)" if len(hits) > 1 else ""
            msg = f"[PASS]   {tag:<14} {item['label']:<24} -> {loc[0].name}:{loc[1]}{extra}"
        else:
            khits = find_keyword_matches(item["label"], cache) if item["kind"] == "Eq" else []
            if khits:
                passed += 1
                loc = khits[0]
                extra = f" (+{len(khits)-1} more)" if len(khits) > 1 else ""
                kw = ", ".join(label_keywords(item["label"]))
                msg = f"[PASS]   {tag:<14} {item['label']:<24} -> {loc[0].name}:{loc[1]} (matched keywords: {kw}){extra}"
            else:
                ahits = find_alias_matches(item["label"], cache) if item["kind"] == "Eq" else []
                if ahits:
                    passed += 1
                    loc = ahits[0]
                    extra = f" (+{len(ahits)-1} more)" if len(ahits) > 1 else ""
                    al = ", ".join(MANUAL_ALIASES.get(item["label"], []))
                    msg = f"[PASS]   {tag:<14} {item['label']:<24} -> {loc[0].name}:{loc[1]} (manual alias: {al}){extra}"
                else:
                    failed += 1
                    msg = f"[FAILED] {tag:<14} {item['label']:<24} -> NOT found (exact, keyword, or alias) in any source file"
                    fails.append(item)
        if args.verbose and item["desc"]:
            msg += f"\n              \"{item['desc']}\""
        print(msg)
        log_lines.append(msg)

    total = passed + failed
    if failed == 0:
        summary = (f"\n{'='*78}\n"
                   f"Equation/Algorithm presence audit: ALL {total} PASSED\n"
                   f"{'='*78}")
    else:
        summary = (f"\n{'='*78}\n"
                   f"Equation/Algorithm presence audit: {passed} PASSED, "
                   f"{failed} FAILED  (of {total})\n"
                   f"{'='*78}")
    print(summary)
    log_lines.append(summary)

    if fails:
        fail_list = "\nFAILED items (specified in report, no matching citation, concept keywords, " \
                     "or alias found anywhere):\n" + \
            "\n".join(f"  - {i['kind']} {i['number']} ({i['label']}): {i['desc']}" for i in fails)
        print(fail_list)
        log_lines.append(fail_list)

    args.log.write_text("\n".join(log_lines) + "\n")
    print(f"\n[equation_audit] Full log written to: {args.log}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
