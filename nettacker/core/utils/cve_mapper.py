#!/usr/bin/env python3
"""
vuln_range_mapper.py

Maintains, per-product, a JSON file that maps *disjoint* version ranges to the
list of CVEs applicable in that range. New vulnerabilities (which may carry
multiple, possibly overlapping, affected-version ranges) are merged into the
existing per-product file: overlapping ranges are split at their boundaries
and the CVE sets for each resulting sub-range are unioned. Adjacent sub-ranges
that end up with an identical CVE set are re-merged so the file stays compact.

-------------------------------------------------------------------------
PURL (Package URL)
-------------------------------------------------------------------------
A mapping keyed only by a filename (e.g. nginx.json) isn't self-describing
- if the file is copied, piped, or read without its original path, nothing
in the JSON itself says what product it's about. To fix that, every
deliverable file also carries a "purl" field: a Package URL
(https://github.com/package-url/purl-spec) that unambiguously identifies
the product, e.g. "pkg:generic/nginx" or "pkg:pypi/somepypkg".

purl comes straight from the input file, per product (see INPUT FORMAT
below) - there's no separate CLI flag for it. The first time a product is
ingested, whatever purl the input specifies (or, if omitted, an
auto-generated pkg:generic/<product> default) is recorded in a hidden
sidecar file, <db_dir>/.purls.json (a simple {"product": "purl"} map).
Every later ingest reuses whatever's on record, UNLESS the input's purl
for that product disagrees with what's on record, in which case the
script refuses rather than silently changing it - edit
<db_dir>/.purls.json directly if you deliberately want to change a
product's purl.

-------------------------------------------------------------------------
VERSION SCHEMES
-------------------------------------------------------------------------
Not every product uses the same version format, and getting the ordering
wrong silently misclassifies which versions a CVE applies to. Three
schemes are supported:

  simple   (default) - separator-agnostic numeric/alpha tokenizer. Handles
             plain dotted/underscored/dashed numeric versions like
             '1.26.2', '1_26_2', 'v1.2.3'. Does NOT correctly order
             pre-release suffixes (e.g. treats '1.2.3rc1' as > '1.2.3',
             which is backwards per SemVer/PEP440 convention). No
             dependencies required.
  pep440   - uses packaging.version.Version (pip install packaging).
             Correct for Python package versions (PyPI), e.g.
             '1.0.0a1', '1.0.0.dev0', '1.0.0.post1'.
  semver   - uses the `semver` library (pip install semver). Correct
             SemVer 2.0 precedence for pre-release/build metadata, e.g.
             '1.2.3-alpha.1+build.5'.

The scheme is chosen PER PRODUCT and is NOT stored inside the deliverable
file (keeping that file's shape clean and predictable). Instead it's
recorded in a small hidden sidecar file, <db_dir>/.version_schemes.json
(a simple {"product": "scheme"} map), which the script reads/writes
automatically. Every subsequent ingest/query for a product reuses whatever
scheme is on record for it. If you try to ingest with a different
--version-scheme than what's on record, the script refuses (mixing schemes
within one product would silently corrupt the ordering).

-------------------------------------------------------------------------
STORAGE LAYOUT (one file per product)
-------------------------------------------------------------------------
<db_dir>/<product>.json      <- the deliverable file, this shape:

{
  "purl": "pkg:generic/nginx",
  "display_name": "nginx",                     // optional, from input
  "nettacker_modules": {                        // optional, from input
    "scan": ["adobe_aem_lastpatcheddate_scan"],
    "vuln": ["nginx_cve_2024_7347_vuln"]
  },
  "versions": [
    {
      "range_start": "1.0.0",
      "range_end": "1.2.3",      // null means "still unfixed / unbounded"
      "cves": [
        {"cve_id": "CVE-2024-0001"}             // "summary" included only if supplied
      ]
    },
    ...
  ]
}

<db_dir>/.version_schemes.json   <- internal only, not part of the deliverable:

{
  "nginx": "simple",
  "somepypkg": "pep440"
}

<db_dir>/.purls.json   <- internal only, not part of the deliverable:

{
  "nginx": "pkg:generic/nginx",
  "somepypkg": "pkg:pypi/somepypkg"
}

Ranges are treated as HALF-OPEN intervals: [range_start, range_end). This
matches the usual "introduced" / "fixed" convention (the "fixed" version
itself is NOT vulnerable). It also means ranges compose cleanly when split.

display_name and nettacker_modules are plain metadata, not guarded like
scheme/purl: whatever an ingest provides for them becomes the new recorded
value; omitting them on a given ingest just leaves whatever's already on
file untouched.

(Older files from earlier versions of this script - a bare JSON list,
{"version_scheme": ..., "segments": [...]}, or {"versions": [...]} without
a "purl" - are still read fine. They get migrated to the current shape,
with scheme/purl moved into their respective sidecar files, on next save.)

-------------------------------------------------------------------------
INPUT FORMAT (what you feed in when reporting new vulnerabilities)
-------------------------------------------------------------------------
{
  "nginx": {
    "display_name": "nginx",
    "purl": "pkg:generic/nginx",
    "nettacker_modules": {"scan": [], "vuln": ["nginx_cve_2024_7347_vuln"]},
    "vulnerabilities": [
      {
        "cve_id": "CVE-2024-7347",
        "ranges": [
          {"introduced": "1.5.13", "fixed": "1.26.2"},
          {"introduced": "1.27.0", "fixed": "1.27.1"}
        ]
      }
    ]
  },
  "wordpress": { ... }
}

display_name/purl/nettacker_modules are all optional on any given ingest -
provide them once and they're remembered (purl/display_name/nettacker_modules
persist as described above); omit them on a follow-up ingest that's just
adding a new CVE and the previously recorded values are kept. "summary" on
a vulnerability entry is optional too.

You only ever need to supply the *new* CVE(s) - the script reads whatever
already exists in <product>.json, does the interval overlay, and rewrites it.
If <product>.json doesn't exist yet, it's created.

-------------------------------------------------------------------------
CLI USAGE
-------------------------------------------------------------------------
Ingest new vulnerabilities:
    python3 vuln_range_mapper.py ingest --input new_vulns.json \\
        --db-dir /path/to/product/db --version-scheme simple

Query which CVEs affect a given product/version:
    python3 vuln_range_mapper.py query --product nginx --version 1.26.0 \\
        --db-dir /path/to/product/db

--db-dir is optional; if omitted, it falls back to the DEFAULT_PRODUCT_DB_DIR
constant below.

--version-scheme is optional on ingest (default: 'simple' for brand-new
products, or whatever's already recorded for existing ones) and ignored on
query (query always uses whatever scheme is recorded for the product, since
that's the only scheme the stored versions can be correctly compared with).
"""

import argparse
import functools
import json
import os
import re
from typing import List, Dict, Optional, Tuple, Any, Callable

# =========================================================================
# DEFAULT OUTPUT LOCATION - used whenever a db_dir isn't explicitly passed
# in (e.g. via --db-dir on the CLI). Change this to your preferred default,
# or just always pass --db-dir / db_dir= explicitly.
# =========================================================================
DEFAULT_PRODUCT_DB_DIR = "/var/lib/vulndb/products"

DEFAULT_VERSION_SCHEME = "simple"


# -------------------------------------------------------------------------
# A sentinel that compares greater than any real parsed version, regardless
# of which scheme produced that version - used to represent "unfixed /
# unbounded" (range_end / "fixed" == None) uniformly across all schemes.
# -------------------------------------------------------------------------
@functools.total_ordering
class _Infinity:
    def __eq__(self, other):
        return isinstance(other, _Infinity)

    def __lt__(self, other):
        return False  # infinity is never less than anything

    def __hash__(self):
        return hash("__VULN_RANGE_MAPPER_INFINITY__")

    def __repr__(self):
        return "INFINITY"


INFINITY = _Infinity()


@functools.total_ordering
class _NegativeInfinity:
    """Compares less than any real parsed version (and less than INFINITY),
    but not less than itself. Used for null 'introduced' - which means
    'vulnerable from the earliest possible version', i.e. the OPPOSITE of
    null 'fixed' (which means 'never fixed / unbounded upper end'). These
    two nulls are not interchangeable - see get_boundary_parsers()."""

    def __eq__(self, other):
        return isinstance(other, _NegativeInfinity)

    def __lt__(self, other):
        return not isinstance(other, _NegativeInfinity)

    def __hash__(self):
        return hash("__VULN_RANGE_MAPPER_NEG_INFINITY__")

    def __repr__(self):
        return "NEG_INFINITY"


NEG_INFINITY = _NegativeInfinity()


# -------------------------------------------------------------------------
# Version parsers - one per scheme. Each takes an Optional[str] and returns
# a comparable object; None always maps to INFINITY.
# -------------------------------------------------------------------------


def _parse_simple(v: Optional[str]):
    """Separator-agnostic numeric/alpha tokenizer. See module docstring."""
    if v is None:
        return INFINITY
    tokens = re.findall(r"\d+|[A-Za-z]+", v.strip())
    key = []
    for t in tokens:
        if t.isdigit():
            key.append((0, int(t)))
        else:
            key.append((1, t.lower()))
    return tuple(key)


def _parse_pep440(v: Optional[str]):
    if v is None:
        return INFINITY
    try:
        from packaging.version import Version
    except ImportError as e:
        raise ImportError(
            "version scheme 'pep440' requires the 'packaging' package: " "pip install packaging"
        ) from e
    return Version(v)


def _parse_semver(v: Optional[str]):
    if v is None:
        return INFINITY
    try:
        import semver
    except ImportError as e:
        raise ImportError(
            "version scheme 'semver' requires the 'semver' package: " "pip install semver"
        ) from e
    # optional_minor_and_patch lets '1' or '1.2' parse instead of requiring
    # strict major.minor.patch - harmless for fully-specified versions.
    return semver.Version.parse(v, optional_minor_and_patch=True)


SCHEME_PARSERS: Dict[str, Callable[[Optional[str]], Any]] = {
    "simple": _parse_simple,
    "pep440": _parse_pep440,
    "semver": _parse_semver,
}


def get_parser(scheme: str) -> Callable[[Optional[str]], Any]:
    if scheme not in SCHEME_PARSERS:
        raise ValueError(
            f"Unknown version scheme '{scheme}'. Valid options: {sorted(SCHEME_PARSERS)}"
        )
    return SCHEME_PARSERS[scheme]


def get_boundary_parsers(
    scheme: str,
) -> Tuple[Callable[[Optional[str]], Any], Callable[[Optional[str]], Any]]:
    """Returns (parse_start, parse_end): the same underlying version parser,
    but with null resolved correctly depending on which side of a range it's
    on. null 'introduced' (start) means 'earliest possible version' -> less
    than everything. null 'fixed' (end) means 'never fixed / unbounded' ->
    greater than everything. These are NOT the same value, so a range's
    start and end must always be parsed with the matching one of these two,
    never with the raw per-scheme parser directly."""
    base = get_parser(scheme)

    def parse_start(v: Optional[str]):
        return NEG_INFINITY if v is None else base(v)

    def parse_end(v: Optional[str]):
        return base(v)  # base() already resolves None -> INFINITY correctly

    return parse_start, parse_end


def fmt_version(v: Optional[str]) -> str:
    return "unfixed" if v is None else v


# -------------------------------------------------------------------------
# Data model helpers
# -------------------------------------------------------------------------

SCHEME_REGISTRY_FILENAME = ".version_schemes.json"
PURL_REGISTRY_FILENAME = ".purls.json"


def product_path(product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> str:
    safe_name = product.strip().lower().replace("/", "_")
    return os.path.join(db_dir, f"{safe_name}.json")


def default_purl(product: str) -> str:
    """Best-effort default PURL for a product with no recorded/override PURL.
    Falls back to the 'generic' PURL type since we don't know the actual
    package ecosystem (pypi, npm, deb, etc.) just from a bare product name."""
    safe_name = product.strip().lower().replace(" ", "-")
    return f"pkg:generic/{safe_name}"


def _scheme_registry_path(db_dir: str) -> str:
    return os.path.join(db_dir, SCHEME_REGISTRY_FILENAME)


def _purl_registry_path(db_dir: str) -> str:
    return os.path.join(db_dir, PURL_REGISTRY_FILENAME)


def load_scheme_registry(db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> Dict[str, str]:
    path = _scheme_registry_path(db_dir)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def save_scheme_registry(registry: Dict[str, str], db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> None:
    os.makedirs(db_dir, exist_ok=True)
    with open(_scheme_registry_path(db_dir), "w") as f:
        json.dump(registry, f, indent=2, sort_keys=True)


def load_purl_registry(db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> Dict[str, str]:
    path = _purl_registry_path(db_dir)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def save_purl_registry(registry: Dict[str, str], db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> None:
    os.makedirs(db_dir, exist_ok=True)
    with open(_purl_registry_path(db_dir), "w") as f:
        json.dump(registry, f, indent=2, sort_keys=True)


def get_purl(
    product: str,
    db_dir: str = DEFAULT_PRODUCT_DB_DIR,
    override: Optional[str] = None,
    embedded_purl: Optional[str] = None,
) -> str:
    """Resolve the PURL to use for `product`, recording it in the sidecar
    registry the first time. `override` is an explicit --purl request;
    `embedded_purl` is whatever was already inside an older product file
    (for migration). Raises if `override` conflicts with what's on record."""
    registry = load_purl_registry(db_dir)

    if product in registry:
        recorded = registry[product]
        if override is not None and override != recorded:
            raise ValueError(
                f"Product '{product}' already has PURL '{recorded}' on record, "
                f"but '{override}' was requested for this ingest. Refusing to "
                f"change a product's PURL silently - re-run without --purl to "
                f"reuse '{recorded}', or edit {_purl_registry_path(db_dir)} directly "
                f"if you deliberately want to change it."
            )
        return recorded

    resolved = override or embedded_purl or default_purl(product)
    registry[product] = resolved
    save_purl_registry(registry, db_dir)
    return resolved


def load_product_file(
    product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR
) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """Returns (version_scheme, segments). version_scheme is None only when
    this is a genuinely brand-new product (no file, no registry entry)."""
    path = product_path(product, db_dir)
    registry = load_scheme_registry(db_dir)
    file_exists = os.path.exists(path)

    if not file_exists and product not in registry:
        return None, []

    segments: List[Dict[str, Any]] = []
    embedded_scheme: Optional[str] = None

    if file_exists:
        with open(path, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            # Oldest format: a bare list of segments.
            segments = data
        elif isinstance(data, dict):
            if "versions" in data:
                segments = data["versions"]
            elif "segments" in data:
                # Intermediate format that embedded the scheme in-file.
                segments = data["segments"]
            embedded_scheme = data.get("version_scheme")

    scheme = registry.get(product) or embedded_scheme or DEFAULT_VERSION_SCHEME
    return scheme, segments


def _load_embedded_purl(product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> Optional[str]:
    """Pull a 'purl' out of an existing product file, if present, for
    migration purposes only (a file written by this version of the script
    never needs this - the registry is authoritative going forward)."""
    path = product_path(product, db_dir)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("purl")
    return None


def _load_raw_existing(product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> Dict[str, Any]:
    """Raw dict of whatever's currently on disk for this product, or {} if
    there's no file yet or it's the legacy bare-list format. Used only to
    preserve metadata fields (display_name, nettacker_modules) across ingests
    that don't repeat them."""
    path = product_path(product, db_dir)
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def save_product_file(
    product: str,
    scheme: str,
    segments: List[Dict[str, Any]],
    db_dir: str = DEFAULT_PRODUCT_DB_DIR,
    purl_override: Optional[str] = None,
    display_name: Optional[str] = None,
    nettacker_modules: Optional[Dict[str, List[str]]] = None,
) -> str:
    os.makedirs(db_dir, exist_ok=True)
    path = product_path(product, db_dir)
    parse_start, _parse_end = get_boundary_parsers(scheme)
    segments_sorted = sorted(segments, key=lambda s: parse_start(s["range_start"]))

    purl = get_purl(
        product,
        db_dir,
        override=purl_override,
        embedded_purl=_load_embedded_purl(product, db_dir),
    )

    # display_name/nettacker_modules are ordinary product metadata (unlike
    # scheme/purl, nothing guards against them changing): use what this
    # ingest provided, else keep whatever was already on file, else omit.
    existing = _load_raw_existing(product, db_dir)
    effective_display_name = (
        display_name if display_name is not None else existing.get("display_name")
    )
    effective_modules = (
        nettacker_modules if nettacker_modules is not None else existing.get("nettacker_modules")
    )

    # The deliverable file: purl + optional display_name/nettacker_modules +
    # versions - matching the Nettacker mapping-file structure exactly.
    out: Dict[str, Any] = {"purl": purl}
    if effective_display_name is not None:
        out["display_name"] = effective_display_name
    if effective_modules is not None:
        out["nettacker_modules"] = effective_modules
    out["versions"] = segments_sorted

    with open(path, "w") as f:
        json.dump(out, f, indent=2)

    # Scheme bookkeeping lives in the sidecar registry, not in the file.
    registry = load_scheme_registry(db_dir)
    registry[product] = scheme
    save_scheme_registry(registry, db_dir)

    return path


def ranges_overlap(
    s1,
    e1,
    s2,
    e2,
    parse_start: Callable[[Optional[str]], Any],
    parse_end: Callable[[Optional[str]], Any],
) -> bool:
    """Half-open interval overlap test: [s1,e1) vs [s2,e2)."""
    return parse_start(s1) < parse_end(e2) and parse_start(s2) < parse_end(e1)


# -------------------------------------------------------------------------
# Core merge algorithm
# -------------------------------------------------------------------------


def merge_vulnerability_into_segments(
    existing_segments: List[Dict[str, Any]],
    new_cve: Dict[str, Any],
    new_ranges: List[Dict[str, Optional[str]]],
    scheme: str,
) -> List[Dict[str, Any]]:
    """
    Overlay `new_ranges` (all belonging to `new_cve`) onto `existing_segments`
    and return the resulting, still-disjoint, segment list. `scheme`
    determines version ordering (i.e. which parser is in effect); start and
    end boundaries are parsed differently (see get_boundary_parsers) so that
    a null 'introduced' and a null 'fixed' are never confused with each other.
    """
    parse_start, parse_end = get_boundary_parsers(scheme)

    new_cve_entry: Dict[str, Any] = {"cve_id": new_cve["cve_id"]}
    if new_cve.get("summary"):
        new_cve_entry["summary"] = new_cve["summary"]

    # Normalize new ranges to (start, end) pairs.
    norm_new_ranges = [(r.get("introduced"), r.get("fixed")) for r in new_ranges]

    # Split existing segments into those untouched by any new range, and
    # those that overlap and therefore need to be recomputed.
    untouched = []
    touched = []
    for seg in existing_segments:
        overlaps_any = any(
            ranges_overlap(seg["range_start"], seg["range_end"], ns, ne, parse_start, parse_end)
            for ns, ne in norm_new_ranges
        )
        (touched if overlaps_any else untouched).append(seg)

    # Build the list of "sources" to overlay: touched existing segments +
    # all new ranges (each carrying their own cve set).
    sources: List[Tuple[Optional[str], Optional[str], List[Dict[str, Any]]]] = []
    for seg in touched:
        sources.append((seg["range_start"], seg["range_end"], seg["cves"]))
    for ns, ne in norm_new_ranges:
        sources.append((ns, ne, [new_cve_entry]))

    if not sources:
        sources = [(ns, ne, [new_cve_entry]) for ns, ne in norm_new_ranges]

    # Collect all boundary points among the sources. Each source's `s` is
    # always a start position and `e` is always an end position - parse
    # them with the matching function, never interchangeably.
    boundary_points = set()
    for s, e, _ in sources:
        boundary_points.add(parse_start(s))
        boundary_points.add(parse_end(e))
    sorted_points = sorted(boundary_points)

    # For each minimal interval between consecutive boundary points,
    # determine the union of CVEs whose source range covers it.
    raw_pieces: List[Tuple[Any, Any, Dict[str, Dict[str, Any]]]] = []
    for i in range(len(sorted_points) - 1):
        lo, hi = sorted_points[i], sorted_points[i + 1]
        if lo == hi:
            continue
        cve_map: Dict[str, Dict[str, Any]] = {}
        for s, e, cves in sources:
            s_key, e_key = parse_start(s), parse_end(e)
            if s_key <= lo and hi <= e_key:
                for c in cves:
                    cve_map[c["cve_id"]] = c
        if cve_map:
            raw_pieces.append((lo, hi, cve_map))

    # Merge adjacent minimal pieces that share an identical CVE set.
    merged_touched_region: List[Dict[str, Any]] = []
    for lo, hi, cve_map in raw_pieces:
        cve_ids = frozenset(cve_map.keys())
        if (
            merged_touched_region
            and merged_touched_region[-1]["_end_key"] == lo
            and merged_touched_region[-1]["_cve_ids"] == cve_ids
        ):
            merged_touched_region[-1]["_end_key"] = hi
        else:
            merged_touched_region.append(
                {"_start_key": lo, "_end_key": hi, "_cve_ids": cve_ids, "_cve_map": cve_map}
            )

    # Convert internal keys back to the original string representations.
    key_to_str: Dict[Any, Optional[str]] = {}
    for s, e, _ in sources:
        key_to_str[parse_start(s)] = s
        key_to_str[parse_end(e)] = e

    final_touched_segments = []
    for piece in merged_touched_region:
        start_str = key_to_str.get(piece["_start_key"])
        end_str = key_to_str.get(piece["_end_key"])
        final_touched_segments.append(
            {
                "range_start": start_str,
                "range_end": end_str,
                "cves": sorted(piece["_cve_map"].values(), key=lambda c: c["cve_id"]),
            }
        )

    result = untouched + final_touched_segments

    # Final pass: merge any adjacent segments (touched/untouched boundary)
    # that happen to share an identical CVE set, for a compact file.
    result.sort(key=lambda s: parse_start(s["range_start"]))
    compacted: List[Dict[str, Any]] = []
    for seg in result:
        if compacted:
            prev = compacted[-1]
            prev_ids = {c["cve_id"] for c in prev["cves"]}
            cur_ids = {c["cve_id"] for c in seg["cves"]}
            if (
                parse_end(prev["range_end"]) == parse_start(seg["range_start"])
                and prev_ids == cur_ids
            ):
                prev["range_end"] = seg["range_end"]
                continue
        compacted.append(dict(seg))

    return compacted


def ingest_vulnerability(
    product: str,
    cve: Dict[str, Any],
    db_dir: str = DEFAULT_PRODUCT_DB_DIR,
    version_scheme: Optional[str] = None,
    purl: Optional[str] = None,
    display_name: Optional[str] = None,
    nettacker_modules: Optional[Dict[str, List[str]]] = None,
) -> str:
    """Load, merge, save. Returns the path written. `cve` must have
    'cve_id' and 'ranges' (a list of {"introduced":..., "fixed":...}).

    `version_scheme` is only used to pick the scheme for a BRAND-NEW
    product file. For an existing product, the scheme already recorded in
    its file is used, and if `version_scheme` is given and disagrees, this
    raises rather than silently mixing schemes. `purl` behaves the same way
    with respect to the product's recorded Package URL. `display_name` and
    `nettacker_modules` are plain metadata: whatever's passed here becomes
    the new recorded value; omit them to leave whatever's already on file
    untouched."""
    existing_scheme, existing_segments = load_product_file(product, db_dir)

    if existing_scheme is None:
        effective_scheme = version_scheme or DEFAULT_VERSION_SCHEME
    else:
        effective_scheme = existing_scheme
        if version_scheme is not None and version_scheme != existing_scheme:
            raise ValueError(
                f"Product '{product}' already uses version scheme '{existing_scheme}', "
                f"but '{version_scheme}' was requested for this ingest. Refusing to mix "
                f"version schemes within one product - re-run without --version-scheme "
                f"to reuse '{existing_scheme}', or migrate the file deliberately first."
            )

    updated = merge_vulnerability_into_segments(
        existing_segments, cve, cve["ranges"], effective_scheme
    )
    return save_product_file(
        product,
        effective_scheme,
        updated,
        db_dir,
        purl_override=purl,
        display_name=display_name,
        nettacker_modules=nettacker_modules,
    )


def ingest_file(
    input_path: str,
    db_dir: str = DEFAULT_PRODUCT_DB_DIR,
    version_scheme: Optional[str] = None,
) -> None:
    """Ingest a file shaped like:

    {
      "<product>": {
        "display_name": "...",
        "purl": "pkg:...",
        "nettacker_modules": {"scan": [...], "vuln": [...]},
        "vulnerabilities": [
          {"cve_id": "CVE-...", "ranges": [{"introduced": ..., "fixed": ...}, ...]},
          ...
        ]
      },
      ...
    }

    purl/display_name/nettacker_modules are read per-product from the input
    itself - there's no separate --purl flag needed, since the input already
    carries this per product rather than once for the whole file."""
    with open(input_path, "r") as f:
        payload = json.load(f)

    for product, info in payload.items():
        purl = info.get("purl")
        display_name = info.get("display_name")
        nettacker_modules = info.get("nettacker_modules")
        for cve in info.get("vulnerabilities", []):
            path = ingest_vulnerability(
                product,
                cve,
                db_dir,
                version_scheme,
                purl=purl,
                display_name=display_name,
                nettacker_modules=nettacker_modules,
            )
            print(f"[ok] {cve['cve_id']} merged into {path}")


# -------------------------------------------------------------------------
# Query
# -------------------------------------------------------------------------


def query_version(
    product: str, version: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR
) -> List[Dict[str, Any]]:
    scheme, segments = load_product_file(product, db_dir)
    if scheme is None:
        return []
    base = get_parser(scheme)
    parse_start, parse_end = get_boundary_parsers(scheme)
    v_key = base(version)  # the queried version is always a concrete value, never null
    hits = []
    for seg in segments:
        if parse_start(seg["range_start"]) <= v_key < parse_end(seg["range_end"]):
            hits.extend(seg["cves"])
    return hits


# -------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Product version-range -> CVE mapper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Ingest new vulnerabilities from a JSON file")
    p_ingest.add_argument("--input", required=True, help="Path to input JSON file")
    p_ingest.add_argument(
        "--db-dir",
        default=DEFAULT_PRODUCT_DB_DIR,
        help=f"Directory holding per-product JSON files (default: {DEFAULT_PRODUCT_DB_DIR})",
    )
    p_ingest.add_argument(
        "--version-scheme",
        choices=sorted(SCHEME_PARSERS),
        default=None,
        help=(
            "Version comparison scheme to use for BRAND-NEW products "
            f"(default: {DEFAULT_VERSION_SCHEME}). Ignored for products that "
            "already have a file - their recorded scheme is always used, "
            "and a mismatch here raises an error instead of mixing schemes."
        ),
    )

    p_query = sub.add_parser("query", help="List CVEs affecting product@version")
    p_query.add_argument("--product", required=True)
    p_query.add_argument("--version", required=True)
    p_query.add_argument(
        "--db-dir",
        default=DEFAULT_PRODUCT_DB_DIR,
        help=f"Directory holding per-product JSON files (default: {DEFAULT_PRODUCT_DB_DIR})",
    )

    args = parser.parse_args()

    if args.cmd == "ingest":
        ingest_file(args.input, args.db_dir, args.version_scheme)
    elif args.cmd == "query":
        hits = query_version(args.product, args.version, args.db_dir)
        if not hits:
            print(f"No known vulnerabilities for {args.product}@{args.version}")
        else:
            print(f"{args.product}@{args.version} is affected by:")
            for c in hits:
                label = f" - {c.get('summary')}" if c.get("summary") else ""
                print(f"  - {c['cve_id']}{label}")


if __name__ == "__main__":
    main()
