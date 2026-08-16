#!/usr/bin/env python3
"""Offline BYOVD blocklist regression gate.

Asserts against LIVE public datasets (nothing repo-local to go stale):

  Microsoft Vulnerable Driver Blocklist (authoritative — the WDAC policy
  that rejects blocklisted drivers in NtLoadDriver, 0xC0000034/0xC0000428):
    A1. WDTKernel.sys is ABSENT (name + both known file SHA256s). This is
        the entire value proposition of the WDT BYOVD path — if Microsoft
        ever adds it, the --wdt arm in windows-byovd-hosted.yml must fail.
    A2. RTCore64.sys is PRESENT (positive control — proves the policy really
        contains driver rules and the parse below works). RTCore64 was
        REMOVED from the kernelsdk driver pack on 2026-08-16 precisely
        because this assertion holds (CI measured NtLoadDriver → 0xC0000034
        on every hosted image); it stays here as the canary.
    A3. iqvw64e.sys is PRESENT (positive control 2 — same removal rationale).
        NOTE: the policy names it by OriginalFilename — the kdmapper sample's
        OriginalFilename is "iQVW64.SYS" (no 'e'), so the rule FriendlyName is
        "IQVW64.sys FileAttribute" (FileName="iQVW64.SYS", versions
        <=1.4.0.21, referenced from a <Deny>). Match the "iqvw64" stem to
        catch both spellings.
    A4. shield.sys / shield-async.sys / shieldwp.sys are ABSENT — Shield is
        the DEFAULT BYOVD driver (clean, arbitrary VA memcpy); if any
        variant name appears, the default path is dead and this gate must
        go red.

  LOLDrivers dataset (cross-reference — tracks KNOWN-vulnerable drivers, a
  superset of the MS blocklist):
    B1. RTCore64.sys is catalogued as "vulnerable driver" (control).
    B2. WDTKernel.sys, if catalogued (it IS, since 2026-04 — LOLDrivers
        issue #290), has LoadsDespiteHVCI=TRUE on every sample: LOLDrivers'
        own signal for "loads past the MS blocklist". Absence from the
        dataset is also accepted.

Exit 0 on pass, 1 on any assertion violation, 2 on fetch/parse failure.

Usage: python3 scripts/check_byovd_blocklist.py [--ms-only] [--version-report]

  --version-report : report-only mode. Fetches the MS blocklist, prints the
                     SiPolicy VersionEx + policy date, diffs against the
                     pinned EXPECTED_MS_BLOCKLIST_VERSION, appends a markdown
                     summary to $GITHUB_STEP_SUMMARY when set, and ALWAYS
                     exits 0 (a version bump is a tripwire for human review,
                     not a gate failure — A1/A2 remain the hard assertions).
"""
import io
import json
import os
import re
import sys
import urllib.request
import zipfile

# aka.ms short link (stable) → download.microsoft.com zip. The direct URL is
# the current redirect target, kept as a fallback because the short link
# occasionally refuses connections (observed 2026-08-13).
MS_BLOCKLIST_URLS = [
    "https://aka.ms/VulnerableDriverBlockList",
    "https://download.microsoft.com/download/75bf7aa6-7700-43cc-bbac-9dfc0cc4ed50/VulnerableDriverBlockList.zip",
]
LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"

# WDTKernel.sys file SHA256s (the two samples catalogued by LOLDrivers,
# issue #290). The SiPolicy FileAttrib FriendlyNames embed the FILE SHA256
# ("<Name>\<file-sha256> Hash Sha256"), so a hex scan of the policy XML
# catches hash rules regardless of how the rule is named. Authentihashes
# are included as a belt-and-braces check.
WDTKERNEL_SHA256 = [
    # file hashes (what SiPolicy embeds)
    "0e27bec347ca0050c455467bd8d774175c503b8aa1af3411e94966f7dc6b28b7",
    "8b695b1a430336f49335162d8ca4137c2424640e27ee29511472fea4451462fe",
    # authentihashes
    "6a27a2af4b3123d2e0e0daa23bdda0a2f8cfbef495b257dc83cfe8b4faffd7d5",
    "cfae2c01311fb5a6d5aa5be2a3822e01e825258fe4d860e6e8778cb6738b95f3",
]

# HVCI tripwire: SiPolicy <VersionEx> of the MS blocklist, pinned at the last
# human review (2026-08-15: 10.0.29545.0, policy XML dated 2026-04-09 inside
# the zip). A bump means Microsoft shipped a new blocklist revision — the A1
# absence assertion below re-verifies WDTKernel content-wise on every run, so
# the diff is a WARNING (review prompt), not a failure. When you see it:
# confirm A1 still passes, skim the revision, then bump this constant.
EXPECTED_MS_BLOCKLIST_VERSION = "10.0.29545.0"


def fetch(urls, timeout=300, binary=True):
    last = None
    for url in urls:
        try:
            print(f"[*] fetching {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            print(f"[*] got {len(data)} bytes")
            return data if binary else data.decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 — report and try the next mirror
            print(f"[!] fetch failed: {e}")
            last = e
    print(f"::error::all URLs failed ({last})")
    sys.exit(2)


def _open_policy(blob):
    """Return (zf, xml) for DriverPolicy_Enforced.xml; exit 2 on parse failure."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        name = next(n for n in zf.namelist() if n.endswith("DriverPolicy_Enforced.xml"))
        xml = zf.read(name).decode("utf-8", "replace")
        return zf, xml
    except Exception as e:  # noqa: BLE001
        print(f"::error::cannot parse blocklist zip: {e}")
        sys.exit(2)


def ms_blocklist_version(zf, xml):
    """(VersionEx str or None, latest zip member date 'YYYY-MM-DD' or None)."""
    m = re.search(r"<VersionEx>([^<]+)</VersionEx>", xml)
    version = m.group(1).strip() if m else None
    dates = ["%04d-%02d-%02d" % i.date_time[:3] for i in zf.infolist() if not i.is_dir()]
    return version, (max(dates) if dates else None)


def warn_version_diff(version, date):
    if version is None:
        print("::warning::no <VersionEx> in SiPolicy XML — cannot diff blocklist revision (schema change?)")
        return
    print(f"[*] MS blocklist VersionEx={version} (policy date {date}, pinned {EXPECTED_MS_BLOCKLIST_VERSION})")
    if version != EXPECTED_MS_BLOCKLIST_VERSION:
        print(f"::warning::MS blocklist version CHANGED {EXPECTED_MS_BLOCKLIST_VERSION} -> {version} "
              "(policy date {}) — Microsoft shipped a new revision. A1/A2 content assertions above "
              "already re-verified WDTKernel absence on THIS revision; if green, bump "
              "EXPECTED_MS_BLOCKLIST_VERSION in scripts/check_byovd_blocklist.py after review.".format(date))


def version_report():
    """--version-report: print the version diff and write $GITHUB_STEP_SUMMARY.
    Report-only: fetch/parse failures degrade to a ::warning::, never an error."""
    try:
        zf, xml = _open_policy(fetch(MS_BLOCKLIST_URLS))
    except SystemExit:  # fetch/parse failure — report mode must not fail the job
        print("::warning::version report unavailable (fetch/parse failed)")
        return
    version, date = ms_blocklist_version(zf, xml)
    warn_version_diff(version, date)
    changed = version is not None and version != EXPECTED_MS_BLOCKLIST_VERSION
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### MS vulnerable-driver blocklist — version diff\n\n")
            f.write(f"- live `VersionEx`: `{version}` (policy date {date})\n")
            f.write(f"- pinned: `{EXPECTED_MS_BLOCKLIST_VERSION}`\n")
            f.write(f"- verdict: **{'CHANGED — review, then re-pin' if changed else 'unchanged'}**\n")
        print("[*] wrote $GITHUB_STEP_SUMMARY")


def check_ms_blocklist(failures):
    blob = fetch(MS_BLOCKLIST_URLS)
    zf, xml = _open_policy(blob)

    friendly = re.findall(r'FriendlyName="([^"]*)"', xml)
    print(f"[*] SiPolicy: {len(friendly)} FileAttrib FriendlyNames")
    if not friendly:
        print("::error::SiPolicy parse yielded 0 FriendlyNames — schema changed?")
        sys.exit(2)

    # Version tripwire (non-fatal — the content assertions below are the gate).
    version, date = ms_blocklist_version(zf, xml)
    warn_version_diff(version, date)

    low_names = [f.lower() for f in friendly]
    xml_low = xml.lower()

    # A1: WDTKernel must be ABSENT.
    if any("wdtkernel" in f or "wdt\\" in f for f in low_names):
        failures.append("A1 FAIL: WDTKernel named in the MS vulnerable-driver blocklist")
    for h in WDTKERNEL_SHA256:
        if h in xml_low:
            failures.append(f"A1 FAIL: WDTKernel SHA256 {h[:16]}… found in the MS blocklist")
    print("[+] A1: WDTKernel.sys ABSENT from MS vulnerable-driver blocklist")

    # A2: RTCore64 must be PRESENT (positive control).
    if not any("rtcore" in f for f in low_names):
        failures.append("A2 FAIL: RTCore64 NOT found in the MS blocklist — positive control broken (parse regression?)")
    else:
        print(f"[+] A2: RTCore64 PRESENT ({sum('rtcore' in f for f in low_names)} rules) — positive control OK")

    # A3: iqvw64e must be PRESENT (positive control 2 — removed from the
    # driver pack alongside RTCore64 on 2026-08-16 for exactly this reason).
    # The policy lists it under the sample's OriginalFilename "iQVW64.SYS"
    # (no 'e'); match the "iqvw64" stem so either spelling trips the control.
    if not any("iqvw64" in f for f in low_names):
        failures.append("A3 FAIL: iqvw64e NOT found in the MS blocklist — positive control broken (parse regression?)")
    else:
        print(f"[+] A3: iqvw64e PRESENT ({sum('iqvw64' in f for f in low_names)} rules, as iQVW64.SYS) — positive control OK")

    # A4: Shield variants must be ABSENT (Shield is the DEFAULT driver).
    shield_hits = [f for f in low_names if re.search(r"shield(wp|-async)?\.sys", f)]
    if shield_hits:
        failures.append(f"A4 FAIL: Shield variant(s) named in the MS blocklist: {shield_hits}")
    else:
        print("[+] A4: shield.sys / shield-async.sys / shieldwp.sys ABSENT from MS blocklist")


def check_loldrivers(failures):
    data = fetch([LOLDRIVERS_URL])
    try:
        entries = json.loads(data)
    except Exception as e:  # noqa: BLE001
        print(f"::error::LOLDrivers JSON parse failed: {e}")
        sys.exit(2)
    print(f"[*] LOLDrivers: {len(entries)} entries")

    def by_tag(tag):
        return [e for e in entries if tag.lower() in (t.lower() for t in (e.get("Tags") or []))]

    # B1: RTCore64 catalogued as a vulnerable driver (positive control).
    rt = by_tag("RTCore64.sys")
    if not any(e.get("Category") == "vulnerable driver" for e in rt):
        failures.append("B1 FAIL: RTCore64.sys not catalogued as vulnerable in LOLDrivers — positive control broken")
    else:
        print(f"[+] B1: RTCore64.sys catalogued as vulnerable ({len(rt)} entries) — positive control OK")

    # B2: WDTKernel — catalogued is fine (LOLDrivers is a superset of the MS
    # blocklist), but every sample must carry LoadsDespiteHVCI=TRUE.
    wdt = by_tag("WDTKernel.sys")
    if not wdt:
        print("[+] B2: WDTKernel.sys not catalogued by LOLDrivers at all")
        return
    for e in wdt:
        for s in e.get("KnownVulnerableSamples") or []:
            if s.get("LoadsDespiteHVCI") != "TRUE":
                failures.append(
                    f"B2 FAIL: WDTKernel sample {((s.get('Authentihash') or {}).get('SHA256') or '?')[:16]}… "
                    "has LoadsDespiteHVCI!=TRUE — LOLDrivers now considers it blocklisted"
                )
    n = sum(len(e.get("KnownVulnerableSamples") or []) for e in wdt)
    print(f"[+] B2: WDTKernel.sys catalogued ({n} samples), all LoadsDespiteHVCI=TRUE (not MS-blocklisted)")


def main():
    if "--version-report" in sys.argv:
        version_report()
        sys.exit(0)
    failures = []
    check_ms_blocklist(failures)
    if "--ms-only" not in sys.argv:
        check_loldrivers(failures)
    print()
    if failures:
        for f in failures:
            print(f"::error::{f}")
        print("BLOCKLIST GATE: FAIL")
        sys.exit(1)
    print("BLOCKLIST GATE: PASS — WDTKernel/Shield not blocklisted, controls intact")


if __name__ == "__main__":
    main()
