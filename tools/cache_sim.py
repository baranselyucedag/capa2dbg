"""Offline simulation of the capa2dbg cache validation logic.

Mirrors CacheLookup() from src/capa_cache.cpp so the rules can be tested on the
host without a debugger or a real sample.

Usage:
    python tools\\cache_sim.py                 # run the self-test
    python tools\\cache_sim.py <file> [capa]   # hash a file and print its meta
"""

import hashlib
import json
import os
import sys
import tempfile

SCHEMA = 1
CHUNK = 1024 * 1024


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def stamp(path):
    """(size, mtime) pair used to detect a changed capa.exe."""
    if not path or not os.path.isfile(path):
        return (0, 0)
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns)


def build_meta(target, capa_exe, capa_version, json_size, source="capa_run"):
    tsize, tmtime = stamp(target)
    csize, cmtime = stamp(capa_exe)
    return {
        "schema": SCHEMA,
        "target_path": target,
        "target_size": tsize,
        "target_mtime": tmtime,
        "target_sha256": sha256_file(target),
        "capa_exe": capa_exe or "",
        "capa_exe_size": csize,
        "capa_exe_mtime": cmtime,
        "capa_version": capa_version,
        "json_size": json_size,
        "created_utc": "1970-01-01T00:00:00Z",
        "plugin_version": 2,
        "source": source,
    }


def lookup(meta, sha, capa_exe, json_text):
    """Returns 'HIT' or a 'STALE: <reason>' string."""
    if not isinstance(meta, dict):
        return "STALE: meta bozuk"
    if meta.get("schema") != SCHEMA:
        return "STALE: schema farkli"
    if meta.get("target_sha256") != sha:
        return "STALE: sha uyusmuyor"

    meta_capa = meta.get("capa_exe", "")
    if meta_capa:
        csize, cmtime = stamp(capa_exe)
        if capa_exe and csize:
            if (csize, cmtime) != (meta.get("capa_exe_size"), meta.get("capa_exe_mtime")):
                return "STALE: capa.exe degisti"
    if not json_text or not json_text.startswith("{"):
        return "STALE: json bozuk"
    return "HIT"


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "sample.exe")
        capa = os.path.join(tmp, "capa.exe")
        with open(target, "wb") as f:
            f.write(b"MZ" + b"\x00" * 4096)
        with open(capa, "wb") as f:
            f.write(b"capa-v1")

        payload = json.dumps({"meta": {"version": "9.4.0"}, "rules": {}})
        sha = sha256_file(target)
        meta = build_meta(target, capa, "9.4.0", len(payload))

        assert lookup(meta, sha, capa, payload) == "HIT", "fresh entry must hit"
        print("ok: fresh entry -> HIT")

        # Same bytes, different name: hash key still matches.
        copy = os.path.join(tmp, "renamed.bin")
        with open(copy, "wb") as f:
            f.write(open(target, "rb").read())
        assert sha256_file(copy) == sha
        print("ok: renamed copy -> same sha (HIT)")

        # capa.exe rebuilt -> stale.
        with open(capa, "wb") as f:
            f.write(b"capa-v2-larger")
        res = lookup(meta, sha, capa, payload)
        assert res.startswith("STALE"), res
        print("ok: capa.exe changed -> " + res)

        # Patched sample -> different sha, so the key never collides.
        with open(target, "ab") as f:
            f.write(b"patched")
        assert sha256_file(target) != sha
        print("ok: patched sample -> different sha (MISS)")

        # Corrupt payload is rejected even if the meta looks fine.
        meta2 = build_meta(target, capa, "9.4.0", 5)
        res = lookup(meta2, sha256_file(target), capa, "ERROR: no such file")
        assert res.startswith("STALE"), res
        print("ok: non-JSON payload -> " + res)

        # Adopted entries carry no capa.exe stamp and stay valid.
        adopted = build_meta(target, "", "", len(payload), "capa_load_adopted")
        assert lookup(adopted, sha256_file(target), capa, payload) == "HIT"
        print("ok: adopted entry (empty capa_exe) -> HIT")

        # Schema bump invalidates old entries.
        old = dict(meta)
        old["schema"] = 0
        assert lookup(old, sha, capa, payload).startswith("STALE")
        print("ok: schema mismatch -> STALE")

    print("ALL CACHE SIM CHECKS PASSED")


def main():
    if len(sys.argv) < 2:
        self_test()
        return 0

    target = sys.argv[1]
    capa = sys.argv[2] if len(sys.argv) > 2 else ""
    if not os.path.isfile(target):
        print("not a file: " + target)
        return 1

    meta = build_meta(target, capa, "?", 0)
    print(json.dumps(meta, indent=2))
    print("cache file: " + meta["target_sha256"] + ".json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
