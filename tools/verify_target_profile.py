#!/usr/bin/env python3
"""Verify a Root My Galaxy target profile against a recovered vmlinux.

Checks that every symbol-derived macro in
src/targets/<profile>/target.h equals (symbol - _text) in the supplied
System.map, that size/layout macros match the target BTF, and that the
P0 fingerprint table reproduces the raw Image byte for byte.

usage: verify_target_profile.py PROFILE VMLINUX_ELF SYSTEM_MAP RAW_KERNEL
       [--header PATH] [--p0 PATH]
"""

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

BASE_RE = re.compile(r"^#define\s+KIMAGE_TEXT_BASE\s+(0x[0-9a-fA-F]+)", re.M)
DEF_RE = re.compile(r"^#define\s+([A-Z0-9_]+)\s+\(?\s*(0x[0-9a-fA-F]+|\d+)", re.M)

# macro -> symbol name (None: derived, handled explicitly)
SYMBOL_MACROS = {
    "ASHMEM_FOPS_OFF": "ashmem_fops",
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF": "ashmem_mmap",
    "ASHMEM_OPEN_OFF": "ashmem_open",
    "ASHMEM_RELEASE_OFF": "ashmem_release",
    "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
    "CONFIGFS_READ_ITER_OFF": "configfs_read_iter",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
    "COPY_SPLICE_READ_OFF": "generic_file_splice_read",
    "NOOP_LLSEEK_OFF": "noop_llseek",
    "INIT_TASK_OFF": "init_task",
    "ROOT_TASK_GROUP_OFF": "root_task_group",
    "SELINUX_ENFORCING_OFF": "selinux_state",
    "KMALLOC_CACHES_OFF": "kmalloc_caches",
    "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
    "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
    "SLIDE_NFULNL_LOGGER_OBJECT_OFF": "nfulnl_logger",
    "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
}

# layout macro -> (pahole type, member)
LAYOUT_MACROS = {
    "FAKE_TASK_USAGE_OFF": ("task_struct", "usage"),
    "FAKE_TASK_PRIO_OFF": ("task_struct", "prio"),
    "FAKE_TASK_NORMAL_PRIO_OFF": ("task_struct", "normal_prio"),
    "FAKE_TASK_TASK_GROUP_OFF": ("task_struct", "sched_task_group"),
    "FAKE_TASK_PI_LOCK_OFF": ("task_struct", "pi_lock"),
    "FAKE_TASK_PI_WAITERS_OFF": ("task_struct", "pi_waiters"),
    "FAKE_TASK_PI_TOP_TASK_OFF": ("task_struct", "pi_top_task"),
    "FAKE_TASK_PI_BLOCKED_ON_OFF": ("task_struct", "pi_blocked_on"),
    "STRUCT_PAGE_COMPOUND_HEAD_OFF": ("page", "compound_head"),
    "STRUCT_SLAB_CACHE_OFF": ("slab", "slab_cache"),
    "STRUCT_PAGE_TYPE_OFF": ("page", "page_type"),
    "WORK_DATA_OFF": ("work_struct", "data"),
    "WORK_ENTRY_OFF": ("work_struct", "entry"),
    "WORK_FUNC_OFF": ("work_struct", "func"),
    "PIPE_BUF_FLAG_CAN_MERGE": (None, None),  # constant, not layout
}

SIZE_MACROS = {
    "STRUCT_PAGE_SIZE": ("page", 0x40),
}


def parse_defines(text):
    out = {}
    for name, ref in re.findall(r"^#define\s+([A-Z0-9_]+)\s+([A-Z][A-Z0-9_]+)\s*$", text, re.M):
        out.setdefault("__alias__" + name, ref)
    for name, val in DEF_RE.findall(text):
        out[name] = int(val, 16) if val.lower().startswith("0x") else int(val)
    return out


def resolve(defines, name, seen=None):
    if name in defines:
        return defines[name]
    alias = defines.get("__alias__" + name)
    seen = seen or set()
    if alias and alias not in seen:
        seen.add(alias)
        return resolve(defines, alias, seen)
    return None


def load_symbols(path):
    syms = {}
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            syms[parts[1]] = int(parts[0], 16)
        elif len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
    return syms


def pahole_members(elf, typename):
    try:
        out = subprocess.run(
            ["pahole", "-C", typename, "--hex", str(elf)],
            capture_output=True, text=True, check=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"pahole failed for {typename}: {exc}")
    members = {}
    size = None
    m = re.search(r"/\*\s*size:\s*(\d+)", out)
    if m:
        size = int(m.group(1))
    for line in out.splitlines():
        mm = re.match(r"\s+.*\b([A-Za-z_]\w*)\s*;\s*/\*\s*(0x[0-9a-f]+|\d+)", line)
        if mm:
            members[mm.group(1)] = int(mm.group(2), 0)
        fm = re.match(r"\s+.*\(\s*\*\s*([A-Za-z_]\w*)\s*\)", line)
        if fm and fm.group(1) not in members:
            off = re.search(r"/\*\s*(0x[0-9a-f]+|\d+)", line)
            if off:
                members[fm.group(1)] = int(off.group(1), 0)
    return members, size


def check_p0(header_text, p0_text, raw):
    rows = re.findall(
        r"\{\s*(0x[0-9a-fA-F]+)ULL,\s*\{(.*?)\}\s*\}", p0_text, re.S)
    if not rows:
        return [("P0 table", False, "no rows parsed")]
    probe_match = re.search(
        r"#define\s+P0_ORACLE_PROBE_OFFSET\s+(0x[0-9a-fA-F]+)", header_text)
    if not probe_match:
        return [("P0 probe", False, "P0_ORACLE_PROBE_OFFSET missing")]
    probe = int(probe_match.group(1), 16)
    results = []
    for slide_s, body in rows:
        slide = int(slide_s, 16)
        words = [int(w, 16) for w in re.findall(r"0x([0-9a-fA-F]+)ULL", body)]
        if len(words) != 8:
            results.append((f"P0 slide {slide:#x}", False, "expected 8 words"))
            continue
        src = probe - slide
        if src < 0 or src + 0xe08 > len(raw):
            results.append((f"P0 slide {slide:#x}", False, "source out of range"))
            continue
        ok = all(struct.unpack_from("<Q", raw, src + i * 0x200)[0] == words[i]
                 for i in range(8))
        results.append((f"P0 slide {slide:#x}", ok, "" if ok else "word mismatch"))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("profile")
    ap.add_argument("vmlinux")
    ap.add_argument("system_map")
    ap.add_argument("raw_kernel")
    ap.add_argument("--header")
    ap.add_argument("--p0")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    header = Path(args.header or root / "src/targets" / args.profile / "target.h")
    p0 = Path(args.p0 or root / "src/targets" / args.profile / "p0_fingerprint.h")
    text = header.read_text()
    defines = parse_defines(text)

    base_m = BASE_RE.search(text)
    if not base_m:
        raise SystemExit("KIMAGE_TEXT_BASE not found")
    base = int(base_m.group(1), 16)
    syms = load_symbols(args.system_map)
    if "_text" not in syms:
        raise SystemExit("System.map has no _text")
    # vmlinux-to-elf may anchor _text differently than the link-time symbol
    # table; require agreement, otherwise every delta below is wrong.
    if syms["_text"] != base:
        raise SystemExit(
            f"KIMAGE_TEXT_BASE {base:#x} != _text {syms['_text']:#x}")

    results = []
    for macro, symbol in SYMBOL_MACROS.items():
        if macro not in defines and resolve(defines, macro) is None:
            results.append((macro, False, "macro missing"))
            continue
        if symbol not in syms:
            results.append((macro, False, f"symbol {symbol} missing"))
            continue
        want = syms[symbol] - base
        got = resolve(defines, macro)
        results.append((macro, want == got,
                        "" if want == got else f"want {want:#x} got {got:#x}"))

    members, size = {}, {}
    for typename in {t for t, _ in LAYOUT_MACROS.values() if t}:
        m, s = pahole_members(args.vmlinux, typename)
        members[typename] = m
        size[typename] = s

    for macro, (typename, member) in LAYOUT_MACROS.items():
        if typename is None:
            continue
        got = resolve(defines, macro)
        if got is None:
            results.append((macro, False, "macro missing"))
            continue
        want = members.get(typename, {}).get(member)
        if want is None:
            results.append((macro, False, f"{typename}.{member} not in BTF"))
            continue
        results.append((macro, want == got,
                        "" if want == got else f"want {want:#x} got {got:#x}"))

    for macro, (typename, want) in SIZE_MACROS.items():
        got = defines.get(macro)
        actual = size.get(typename)
        ok = got == want == actual
        results.append((macro, ok, "" if ok else
                        f"want {want:#x} header {got} sizeof {actual}"))

    if p0.exists():
        results += check_p0(text, p0.read_text(), Path(args.raw_kernel).read_bytes())
    else:
        results.append(("p0_fingerprint.h", False, "file missing"))

    failed = [r for r in results if not r[1]]
    width = max(len(r[0]) for r in results)
    for name, ok, note in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {note}")
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
