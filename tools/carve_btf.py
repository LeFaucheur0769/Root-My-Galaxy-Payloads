#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
carve_btf.py -- pull the .BTF type blob out of a raw kernel Image.

Why this exists: `pahole -F btf` needs a BTF blob, and the usual way to get
one is /sys/kernel/btf/vmlinux on a rooted device. The boot Image itself
contains the same .BTF section (CONFIG_DEBUG_INFO_BTF embeds it in vmlinux,
and arch/arm64/boot/Image is an objcopy of vmlinux), so a plain firmware
download is enough. No root, no device.

The Image has no section headers, so we scan for the BTF header magic
(0xeb9f, little endian -> bytes 9f eb), validate the header, and cut
hdr_len + max(type_off+type_len, str_off+str_len) bytes.

usage:
  carve_btf.py kernel -o vmlinux.btf
  carve_btf.py --list Image.gz          # show every candidate and its size
  carve_btf.py --selftest

Wire format (include/uapi/linux/btf.h):
  struct btf_header {
      __u16 magic;    __u8 version;  __u8 flags;
      __u32 hdr_len;  __u32 type_off; __u32 type_len;
      __u32 str_off;  __u32 str_len;
  };
Offsets in the header are relative to the END of the header, not to the
start of the blob.
"""

import argparse
import gzip
import os
import struct
import sys

MAGIC = b"\x9f\xeb"
HDR = struct.Struct("<HBBIIIII")  # 24 bytes
HDR_LEN_MIN, HDR_LEN_MAX = 24, 64


def _lz4_decompress(data):
    try:
        import lz4.frame
        return lz4.frame.decompress(data)
    except Exception:
        import subprocess
        p = subprocess.run(["lz4", "-d", "-c"], input=data,
                           stdout=subprocess.PIPE, check=True)
        return p.stdout


def maybe_decompress(data):
    """Handle the containers Samsung ships around a kernel Image."""
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data), "gzip"
    if data[:4] == b"\x04\x22\x4d\x18":
        return _lz4_decompress(data), "lz4"
    if data[:4] == b"\x02\x21\x4c\x18":          # legacy lz4 frame
        import subprocess
        p = subprocess.run(["lz4", "-d", "-c", "-l"], input=data,
                           stdout=subprocess.PIPE, check=True)
        return p.stdout, "lz4-legacy"
    if data[:6] == b"\xfd7zXZ\x00":
        import lzma
        return lzma.decompress(data), "xz"
    if data[:4] == b"\x28\xb5\x2f\xfd":
        import zstandard
        return zstandard.ZstdDecompressor().decompress(data), "zstd"
    return data, "none"


def candidates(buf):
    """Yield (offset, total_size, details) for every plausible BTF blob."""
    pos = 0
    while True:
        pos = buf.find(MAGIC, pos)
        if pos < 0 or pos + HDR.size > len(buf):
            return
        if pos % 4 == 0 and buf.startswith(MAGIC, pos):
            try:
                magic, version, flags, hdr_len, toff, tlen, soff, slen = \
                    HDR.unpack_from(buf, pos)
            except struct.error:
                return
            if (magic == 0xeb9f and version == 1
                    and HDR_LEN_MIN <= hdr_len <= HDR_LEN_MAX
                    and tlen > 0 and slen > 0 and slen < (1 << 28)
                    and (tlen % 4) == 0):
                total = hdr_len + max(toff + tlen, soff + slen)
                if total <= len(buf) - pos:
                    # first string of the string section must be the empty one
                    if buf[pos + hdr_len + soff] == 0:
                        yield pos, total, dict(hdr_len=hdr_len,
                                               type_len=tlen, str_len=slen)
        pos += 4


def carve(buf, index=0):
    for i, (off, total, info) in enumerate(candidates(buf)):
        if i == index:
            return off, total, info
    raise SystemExit("[-] no BTF blob found in input")


def selftest():
    body = bytearray()
    body += struct.pack("<I", 1)                 # fake type entry
    body += struct.pack("<I", 0)                 # padding to 4-byte align
    strings = b"\x00int\x00task_struct\x00" + b"\x00" * 3
    hdr_len = 24
    toff, tlen = 0, len(body)
    soff, slen = (tlen + 3) & ~3, len(strings)
    blob = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, hdr_len,
                       toff, tlen, soff, slen) + bytes(body) + strings
    fake = b"\x00" * 0x1000 + blob + b"\x00" * 0x400
    off, total, info = carve(fake)
    assert off == 0x1000, off
    assert total == len(blob), (total, len(blob))
    assert info["type_len"] == len(body)
    print("[+] selftest OK (offset 0x%x, %d bytes)" % (off, total))


def main():
    ap = argparse.ArgumentParser(
        description="carve the .BTF type blob out of a raw kernel Image")
    ap.add_argument("image", nargs="?")
    ap.add_argument("-o", "--out", default="vmlinux.btf")
    ap.add_argument("--list", action="store_true",
                    help="list candidates, do not write")
    ap.add_argument("--index", type=int, default=0,
                    help="which candidate to take (default 0 = first)")
    ap.add_argument("--raw", action="store_true",
                    help="do not decompress the input")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.image:
        ap.error("an image path is required")
    if not os.path.exists(args.image):
        print(f"[-] no such file: {args.image}", file=sys.stderr)
        return 2

    data = open(args.image, "rb").read()
    if not args.raw:
        try:
            data, how = maybe_decompress(data)
        except Exception as e:
            print(f"[-] decompression failed ({e}); try --raw", file=sys.stderr)
            return 2
        print(f"[*] container: {how}, {len(data)} bytes", file=sys.stderr)

    found = list(candidates(data))
    if not found:
        print("[-] no BTF header found. Either CONFIG_DEBUG_INFO_BTF is off "
              "for this build, or the Image is still compressed (try --raw "
              "on the decompressed file).", file=sys.stderr)
        return 3

    if args.list:
        for i, (off, total, info) in enumerate(found):
            print(f"  [{i}] file offset 0x{off:08x}  size {total:8d}  "
                  f"types {info['type_len']:8d}  str {info['str_len']:8d}")
        return 0

    off, total, info = carve(data, args.index)
    with open(args.out, "wb") as fh:
        fh.write(data[off:off + total])
    print(f"[+] wrote {args.out}: {total} bytes from 0x{off:x} "
          f"(type_len={info['type_len']}, str_len={info['str_len']})",
          file=sys.stderr)
    print(f"[+] next: pahole -F btf -C task_struct --hex {args.out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
