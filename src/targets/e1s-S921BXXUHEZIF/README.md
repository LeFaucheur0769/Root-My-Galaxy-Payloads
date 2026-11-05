# e1s-S921BXXUHEZIF

```text
device: Samsung Galaxy S24 (SM-S921B, e1s, Exynos 2400)
firmware: S921BXXUHEZIF / EUX (OXM multi-CSC)
display build: CP2A.260605.016.S921BXXUHEZIF
fingerprint: samsung/e1sxeea/e1s:17/CP2A.260605.016/S921BXXUHEZIF:user/release-keys
kernel: 6.1.162-android14-11
kernel build: #1 SMP PREEMPT Sat Sep 19 08:06:47 UTC 2026, clang 17.0.2 +pgo +bolt +lto
raw kernel SHA-256: ca8e9199ccfb7d12561a18ffdf38346c681da44da7ee1b722d0ee5f611f94f91
```

Profile for the Android 17 / `CP2A.260605.016` build of the S24. It is a new
6.1.162 Image, not a derivative of `e1s-S921BXXSFDZF2` (6.1.157), so every
symbol and layout was re-derived from this build's own kernel, BTF and
`System.map`. The exploit variant is `APP_PHYS_P0_ORACLE` with the compact
`rt_mutex_waiter` layout (`0x58`), a five-slot slide bank
(`SLIDE_BANK_TASK_OFF 0x3200`, production slot `4`) and the compact-family
P0-oracle geometry. `KMALLOC_CGROUP_TYPE 1` / `KMALLOC_CACHE_TYPES 3` come
from this build's own `kmalloc_cache_type` enum and `kmalloc_caches` bounds.

## Provenance

Offline, from the downloaded AP archive only (no rooted device):

1. `samloader-rs` fetch of `S921BXXUHEZIF/S921BOXMHEZIF/S921BXXUHEZIF/S921BXXUHEZIF`
   (archive SHA-256 `0150f11a...`).
2. `boot.img` from the AP tar, `lz4 -d` + `magiskboot unpack`, raw kernel
   extracted as `boot/kernel` (38,832,640 bytes).
3. `.BTF` carved at kernel file offset `0x188f4e8` (5,998,391 bytes).
4. `vmlinux-to-elf` recovered 115,739 symbols at `_text = 0xffffffc008000000`;
   `System.map` written from the same table.
5. `tools/verify_target_profile.py` reports `67/67 checks passed`, including all
   32 P0 fingerprint rows.

## Status and open items

Hardware-untested. The symbol constants are provable from the shipped Image;
the physical load address (`0x80000000`) and the compact-family runtime
geometry (`SLIDE_PSELECT_WORD_SHIFT 3`, `SKB_DATA_DELTA -0x1000`,
`MM_STRUCT_SZ 0x400`) are inherited from device-validated profiles and are
marked unverified for this build. The HEZIF `sboot.bin` differs from the
DZE1/DZDR/ZF2 blob and its handoff is indirect, so the physical-load proof has
not been reproduced locally.

Full derivation, the HEZIF-vs-DZE1 delta table and the mitigation matrix are in
[`docs/SM-S921B-S921BXXUHEZIF.md`](../../../docs/SM-S921B-S921BXXUHEZIF.md).
