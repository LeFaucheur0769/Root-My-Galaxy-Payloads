# e1s-S921BXXUHEZIF

```text
device: Samsung Galaxy S24 (SM-S921B, e1s, Exynos 2400)
firmware: S921BXXUHEZIF / EUX (OXM multi-CSC)
display build: CP2A.260605.016.S921BXXUHEZIF
fingerprint: samsung/e1sxeea/e1s:17/CP2A.260605.016/S921BXXUHEZIF:user/release-keys
kernel: 6.1.162-android14-11
kernel build: #1 SMP PREEMPT Sat Sep 19 08:06:47 UTC 2026, clang 17.0.2 +pgo +bolt +lto
raw kernel SHA-256: see README in the port workspace
```

Profile for the Android 17 / `CP2A.260605.016` build of the S24. It is a
sibling of `e1s-S921BXXSFDZF2` (6.1.157) and keeps that profile's exploit
variant (`APP_PHYS_P0_ORACLE`, full `rt_mutex_waiter` fake layout, four-slot
slide bank). Every firmware-dependent constant was re-derived from this
build's own Image; none were copied.

## Provenance

Offline, from the downloaded AP archive only (no rooted device):

1. `samloader-rs` fetch of `S921BXXUHEZIF/S921BOXMHEZIF/S921BXXUHEZIF/S921BXXUHEZIF`.
2. `boot.img` from the AP tar, `lz4` + `magiskboot unpack`, kernel extracted
   with the header `kernel_size` at `0x08` (38832640 bytes).
3. Raw `.BTF` carved from the Image (validated header, bounds, string NUL) and
   merged into the `vmlinux-to-elf` reconstruction with `llvm-objcopy`.
4. Symbol offsets from the reconstructed symbol table, layout values from BTF
   via `pahole --hex`, both cross-checked with
   `tools/verify_target_profile.py`.

## Derived values that are easy to get wrong

| Value | This build | Note |
| --- | ---: | --- |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `0x022f2808` | `struct nf_logger`, qword 0 is the name pointer |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x016dfad0` | target of that pointer, `"nfnetlink_log"` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `0x0243ef60` | `random_table[4]` (`boot_id`) `.data` field |
| `SLIDE_SYSCTL_BOOTID_OFF` | `0x026d1ba0` | real `sysctl_bootid` storage, restored after the read |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `0x000dbeb8` | `worker_thread+0xa0`, instruction after `bl schedule` |
| `SLIDE_TRACEFS_EVENT_ID` | `106` | `__TRACE_LAST_TYPE(20)` + zero-based index 86 |
| `ASHMEM_MISC_FOPS_OFF` | `0x02484d80` | `ashmem_miscs + offsetof(miscdevice, fops)`; no `ashmem_misc` symbol exists in this build, the slot was located by finding the qword equal to `ashmem_fops` |
| `SELINUX_ENFORCING_OFF` | `0x025ea4a8` | `selinux_state.enforcing`, `struct selinux_state` starts at 0 |

`P0_ORACLE_PROBE_OFFSET` stays `0x1f0000`: the Image has the same
`image_size` (`0x27c0000`) and `text_offset` (0) as the DZF2 build, and the
generated table was verified against all 256 source qwords.

## Layout equality with the DZF2 profile

BTF confirms identical offsets for every structure the payload touches:
`task_struct` (usage `0x40`, prio `0x84`, normal_prio `0x8c`,
sched_task_group `0x348`, pi_lock `0x924`, pi_waiters `0x938`,
pi_top_task `0x948`, pi_blocked_on `0x950`), `rt_mutex_waiter` (`0x58`),
`struct page` (`0x40`), `struct slab` (slab_cache `0x18`), `work_struct`,
`subprocess_info` (`0x70`), `pipe_buffer` (`0x28`), `pipe_buf_operations`
(`0x20`), `file_operations` (`0x110`) and `miscdevice` (fops `0x10`).

## Items that need device confirmation

These are not recoverable from the Image and are carried over from the
sibling profile; each fails closed rather than guessing:

- `SLIDE_PSELECT_WORD_SHIFT` = 0. Correct for the 6.1 Samsung pselect stack
  shape used by this variant; the `3` seen in `e1s-S921BXXSFDZE1` belongs to
  that profile's superseded compact-waiter layout, not to the kernel build.
- `SKB_DATA_DELTA` = `-0xe80`, the 6.1 family value (also the `common.h`
  default).
- `P0_KERNEL_PHYS_LOAD` = `0x80000000`. The Image reports `text_offset == 0`
  and the S24 bootloader adds `0x80000000`; unchanged across e1s builds.

Run `tools/verify_target_profile.py e1s-S921BXXUHEZIF <vmlinux.elf> <System.map> <raw kernel>`
after any change; it re-derives each symbol delta, each layout offset and all
32 P0 rows.

## Config notes that affect the endgame

- `CONFIG_STATIC_USERMODEHELPER=y` with an empty
  `CONFIG_STATIC_USERMODEHELPER_PATH`, so `modprobe_path` is a dead end:
  `call_usermodehelper_setup()` overwrites `sub_info->path` with the empty
  string and `call_usermodehelper_exec()` bails on `strlen(path) == 0`.
  The only live route is the hand-built `subprocess_info` queued on
  `system_unbound_wq` with `work.func = call_usermodehelper_exec_work`
  (`exec_work` does not re-check the path), which is what `root.c` does.
- `RKP=y`, `KNOX_NCM=y`, `CFI_CLANG=y`, `SHADOW_CALL_STACK=y`,
  `ARM64_PTR_AUTH=y`, `KASAN_HW_TAGS=y`, `SLAB_FREELIST_HARDENED=y`,
  `INIT_ON_ALLOC_DEFAULT_ON=y`. The runtime cmdline has no `kasan=off`;
  heap tag checks are live, stack memory is not tagged.

## Status

Offline-verified (67/67 profile checks, P0 table byte-exact). Not yet run on
hardware.
