/*
 * vm_probe_loader_win.c
 *
 * Probe payload for VM-protected loader entry points.
 * Targeted for injection at 0x140290A10 in Prospect.Client.Loader.exe.
 *
 * It logs argument registers and appends raw snapshots to disk:
 *   C:\vm_probe_log.txt      (human-readable register log)
 *   C:\vm_probe_ctx.bin      (raw ctx_t records, appended)
 *   C:\vm_probe_records.bin  (header + dumped buffers, appended)
 */
#include "bpatch_rt.h"

typedef struct {
    u64 tag;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u32 len2;
    u32 len3;
} snap_hdr_t;

static int is_user_ptr(u64 p) {
    return (p > 0x10000ULL) && (p < 0x0000800000000000ULL);
}

void payload() {
    char log_path[] = "C:\\vm_probe_log.txt";
    char ctx_path[] = "C:\\vm_probe_ctx.bin";
    char rec_path[] = "C:\\vm_probe_records.bin";
    char sep[] = "---\n";

    u64 a1 = ARG1;  /* rcx */
    u64 a2 = ARG2;  /* rdx */
    u64 a3 = ARG3;  /* r8  */
    u64 a4 = ARG4;  /* r9  */

    /* Heuristic: if arg1 looks like a sane length, use it for arg2 dump. */
    u32 len2 = (a1 > 0 && a1 <= 0x4000ULL) ? (u32)a1 : 0x200U;
    u32 len3 = 0x200U;

    dump_str_append(sep, log_path);
    LOG_REG("arg1(rcx)", a1, log_path);
    LOG_REG("arg2(rdx)", a2, log_path);
    LOG_REG("arg3(r8)",  a3, log_path);
    LOG_REG("arg4(r9)",  a4, log_path);

    dump_append(ctx, (u32)sizeof(ctx_t), ctx_path);

    snap_hdr_t h;
    h.tag  = 0x5653504E41500001ULL; /* "VSPNAP" + version */
    h.arg1 = a1;
    h.arg2 = a2;
    h.arg3 = a3;
    h.arg4 = a4;
    h.len2 = is_user_ptr(a2) ? len2 : 0U;
    h.len3 = is_user_ptr(a3) ? len3 : 0U;

    dump_append(&h, (u32)sizeof(h), rec_path);
    if (h.len2) dump_append(ARG2_PTR(void), h.len2, rec_path);
    if (h.len3) dump_append(ARG3_PTR(void), h.len3, rec_path);
}
