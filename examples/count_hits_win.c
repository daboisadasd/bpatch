/*
 * count_hits_win.c — Windows x64 / ARM64
 *
 * Count how many times the hooked site is reached.
 * Writes the running total to C:\bpatch_count.txt on every hit.
 *
 * Usage:
 *   bpatch target.exe --at 0x140001234 --payload count_hits_win.c
 *   type C:\bpatch_count.txt
 */

#include "bpatch_rt.h"

#define BP_OUT_PATH "C:\\bpatch_count.txt"

static u64 _bp_hit_count = 0;

static void _bp_write_count(u64 count, const char *path) {
    char buf[24];
    u32 len = 0;
    if (count == 0) {
        buf[len++] = '0';
    } else {
        u64 tmp = count;
        char rev[20];
        u32 rlen = 0;
        while (tmp > 0) { rev[rlen++] = '0' + (int)(tmp % 10); tmp /= 10; }
        for (u32 i = rlen; i > 0; i--) buf[len++] = rev[i-1];
    }
    buf[len++] = '\r'; buf[len++] = '\n';
    dump_bytes(buf, len, path);
}

void payload(void) {
    _bp_hit_count++;
    _bp_write_count(_bp_hit_count, BP_OUT_PATH);
}
