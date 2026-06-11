/*
 * count_hits.c — Linux x86-64/aarch64
 *
 * Count how many times the hooked site is reached and write the
 * running total to /tmp/bpatch_count.txt on every hit.
 *
 * The counter is stored in a static variable inside the payload section
 * (no heap, no external memory needed).
 *
 * Usage:
 *   bpatch target.elf --at <fn_addr> --payload count_hits.c
 *   cat /tmp/bpatch_count.txt   # shows latest count
 *
 * Useful for:
 *   - Determining how many times an anti-debug check runs
 *   - Counting how many packets/requests are processed
 *   - Verifying that a particular code path is (or isn't) reached
 */

#include "bpatch_rt.h"

#define BP_OUT_PATH "/tmp/bpatch_count.txt"

/* Static counter — lives inside the injected section, survives across calls */
static u64 _bp_hit_count = 0;

static void _bp_write_count(u64 count, const char *path) {
    /* Convert count to decimal string */
    char buf[24];
    int len = 0;
    if (count == 0) {
        buf[len++] = '0';
    } else {
        u64 tmp = count;
        char rev[20];
        int rlen = 0;
        while (tmp > 0) { rev[rlen++] = '0' + (int)(tmp % 10); tmp /= 10; }
        for (int i = rlen - 1; i >= 0; i--) buf[len++] = rev[i];
    }
    buf[len++] = '\n';
    dump_bytes(buf, len, path);
}

void payload(void) {
    _bp_hit_count++;
    _bp_write_count(_bp_hit_count, BP_OUT_PATH);
}
