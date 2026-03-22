/*
 * stress_payload_win.c -- injection stress test payload (Windows x64)
 *
 * Injected into encrypt_block() which is called 8000 times across 4 threads.
 * Logs a sample of calls to C:\bpatch_stress.txt to verify all 4 argument
 * registers are read correctly under thread contention.
 *
 * Win64 ABI at encrypt_block() entry:
 *   ARG1 (rcx) = const unsigned char *input
 *   ARG2 (rdx) = unsigned char *output
 *   ARG3 (r8)  = unsigned int len
 *   ARG4 (r9)  = unsigned int key
 *
 * Deliberately avoids static/global variables -- .bss is discarded by the
 * linker script and would silently produce zero on every read.
 */
#include "bpatch_rt.h"

static void fmt_u32_hex(char *buf, u32 v) {
    for (int i = 7; i >= 0; i--) {
        u8 n = (u8)(v & 0xF); v >>= 4;
        buf[i] = n < 10 ? '0' + n : 'a' + (n - 10);
    }
}

static void log_call(u32 key, u32 len, const u8 *input, const char *path) {
    /* "key=0xKKKKKKKK len=LLL in=XX XX XX XX XX XX XX XX\n" */
    char line[72];
    int  p = 0;

    char pfx[] = "key=0x00000000 len=000 in=";
    fmt_u32_hex(pfx + 7, key);
    pfx[18] = '0' + ((len / 100) % 10);
    pfx[19] = '0' + ((len / 10)  % 10);
    pfx[20] = '0' + (len % 10);

    int i = 0; while (pfx[i]) line[p++] = pfx[i++];

    u32 show = len < 8 ? len : 8;
    for (u32 j = 0; j < show; j++) {
        u8 b = input[j];
        u8 hi = b >> 4, lo = b & 0xF;
        line[p++] = hi < 10 ? '0' + hi : 'a' + (hi - 10);
        line[p++] = lo < 10 ? '0' + lo : 'a' + (lo - 10);
        if (j + 1 < show) line[p++] = ' ';
    }
    line[p++] = '\n';
    dump_bytes(line, (u32)p, path);
}

void payload() {
    /* Read all 4 Win64 argument registers */
    const u8 *input = ARG1_PTR(u8);
    u32  len        = (u32)ARG3;
    u32  key        = (u32)ARG4;

    /* Sanity guard -- implausible len means register corruption */
    if (len == 0 || len > 4096) return;

    
    char path[] = "C:\\bpatch_stress.txt";
    log_call(key, len, input, path);
    
}
