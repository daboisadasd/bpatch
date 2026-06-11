/*
 * hexdump_arg_win.c — Windows x64 / ARM64
 *
 * Hex-dump ARG1 (treated as a pointer to bytes) to C:\bpatch_hex.txt.
 * Useful for inspecting buffers passed to encrypted/packed functions.
 *
 * Usage:
 *   bpatch target.exe  --at 0x140001234 --payload hexdump_arg_win.c
 *   type C:\bpatch_hex.txt
 */

#include "bpatch_rt.h"

#define BP_DUMP_LEN  64
#define BP_OUT_PATH  "C:\\bpatch_hex.txt"

void payload(void) {
    const u8 *ptr = (const u8 *)(u64)ARG1;

    char hdr[] = "--- hit ---\n";
    dump_str_append(hdr, BP_OUT_PATH);

    char line[80];
    for (int row = 0; row < BP_DUMP_LEN; row += 16) {
        int li = 0;
        u8 off = (u8)(row >> 4);
        line[li++] = "0123456789abcdef"[(off >> 4) & 0xF];
        line[li++] = "0123456789abcdef"[ off        & 0xF];
        line[li++] = '0'; line[li++] = ':'; line[li++] = ' ';

        for (int col = 0; col < 16; col++) {
            if (row + col < BP_DUMP_LEN) {
                u8 b = ptr[row + col];
                line[li++] = "0123456789abcdef"[(b >> 4) & 0xF];
                line[li++] = "0123456789abcdef"[ b        & 0xF];
            } else {
                line[li++] = ' '; line[li++] = ' ';
            }
            line[li++] = ' ';
            if (col == 7) line[li++] = ' ';
        }
        line[li++] = ' ';

        for (int col = 0; col < 16 && (row + col) < BP_DUMP_LEN; col++) {
            u8 b = ptr[row + col];
            line[li++] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
        }
        line[li++] = '\r'; line[li++] = '\n';
        dump_append(line, (u32)li, BP_OUT_PATH);
    }
}
