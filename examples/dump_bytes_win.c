/*
 * dump_bytes_win.c — dump a length-prefixed buffer to a file
 *
 * Scenario: injecting at entry of a function that takes:
 *   rcx = HANDLE or context pointer  (ARG1 — ignored here)
 *   rdx = void *data                 (ARG2)
 *   r8  = size_t length              (ARG3)
 *
 * Common for crypto functions, WriteFile wrappers, encryption routines, etc.
 */
#include "bpatch_rt.h"

void payload()
{
    char path[] = "C:\\bpatch_keydump.bin";

    const void *data = ARG2_PTR(void);   /* rdx */
    u64         len  = ARG3;             /* r8  */

    dump_bytes(data, (u32)len, path);
}
