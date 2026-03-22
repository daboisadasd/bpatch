/*
 * dump_string.c — dump a null-terminated string from a register to a file
 *
 * Scenario: you've injected at a point where rax holds a pointer to a key/string
 * and you want to dump it to /tmp/bpatch_dump.txt.
 *
 * Note: use char arr[] = "..." for string literals, NOT char *p = "..."
 * The arr[] form is stack-allocated (safe in shellcode).
 * The ptr form references .rodata which won't exist in the injected section.
 */
#include "bpatch_rt.h"

void payload()
{
    char path[] = "/tmp/bpatch_dump.txt";

    /* RAX holds a char* — dump the null-terminated string it points to */
    const char *str = RAX_PTR(char);
    dump_str(str, path);
}
