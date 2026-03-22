/*
 * dump_string_win.c — dump a null-terminated string from a register to a file
 *
 * Windows x64 calling convention:
 *   ARG1 = rcx  (first argument)
 *   ARG2 = rdx  (second argument)
 *   ARG3 = r8
 *   ARG4 = r9
 *   RETVAL = rax
 *
 * Scenario: injecting at the entry of a function where rcx holds a
 * char* or wchar_t* you want to capture (key, path, decrypted string, etc.)
 *
 * NOTE: use  char arr[] = "..."  NOT  char *p = "..."  for string literals.
 * arr[] is stack-allocated (safe in injected code).
 * ptr would reference .rodata outside our injected section.
 */
#include "bpatch_rt.h"

void payload()
{
    char path[] = "C:\\bpatch_dump.txt";

    /* Dump the null-terminated string that rcx (ARG1) points to */
    const char *str = ARG1_PTR(char);
    dump_str(str, path);
}
