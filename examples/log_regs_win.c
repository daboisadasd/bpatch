/*
 * log_regs_win.c — log all register values on each hit
 *
 * Appends a separator and all 16 GP register values (as hex) to the log file
 * every time the injection point is executed.  Useful for understanding calling
 * patterns in obfuscated code, or finding when a key material appears.
 */
#include "bpatch_rt.h"

void payload()
{
    char path[] = "C:\\bpatch_regs.txt";
    char sep[]  = "---\n";

    dump_str_append(sep, path);

    LOG_REG("rax", RAX,  path);
    LOG_REG("rbx", RBX,  path);
    LOG_REG("rcx", RCX,  path);
    LOG_REG("rdx", RDX,  path);
    LOG_REG("rsi", RSI,  path);
    LOG_REG("rdi", RDI,  path);
    LOG_REG("rbp", RBP,  path);
    LOG_REG("r8 ", R8,   path);
    LOG_REG("r9 ", R9,   path);
    LOG_REG("r10", R10,  path);
    LOG_REG("r11", R11,  path);
    LOG_REG("r12", R12,  path);
    LOG_REG("r13", R13,  path);
    LOG_REG("r14", R14,  path);
    LOG_REG("r15", R15,  path);
}
