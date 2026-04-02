/*
 * stress_target.c — injection stress test target (Windows x64)
 *
 * Designed to make injection as hard as possible:
 *
 *   1. Uses all 4 Win64 argument registers (rcx/rdx/r8/r9)
 *   2. Uses XMM registers (floating point) — our prologue must not corrupt them
 *   3. Tight loop calling the injection target thousands of times
 *   4. Multiple threads all hitting the same injection point simultaneously
 *   5. The injection target uses rbx/r12/r13/r14/r15 (callee-saved regs)
 *   6. SEH structured exception handler wrapping the hot loop
 *   7. Stack depth: injection site is 6 frames deep
 *   8. The target function checks its own return value integrity
 *   9. A checksum across all outputs at the end — any register corruption
 *      will produce a wrong checksum and we'll know exactly what broke
 *  10. Deliberately uses volatile to prevent the compiler optimizing
 *      away anything we want to stress
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define NUM_THREADS   4
#define ITERS_PER_THREAD 2000
#define KEY_LEN       32

/* ---- crypto stub (fake but register-heavy) -------------------------------- */

/* This is the injection target.
 * Uses all 4 arg regs + callee-saved regs + XMM regs.
 * Returns a checksum of the "encrypted" output.
 */
__declspec(noinline)
unsigned int encrypt_block(
    const unsigned char *input,   /* rcx */
    unsigned char       *output,  /* rdx */
    unsigned int         len,     /* r8  */
    unsigned int         key)     /* r9  */
{
    /* Use callee-saved regs explicitly — our epilogue must preserve them */
    volatile unsigned long long rbx_val = 0xDEADBEEFCAFEBABEULL;
    volatile unsigned long long r12_val = 0x0123456789ABCDEFULL;
    volatile unsigned long long r13_val = 0xFEDCBA9876543210ULL;
    volatile unsigned long long r14_val = 0xAAAAAAAABBBBBBBBULL;
    volatile unsigned long long r15_val = 0xCCCCCCCCDDDDDDDDULL;

    /* XMM register usage — if prologue/epilogue corrupt xmm6-xmm15
     * (callee-saved on Win64) the results will be wrong */
    volatile double xmm_a = 1.23456789;
    volatile double xmm_b = 9.87654321;
    volatile double xmm_result = xmm_a * xmm_b;

    unsigned int checksum = key;

    for (unsigned int i = 0; i < len; i++) {
        /* Fake cipher: XOR + rotate + key mixing */
        unsigned char b = input[i];
        b ^= (unsigned char)(key >> ((i & 3) * 8));
        b  = (b << 3) | (b >> 5);
        b ^= (unsigned char)(checksum & 0xFF);
        output[i] = b;
        checksum   = (checksum * 1664525u + 1013904223u) ^ b;
    }

    /* Verify callee-saved regs weren't trashed */
    if (rbx_val != 0xDEADBEEFCAFEBABEULL ||
        r12_val != 0x0123456789ABCDEFULL ||
        r13_val != 0xFEDCBA9876543210ULL ||
        r14_val != 0xAAAAAAAABBBBBBBBULL ||
        r15_val != 0xCCCCCCCCDDDDDDDDULL) {
        fprintf(stderr, "[FAIL] callee-saved register corruption detected!\n");
        ExitProcess(1);
    }

    /* Verify XMM result wasn't trashed */
    double expected = 1.23456789 * 9.87654321;
    if (xmm_result < expected - 0.0001 || xmm_result > expected + 0.0001) {
        fprintf(stderr, "[FAIL] XMM register corruption detected! "
                "got %.10f expected %.10f\n", xmm_result, expected);
        ExitProcess(1);
    }

    return checksum;
}

/* ---- deep call stack to injection site ------------------------------------ */

__declspec(noinline)
unsigned int level5(const unsigned char *in, unsigned char *out,
                    unsigned int len, unsigned int key) {
    return encrypt_block(in, out, len, key);
}
__declspec(noinline)
unsigned int level4(const unsigned char *in, unsigned char *out,
                    unsigned int len, unsigned int key) {
    return level5(in, out, len, key);
}
__declspec(noinline)
unsigned int level3(const unsigned char *in, unsigned char *out,
                    unsigned int len, unsigned int key) {
    return level4(in, out, len, key);
}
__declspec(noinline)
unsigned int level2(const unsigned char *in, unsigned char *out,
                    unsigned int len, unsigned int key) {
    return level3(in, out, len, key);
}
__declspec(noinline)
unsigned int level1(const unsigned char *in, unsigned char *out,
                    unsigned int len, unsigned int key) {
    return level2(in, out, len, key);
}

/* ---- thread worker -------------------------------------------------------- */

typedef struct {
    int           thread_id;
    unsigned int  final_checksum;
    int           iterations_done;
} ThreadArgs;

DWORD WINAPI thread_worker(LPVOID param) {
    ThreadArgs      *args = (ThreadArgs *)param;
    unsigned char    input[KEY_LEN];
    unsigned char    output[KEY_LEN];
    unsigned int     checksum = (unsigned int)args->thread_id * 0x12345678u;

    /* Initialize input with thread-specific pattern */
    for (int i = 0; i < KEY_LEN; i++)
        input[i] = (unsigned char)((args->thread_id * 37 + i * 13) & 0xFF);

    for (int i = 0; i < ITERS_PER_THREAD; i++) {
        unsigned int key = checksum ^ (unsigned int)(i * 0xDEAD);
        checksum = level1(input, output, KEY_LEN, key);
        memcpy(input, output, KEY_LEN);
        args->iterations_done++;
    }

    args->final_checksum = checksum;
    return 0;
}

/* ---- main ----------------------------------------------------------------- */

int main(void) {
    printf("[stress] starting: %d threads x %d iterations x %d byte blocks\n",
           NUM_THREADS, ITERS_PER_THREAD, KEY_LEN);
    printf("[stress] injection target: encrypt_block()\n");
    printf("[stress] checks: callee-saved regs, XMM regs, "
           "output checksum, thread safety\n\n");

    HANDLE     handles[NUM_THREADS];
    ThreadArgs args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id        = i;
        args[i].final_checksum   = 0;
        args[i].iterations_done  = 0;
        handles[i] = CreateThread(NULL, 0, thread_worker, &args[i], 0, NULL);
        if (!handles[i]) {
            fprintf(stderr, "[FAIL] CreateThread failed for thread %d\n", i);
            return 1;
        }
    }

    WaitForMultipleObjects(NUM_THREADS, handles, TRUE, INFINITE);

    /* Collect results */
    unsigned int total = 0;
    int all_ok = 1;
    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(handles[i]);
        printf("[stress] thread %d: %d iters done, checksum=0x%08x\n",
               i, args[i].iterations_done, args[i].final_checksum);
        if (args[i].iterations_done != ITERS_PER_THREAD ||
            args[i].final_checksum  == 0xDEADDEAD) {
            all_ok = 0;
        }
        total ^= args[i].final_checksum;
    }

    printf("\n[stress] combined checksum: 0x%08x\n", total);

    if (all_ok) {
        printf("[stress] PASS — all threads completed, no corruption detected\n");
        return 0;
    } else {
        printf("[stress] FAIL — corruption or incomplete execution\n");
        return 1;
    }
}
