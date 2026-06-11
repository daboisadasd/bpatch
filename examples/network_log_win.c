/*
 * network_log_win.c — Windows x64 / ARM64
 *
 * Hook winsock send()/WSASend() to capture outgoing network data.
 * Dumps the buffer and size to C:\bpatch_netlog.txt.
 *
 * Hook at the ENTRY of Ws2_32.dll!send (RVA 0x... or via --at-export):
 *   MS ABI: send(SOCKET s, const char *buf, int len, int flags)
 *   ARG1 = socket handle, ARG2 = buffer ptr, ARG3 = length, ARG4 = flags
 *
 * Usage (hook send in a target exe that links ws2_32.dll):
 *   bpatch target.exe --at-export send --payload network_log_win.c
 *
 * Or hook a specific call site inside the malware's own send wrapper:
 *   bpatch malware.exe --at 0x14001ABCD --payload network_log_win.c
 *
 * Output format per call:
 *   === send: 42 bytes ===
 *   <hex+ASCII dump>
 */

#include "bpatch_rt.h"

#define BP_OUT_PATH "C:\\bpatch_netlog.txt"
#define BP_MAX_DUMP 256

void payload(void) {
    u64   buf_ptr = ARG2;
    u64   buf_len = ARG3;
    if (buf_len == 0 || buf_ptr == 0) return;
    if (buf_len > BP_MAX_DUMP) buf_len = BP_MAX_DUMP;

    /* Header */
    char hdr[48];
    u32 hi = 0;
    hdr[hi++]='='; hdr[hi++]='='; hdr[hi++]='='; hdr[hi++]=' ';
    hdr[hi++]='s'; hdr[hi++]='e'; hdr[hi++]='n'; hdr[hi++]='d';
    hdr[hi++]=':'; hdr[hi++]=' ';
    /* decimal length */
    {
        char rev[12]; int rlen=0; u64 tmp=buf_len;
        if(tmp==0){rev[rlen++]='0';}
        else{while(tmp>0){rev[rlen++]='0'+(int)(tmp%10);tmp/=10;}}
        for(int i=rlen-1;i>=0;i--) hdr[hi++]=rev[i];
    }
    hdr[hi++]=' '; hdr[hi++]='b'; hdr[hi++]='y'; hdr[hi++]='t';
    hdr[hi++]='e'; hdr[hi++]='s'; hdr[hi++]=' ';
    hdr[hi++]='='; hdr[hi++]='='; hdr[hi++]='='; hdr[hi++]='\r'; hdr[hi++]='\n';
    dump_str_append(hdr, BP_OUT_PATH);

    /* Hex + ASCII dump */
    const u8 *ptr = (const u8 *)buf_ptr;
    char line[80];
    for (u64 row = 0; row < buf_len; row += 16) {
        u32 li = 0;
        u8 off = (u8)(row >> 4);
        line[li++]="0123456789abcdef"[(off>>4)&0xF];
        line[li++]="0123456789abcdef"[ off    &0xF];
        line[li++]='0'; line[li++]=':'; line[li++]=' ';
        for (int col = 0; col < 16; col++) {
            if (row + col < buf_len) {
                u8 b = ptr[row+col];
                line[li++]="0123456789abcdef"[(b>>4)&0xF];
                line[li++]="0123456789abcdef"[ b    &0xF];
            } else { line[li++]=' '; line[li++]=' '; }
            line[li++]=' ';
            if (col==7) line[li++]=' ';
        }
        line[li++]=' ';
        for (int col = 0; col < 16 && (row+col) < buf_len; col++) {
            u8 b = ptr[row+col];
            line[li++]=(b>=0x20&&b<0x7F)?(char)b:'.';
        }
        line[li++]='\r'; line[li++]='\n';
        dump_append(line, li, BP_OUT_PATH);
    }
}
