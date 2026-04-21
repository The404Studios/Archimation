/*
 * console_hello.c -- Basic msvcrt sanity: printf + malloc + scanf-pathways.
 *
 * Surface tested:
 *   msvcrt!printf, msvcrt!malloc, msvcrt!free, msvcrt!sprintf, msvcrt!strlen
 *
 * Rationale:
 *   This is the floor.  If this fails, every higher-level binary fails.
 *   We deliberately avoid stdin scanf because the harness runs without a
 *   tty; instead we exercise sprintf on a malloc'd buffer to drive the
 *   formatter without needing input.
 *
 * Harness expectation: outputs:CONSOLE_HELLO_OK
 *
 * Build (handled by Makefile):
 *   x86_64-w64-mingw32-gcc -O0 -g -static -o console_hello.exe console_hello.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* Path A: literal printf. */
    printf("console_hello: starting\n");

    /* Path B: malloc + sprintf + free. Catches CRT heap not wired. */
    char *buf = (char *)malloc(128);
    if (!buf) {
        fprintf(stderr, "malloc(128) returned NULL\n");
        return 10;
    }

    int n = sprintf(buf, "value=%d hex=%x str=%s", 42, 0xDEAD, "abc");
    if (n <= 0 || strlen(buf) != (size_t)n) {
        fprintf(stderr, "sprintf produced inconsistent length: n=%d\n", n);
        free(buf);
        return 11;
    }

    printf("formatted: %s\n", buf);
    free(buf);

    /* Final marker the harness greps for. */
    printf("CONSOLE_HELLO_OK\n");
    fflush(stdout);
    return 0;
}
