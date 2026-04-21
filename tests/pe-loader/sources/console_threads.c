/*
 * console_threads.c -- kernel32 threading + sync primitives.
 *
 * Surface tested:
 *   kernel32!CreateThread, kernel32!WaitForSingleObject, kernel32!CloseHandle,
 *   kernel32!CreateMutexA, kernel32!ReleaseMutex, kernel32!Sleep,
 *   InterlockedIncrement (intrinsic, but also imported on some MinGW builds)
 *
 * Rationale:
 *   Spawn N worker threads that each acquire a shared mutex, bump a
 *   shared counter, release.  Final counter must equal N * iterations.
 *   Catches:
 *     - CreateThread actually creates a real OS thread
 *     - WaitForSingleObject blocks until thread exit (not spin-fail)
 *     - Mutex provides mutual exclusion (no torn counter)
 *     - InterlockedIncrement provides atomic increment
 *
 * Harness expectation: outputs:CONSOLE_THREADS_OK
 */

#include <windows.h>
#include <stdio.h>

#define N_THREADS    4
#define ITERATIONS   1000

static volatile LONG g_counter = 0;
static HANDLE g_mutex = NULL;

static DWORD WINAPI worker(LPVOID param) {
    (void)param;
    for (int i = 0; i < ITERATIONS; ++i) {
        WaitForSingleObject(g_mutex, INFINITE);
        /* Mutex-protected non-atomic increment.  Should never tear. */
        g_counter = g_counter + 1;
        ReleaseMutex(g_mutex);
    }
    return 0;
}

int main(void) {
    g_mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!g_mutex) {
        fprintf(stderr, "CreateMutexA failed: GLE=%lu\n",
                (unsigned long)GetLastError());
        return 30;
    }

    HANDLE threads[N_THREADS];
    for (int i = 0; i < N_THREADS; ++i) {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (!threads[i]) {
            fprintf(stderr, "CreateThread #%d failed: GLE=%lu\n", i,
                    (unsigned long)GetLastError());
            return 31;
        }
    }

    /* Wait for all threads.  WaitForMultipleObjects would be more
     * efficient but exercises a wider surface; one-by-one is enough. */
    for (int i = 0; i < N_THREADS; ++i) {
        DWORD r = WaitForSingleObject(threads[i], 10000);
        if (r != WAIT_OBJECT_0) {
            fprintf(stderr, "WaitForSingleObject thread #%d returned %lu\n",
                    i, (unsigned long)r);
            return 32;
        }
        CloseHandle(threads[i]);
    }
    CloseHandle(g_mutex);

    LONG expected = (LONG)N_THREADS * ITERATIONS;
    if (g_counter != expected) {
        fprintf(stderr, "counter mismatch: got %ld expected %ld\n",
                (long)g_counter, (long)expected);
        return 33;
    }

    printf("counter=%ld (expected %ld)\n", (long)g_counter, (long)expected);
    printf("CONSOLE_THREADS_OK\n");
    fflush(stdout);
    return 0;
}
