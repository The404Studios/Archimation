/*
 * registry_signext.c -- HKEY sign-extension regression guard.
 *
 * Surface tested:
 *   advapi32!RegOpenKeyExA on predefined HKEY constants
 *   pe-loader/registry/registry.c::hkey_low32() mask helper (S67 A1)
 *
 * Rationale:
 *   MinGW's <winreg.h> declares the HKEY_* constants as
 *       ((HKEY)(ULONG_PTR)((LONG)0x80000000))
 *   which sign-extends on 64-bit: the LONG cast produces 0xFFFFFFFF80000001
 *   for HKEY_CURRENT_USER, not 0x80000001.  Prior to the S67 fix, the loader's
 *   registry routing compared against the low 32 bits only via implicit cast,
 *   so the sign-extended value never matched and every predefined-hive access
 *   returned ERROR_INVALID_HANDLE.  The hkey_low32() mask helper (now applied
 *   at 7 sites in registry.c) collapses the value back to 0x80000001 before
 *   hive dispatch.
 *
 *   This test simply opens "Software" under HKCU.  Success is either
 *   ERROR_SUCCESS (hive routed, key opened) or ERROR_FILE_NOT_FOUND (hive
 *   routed correctly but the subkey doesn't exist in the test registry).
 *   Any other status -- in particular ERROR_INVALID_HANDLE (6) -- indicates
 *   the sign-extension bug has regressed.
 *
 * Harness expectation: outputs-any:REGISTRY_SIGNEXT_OK,REGISTRY_SIGNEXT_STUB
 */

#include <windows.h>
#include <stdio.h>

int main(void) {
    HKEY h = NULL;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, "Software", 0, KEY_READ, &h);

    if (rc == ERROR_SUCCESS) {
        RegCloseKey(h);
        printf("REGISTRY_SIGNEXT_OK: HKCU routed (rc=0, Software opened)\n");
        fflush(stdout);
        return 0;
    }
    if (rc == ERROR_FILE_NOT_FOUND) {
        /* Acceptable: hive was routed correctly, subkey just absent. */
        printf("REGISTRY_SIGNEXT_OK: HKCU routed (rc=2, Software absent)\n");
        fflush(stdout);
        return 0;
    }
    if (rc == ERROR_INVALID_HANDLE) {
        /* Exactly the regression we're guarding against. */
        fprintf(stderr,
                "FAIL: RegOpenKeyExA on HKCU returned ERROR_INVALID_HANDLE "
                "(rc=%ld); sign-extension fix regressed (hkey_low32 missing?)\n",
                (long)rc);
        return 1;
    }
    if (rc == ERROR_CALL_NOT_IMPLEMENTED ||
        rc == ERROR_NOT_SUPPORTED) {
        /* Stub loader without registry support -- acceptable. */
        printf("REGISTRY_SIGNEXT_STUB: RegOpenKeyExA not implemented (rc=%ld)\n",
               (long)rc);
        fflush(stdout);
        return 0;
    }

    fprintf(stderr,
            "FAIL: RegOpenKeyExA on HKCU returned unexpected rc=%ld\n",
            (long)rc);
    return 1;
}
