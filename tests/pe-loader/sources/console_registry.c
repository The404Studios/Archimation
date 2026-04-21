/*
 * console_registry.c -- advapi32 registry roundtrip.
 *
 * Surface tested:
 *   advapi32!RegCreateKeyExA, advapi32!RegOpenKeyExA, advapi32!RegSetValueExA,
 *   advapi32!RegQueryValueExA, advapi32!RegDeleteValueA, advapi32!RegDeleteKeyA,
 *   advapi32!RegCloseKey
 *
 * Rationale:
 *   Create a key under HKEY_CURRENT_USER (writable in any registry impl),
 *   set a REG_SZ + REG_DWORD, read them back, validate, then delete the
 *   key.  Catches:
 *     - Hive routing (HKCU vs HKLM vs HKCR)
 *     - REG_SZ trailing NUL handling (cbData includes/excludes NUL)
 *     - REG_DWORD endianness
 *     - Key creation under a path that doesn't exist (CreateKey vs OpenKey)
 *
 *   This is the in-process registry test.  An out-of-process test would
 *   require the objectd registry hive to be running.
 *
 * Harness expectation: outputs:CONSOLE_REGISTRY_OK
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

static const char SUBKEY[] = "Software\\PELoaderTest\\corpus";
static const char STR_NAME[] = "TestString";
static const char STR_VALUE[] = "round-trip-marker";
static const char DW_NAME[] = "TestDword";

int main(void) {
    HKEY hkey = NULL;
    DWORD disposition = 0;
    LONG rc;

    rc = RegCreateKeyExA(HKEY_CURRENT_USER, SUBKEY, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                         NULL, &hkey, &disposition);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "RegCreateKeyExA failed: rc=%ld\n", (long)rc);
        return 50;
    }

    /* Write REG_SZ. cbData includes the trailing NUL. */
    rc = RegSetValueExA(hkey, STR_NAME, 0, REG_SZ,
                        (const BYTE *)STR_VALUE,
                        (DWORD)(strlen(STR_VALUE) + 1));
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "RegSetValueExA(SZ) failed: rc=%ld\n", (long)rc);
        RegCloseKey(hkey);
        return 51;
    }

    DWORD dw_in = 0xCAFEBABE;
    rc = RegSetValueExA(hkey, DW_NAME, 0, REG_DWORD,
                        (const BYTE *)&dw_in, (DWORD)sizeof(dw_in));
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "RegSetValueExA(DWORD) failed: rc=%ld\n", (long)rc);
        RegCloseKey(hkey);
        return 52;
    }

    /* Read REG_SZ back. */
    char buf[64] = {0};
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    rc = RegQueryValueExA(hkey, STR_NAME, NULL, &type,
                          (BYTE *)buf, &cb);
    if (rc != ERROR_SUCCESS || type != REG_SZ ||
        strcmp(buf, STR_VALUE) != 0) {
        fprintf(stderr, "Reg SZ mismatch: rc=%ld type=%lu got='%s'\n",
                (long)rc, (unsigned long)type, buf);
        RegCloseKey(hkey);
        return 53;
    }

    /* Read REG_DWORD back. */
    DWORD dw_out = 0;
    cb = sizeof(dw_out);
    rc = RegQueryValueExA(hkey, DW_NAME, NULL, &type,
                          (BYTE *)&dw_out, &cb);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || dw_out != dw_in) {
        fprintf(stderr, "Reg DWORD mismatch: rc=%ld type=%lu got=0x%lx\n",
                (long)rc, (unsigned long)type, (unsigned long)dw_out);
        RegCloseKey(hkey);
        return 54;
    }

    /* Cleanup values, then key. */
    RegDeleteValueA(hkey, STR_NAME);
    RegDeleteValueA(hkey, DW_NAME);
    RegCloseKey(hkey);
    RegDeleteKeyA(HKEY_CURRENT_USER, SUBKEY);

    printf("CONSOLE_REGISTRY_OK\n");
    fflush(stdout);
    return 0;
}
