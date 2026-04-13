#ifndef PE_TYPES_H
#define PE_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* PE magic numbers */
#define PE_DOS_MAGIC        0x5A4D      /* "MZ" */
#define PE_NT_SIGNATURE     0x00004550  /* "PE\0\0" */
#define PE_OPT_MAGIC_PE32   0x010B      /* PE32 */
#define PE_OPT_MAGIC_PE32P  0x020B      /* PE32+ (64-bit) */

/* Machine types */
#define PE_MACHINE_I386     0x014C
#define PE_MACHINE_AMD64    0x8664
#define PE_MACHINE_ARM64    0xAA64

/* Subsystem types */
#define PE_SUBSYSTEM_UNKNOWN        0
#define PE_SUBSYSTEM_NATIVE         1
#define PE_SUBSYSTEM_WINDOWS_GUI    2
#define PE_SUBSYSTEM_WINDOWS_CUI    3
#define PE_SUBSYSTEM_POSIX_CUI      7
#define PE_SUBSYSTEM_EFI_APP        10

/* Section characteristics */
#define PE_SCN_CNT_CODE             0x00000020
#define PE_SCN_CNT_INITIALIZED      0x00000040
#define PE_SCN_CNT_UNINITIALIZED    0x00000080
#define PE_SCN_MEM_DISCARDABLE      0x02000000
#define PE_SCN_MEM_NOT_CACHED       0x04000000
#define PE_SCN_MEM_NOT_PAGED        0x08000000
#define PE_SCN_MEM_SHARED           0x10000000
#define PE_SCN_MEM_EXECUTE          0x20000000
#define PE_SCN_MEM_READ             0x40000000
#define PE_SCN_MEM_WRITE            0x80000000

/* DLL characteristics */
#define PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA   0x0020
#define PE_DLLCHARACTERISTICS_DYNAMIC_BASE      0x0040
#define PE_DLLCHARACTERISTICS_FORCE_INTEGRITY   0x0080
#define PE_DLLCHARACTERISTICS_NX_COMPAT         0x0100
#define PE_DLLCHARACTERISTICS_NO_ISOLATION      0x0200
#define PE_DLLCHARACTERISTICS_NO_SEH            0x0400
#define PE_DLLCHARACTERISTICS_NO_BIND           0x0800
#define PE_DLLCHARACTERISTICS_APPCONTAINER      0x1000
#define PE_DLLCHARACTERISTICS_WDM_DRIVER        0x2000
#define PE_DLLCHARACTERISTICS_GUARD_CF          0x4000
#define PE_DLLCHARACTERISTICS_TERMINAL_SERVER    0x8000

/* File header characteristics */
#define PE_FILE_RELOCS_STRIPPED     0x0001
#define PE_FILE_EXECUTABLE_IMAGE    0x0002
#define PE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define PE_FILE_32BIT_MACHINE       0x0100
#define PE_FILE_DLL                 0x2000
#define PE_FILE_SYSTEM              0x1000

/* Data directory indices */
#define PE_DIR_EXPORT               0
#define PE_DIR_IMPORT               1
#define PE_DIR_RESOURCE             2
#define PE_DIR_EXCEPTION            3
#define PE_DIR_SECURITY             4
#define PE_DIR_BASERELOC            5
#define PE_DIR_DEBUG                6
#define PE_DIR_ARCHITECTURE         7
#define PE_DIR_GLOBALPTR            8
#define PE_DIR_TLS                  9
#define PE_DIR_LOAD_CONFIG          10
#define PE_DIR_BOUND_IMPORT         11
#define PE_DIR_IAT                  12
#define PE_DIR_DELAY_IMPORT         13
#define PE_DIR_COM_DESCRIPTOR       14
#define PE_DIR_RESERVED             15
#define PE_NUM_DATA_DIRECTORIES     16

/* Relocation types */
#define PE_REL_BASED_ABSOLUTE       0
#define PE_REL_BASED_HIGH           1
#define PE_REL_BASED_LOW            2
#define PE_REL_BASED_HIGHLOW        3
#define PE_REL_BASED_HIGHADJ        4
#define PE_REL_BASED_DIR64          10

/* Import lookup table entry flags */
#define PE_IMPORT_ORDINAL_FLAG32    0x80000000
#define PE_IMPORT_ORDINAL_FLAG64    0x8000000000000000ULL

#endif /* PE_TYPES_H */
