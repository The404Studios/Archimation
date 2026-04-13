/*
 * pe_dump.c - PE header diagnostic dumper
 *
 * Usage: pe_dump <file.exe>
 * Prints detailed PE header information for debugging.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe/pe_header.h"
#include "pe/pe_types.h"

static const char *machine_name(uint16_t machine)
{
    switch (machine) {
    case PE_MACHINE_I386:   return "i386 (x86)";
    case PE_MACHINE_AMD64:  return "AMD64 (x86-64)";
    case PE_MACHINE_ARM64:  return "ARM64 (AArch64)";
    default:                return "Unknown";
    }
}

static const char *subsystem_name(uint16_t subsystem)
{
    switch (subsystem) {
    case PE_SUBSYSTEM_UNKNOWN:      return "Unknown";
    case PE_SUBSYSTEM_NATIVE:       return "Native";
    case PE_SUBSYSTEM_WINDOWS_GUI:  return "Windows GUI";
    case PE_SUBSYSTEM_WINDOWS_CUI:  return "Windows Console";
    case PE_SUBSYSTEM_POSIX_CUI:    return "POSIX Console";
    case PE_SUBSYSTEM_EFI_APP:      return "EFI Application";
    default:                        return "Other";
    }
}

static const char *dir_name(int index)
{
    static const char *names[] = {
        "Export", "Import", "Resource", "Exception",
        "Security", "Base Reloc", "Debug", "Architecture",
        "Global Ptr", "TLS", "Load Config", "Bound Import",
        "IAT", "Delay Import", "COM Descriptor", "Reserved"
    };
    if (index >= 0 && index < 16)
        return names[index];
    return "Unknown";
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }

    pe_image_t image;
    if (pe_parse_file(argv[1], &image) < 0) {
        fprintf(stderr, "Failed to parse: %s\n", argv[1]);
        return 1;
    }

    printf("=== PE Header Dump: %s ===\n\n", argv[1]);

    printf("--- DOS Header ---\n");
    printf("  e_magic:    0x%04X (%s)\n", image.dos_header.e_magic,
           image.dos_header.e_magic == PE_DOS_MAGIC ? "MZ" : "INVALID");
    printf("  e_lfanew:   0x%08X\n", image.dos_header.e_lfanew);

    printf("\n--- COFF File Header ---\n");
    printf("  Machine:          0x%04X (%s)\n",
           image.file_header.machine, machine_name(image.file_header.machine));
    printf("  Sections:         %u\n", image.file_header.number_of_sections);
    printf("  Timestamp:        0x%08X\n", image.file_header.time_date_stamp);
    printf("  Opt Header Size:  %u\n", image.file_header.size_of_optional_header);
    printf("  Characteristics:  0x%04X", image.file_header.characteristics);
    if (image.file_header.characteristics & PE_FILE_EXECUTABLE_IMAGE) printf(" EXECUTABLE");
    if (image.file_header.characteristics & PE_FILE_LARGE_ADDRESS_AWARE) printf(" LARGE_ADDRESS");
    if (image.file_header.characteristics & PE_FILE_DLL) printf(" DLL");
    if (image.file_header.characteristics & PE_FILE_RELOCS_STRIPPED) printf(" NO_RELOCS");
    printf("\n");

    printf("\n--- Optional Header (%s) ---\n", image.is_pe32plus ? "PE32+" : "PE32");
    printf("  Image Base:       0x%016lX\n", (unsigned long)image.image_base);
    printf("  Entry Point:      0x%08X\n", image.address_of_entry_point);
    printf("  Section Align:    0x%08X\n", image.section_alignment);
    printf("  File Align:       0x%08X\n", image.file_alignment);
    printf("  Size of Image:    0x%08X\n", image.size_of_image);
    printf("  Size of Headers:  0x%08X\n", image.size_of_headers);
    printf("  Subsystem:        %u (%s)\n", image.subsystem, subsystem_name(image.subsystem));
    printf("  DLL Chars:        0x%04X\n", image.dll_characteristics);
    printf("  Stack Reserve:    0x%lX\n", (unsigned long)image.size_of_stack_reserve);
    printf("  Stack Commit:     0x%lX\n", (unsigned long)image.size_of_stack_commit);
    printf("  Data Directories: %u\n", image.number_of_rva_and_sizes);

    printf("\n--- Data Directories ---\n");
    for (uint32_t i = 0; i < image.number_of_rva_and_sizes; i++) {
        if (image.data_directory[i].virtual_address != 0 ||
            image.data_directory[i].size != 0) {
            printf("  [%2u] %-15s  RVA=0x%08X  Size=0x%08X\n",
                   i, dir_name(i),
                   image.data_directory[i].virtual_address,
                   image.data_directory[i].size);
        }
    }

    printf("\n--- Section Headers ---\n");
    for (uint16_t i = 0; i < image.num_sections; i++) {
        pe_section_header_t *sec = &image.sections[i];
        char name[9] = {0};
        memcpy(name, sec->name, 8);

        printf("  [%u] %-8s  VA=0x%08X  VSize=0x%08X  Raw=0x%08X  RawSize=0x%08X  Flags=0x%08X",
               i, name,
               sec->virtual_address,
               sec->virtual_size,
               sec->pointer_to_raw_data,
               sec->size_of_raw_data,
               sec->characteristics);

        if (sec->characteristics & PE_SCN_MEM_READ) printf(" R");
        if (sec->characteristics & PE_SCN_MEM_WRITE) printf("W");
        if (sec->characteristics & PE_SCN_MEM_EXECUTE) printf("X");
        if (sec->characteristics & PE_SCN_CNT_CODE) printf(" CODE");
        if (sec->characteristics & PE_SCN_CNT_INITIALIZED) printf(" DATA");
        if (sec->characteristics & PE_SCN_CNT_UNINITIALIZED) printf(" BSS");
        printf("\n");
    }

    printf("\n");
    pe_image_free(&image);
    return 0;
}
