/*
 * pe_parser.c - PE/PE32+ file format parser
 *
 * Parses DOS header, COFF header, Optional header, and section headers
 * from a PE executable file into a pe_image_t structure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "pe/pe_header.h"
#include "pe/pe_types.h"

#define LOG_PREFIX "[pe_parser] "

static int read_exact(int fd, void *buf, size_t count)
{
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, (char *)buf + total, count - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1; /* Unexpected EOF */
        total += n;
    }
    return 0;
}

int pe_parse_file(const char *filename, pe_image_t *image)
{
    struct stat st;
    uint32_t pe_sig;

    memset(image, 0, sizeof(*image));
    image->fd = -1;

    /* Open the PE file */
    image->fd = open(filename, O_RDONLY);
    if (image->fd < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to open '%s': %s\n",
                filename, strerror(errno));
        return -1;
    }
    image->filename = filename;

    if (fstat(image->fd, &st) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to stat '%s': %s\n",
                filename, strerror(errno));
        goto fail;
    }
    image->file_size = st.st_size;

    if (image->file_size < sizeof(pe_dos_header_t)) {
        fprintf(stderr, LOG_PREFIX "File too small for DOS header\n");
        goto fail;
    }

    /* Read DOS header */
    if (read_exact(image->fd, &image->dos_header, sizeof(pe_dos_header_t)) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to read DOS header\n");
        goto fail;
    }

    if (image->dos_header.e_magic != PE_DOS_MAGIC) {
        fprintf(stderr, LOG_PREFIX "Invalid DOS magic: 0x%04X (expected 0x%04X)\n",
                image->dos_header.e_magic, PE_DOS_MAGIC);
        goto fail;
    }

    /* Seek to PE signature */
    if (image->dos_header.e_lfanew < 0 ||
        (uint32_t)image->dos_header.e_lfanew >= image->file_size) {
        fprintf(stderr, LOG_PREFIX "Invalid e_lfanew offset: %d\n",
                image->dos_header.e_lfanew);
        goto fail;
    }

    if (lseek(image->fd, image->dos_header.e_lfanew, SEEK_SET) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to seek to PE header\n");
        goto fail;
    }

    /* Read and validate PE signature */
    if (read_exact(image->fd, &pe_sig, sizeof(pe_sig)) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to read PE signature\n");
        goto fail;
    }

    if (pe_sig != PE_NT_SIGNATURE) {
        fprintf(stderr, LOG_PREFIX "Invalid PE signature: 0x%08X\n", pe_sig);
        goto fail;
    }

    /* Read COFF file header */
    if (read_exact(image->fd, &image->file_header, sizeof(pe_file_header_t)) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to read COFF header\n");
        goto fail;
    }

    /* Validate machine type */
    if (image->file_header.machine != PE_MACHINE_AMD64 &&
        image->file_header.machine != PE_MACHINE_I386) {
        fprintf(stderr, LOG_PREFIX "Unsupported machine type: 0x%04X\n",
                image->file_header.machine);
        goto fail;
    }

    /* Read optional header - first peek at magic to determine PE32 vs PE32+ */
    uint16_t opt_magic;
    if (read_exact(image->fd, &opt_magic, sizeof(opt_magic)) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to read optional header magic\n");
        goto fail;
    }

    /* Seek back to re-read the full optional header */
    if (lseek(image->fd, -sizeof(opt_magic), SEEK_CUR) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to seek back\n");
        goto fail;
    }

    if (opt_magic == PE_OPT_MAGIC_PE32P) {
        /* PE32+ (64-bit) */
        pe_optional_header64_t opt64;
        image->is_pe32plus = 1;

        size_t fixed_size = sizeof(pe_optional_header64_t) - sizeof(opt64.data_directory);
        if (image->file_header.size_of_optional_header < fixed_size) {
            fprintf(stderr, LOG_PREFIX "Optional header too small\n");
            goto fail;
        }

        /* Read only the actual optional header size (may have fewer than 16
         * data directories), zero-fill the rest to avoid reading into section
         * headers. */
        size_t actual_size = image->file_header.size_of_optional_header;
        size_t read_size = actual_size < sizeof(opt64) ? actual_size : sizeof(opt64);
        memset(&opt64, 0, sizeof(opt64));
        if (read_exact(image->fd, &opt64, read_size) < 0) {
            fprintf(stderr, LOG_PREFIX "Failed to read PE32+ optional header\n");
            goto fail;
        }

        /* Skip any remaining optional header bytes beyond our struct size */
        if (actual_size > sizeof(opt64)) {
            if (lseek(image->fd, actual_size - sizeof(opt64), SEEK_CUR) < 0) {
                fprintf(stderr, LOG_PREFIX "Failed to skip excess optional header bytes\n");
                goto fail;
            }
        }

        /* Normalize into our internal structure */
        image->image_base = opt64.image_base;
        image->section_alignment = opt64.section_alignment;
        image->file_alignment = opt64.file_alignment;
        image->address_of_entry_point = opt64.address_of_entry_point;
        image->size_of_image = opt64.size_of_image;
        image->size_of_headers = opt64.size_of_headers;
        image->subsystem = opt64.subsystem;
        image->dll_characteristics = opt64.dll_characteristics;
        image->size_of_stack_reserve = opt64.size_of_stack_reserve;
        image->size_of_stack_commit = opt64.size_of_stack_commit;
        image->number_of_rva_and_sizes = opt64.number_of_rva_and_sizes;

        if (image->number_of_rva_and_sizes > PE_NUM_DATA_DIRECTORIES)
            image->number_of_rva_and_sizes = PE_NUM_DATA_DIRECTORIES;

        memcpy(image->data_directory, opt64.data_directory,
               image->number_of_rva_and_sizes * sizeof(pe_data_directory_t));

    } else if (opt_magic == PE_OPT_MAGIC_PE32) {
        /* PE32 (32-bit) */
        pe_optional_header32_t opt32;
        image->is_pe32plus = 0;

        size_t fixed_size32 = sizeof(pe_optional_header32_t) - sizeof(opt32.data_directory);
        if (image->file_header.size_of_optional_header < fixed_size32) {
            fprintf(stderr, LOG_PREFIX "PE32 optional header too small\n");
            goto fail;
        }

        size_t actual_size32 = image->file_header.size_of_optional_header;
        size_t read_size32 = actual_size32 < sizeof(opt32) ? actual_size32 : sizeof(opt32);
        memset(&opt32, 0, sizeof(opt32));
        if (read_exact(image->fd, &opt32, read_size32) < 0) {
            fprintf(stderr, LOG_PREFIX "Failed to read PE32 optional header\n");
            goto fail;
        }
        if (actual_size32 > sizeof(opt32)) {
            if (lseek(image->fd, actual_size32 - sizeof(opt32), SEEK_CUR) < 0) {
                fprintf(stderr, LOG_PREFIX "Failed to skip excess optional header bytes\n");
                goto fail;
            }
        }

        image->image_base = opt32.image_base;
        image->section_alignment = opt32.section_alignment;
        image->file_alignment = opt32.file_alignment;
        image->address_of_entry_point = opt32.address_of_entry_point;
        image->size_of_image = opt32.size_of_image;
        image->size_of_headers = opt32.size_of_headers;
        image->subsystem = opt32.subsystem;
        image->dll_characteristics = opt32.dll_characteristics;
        image->size_of_stack_reserve = opt32.size_of_stack_reserve;
        image->size_of_stack_commit = opt32.size_of_stack_commit;
        image->number_of_rva_and_sizes = opt32.number_of_rva_and_sizes;

        if (image->number_of_rva_and_sizes > PE_NUM_DATA_DIRECTORIES)
            image->number_of_rva_and_sizes = PE_NUM_DATA_DIRECTORIES;

        memcpy(image->data_directory, opt32.data_directory,
               image->number_of_rva_and_sizes * sizeof(pe_data_directory_t));

        /* NOTE: excess optional header bytes were already skipped above
         * (lines 192-197). Do NOT seek again here — that would double-skip
         * and corrupt section header reads for PE32 binaries. */

    } else {
        fprintf(stderr, LOG_PREFIX "Unknown optional header magic: 0x%04X\n", opt_magic);
        goto fail;
    }

    /* Read section headers */
    image->num_sections = image->file_header.number_of_sections;
    if (image->num_sections == 0) {
        fprintf(stderr, LOG_PREFIX "PE has no sections\n");
        goto fail;
    }
    if (image->num_sections > 96) {
        fprintf(stderr, LOG_PREFIX "Too many sections: %u (PE spec max 96)\n",
                image->num_sections);
        goto fail;
    }

    image->sections = calloc(image->num_sections, sizeof(pe_section_header_t));
    if (!image->sections) {
        fprintf(stderr, LOG_PREFIX "Failed to allocate section headers\n");
        goto fail;
    }

    size_t sections_size = image->num_sections * sizeof(pe_section_header_t);
    if (read_exact(image->fd, image->sections, sections_size) < 0) {
        fprintf(stderr, LOG_PREFIX "Failed to read section headers\n");
        goto fail;
    }

    printf(LOG_PREFIX "Parsed PE: %s (%s, %s, %u sections, entry=0x%08X)\n",
           filename,
           image->is_pe32plus ? "PE32+" : "PE32",
           image->subsystem == PE_SUBSYSTEM_WINDOWS_CUI ? "Console" :
           image->subsystem == PE_SUBSYSTEM_WINDOWS_GUI ? "GUI" : "Other",
           image->num_sections,
           image->address_of_entry_point);

    return 0;

fail:
    pe_image_free(image);
    return -1;
}

void pe_image_free(pe_image_t *image)
{
    if (image->sections) {
        free(image->sections);
        image->sections = NULL;
    }
    if (image->mapped_base) {
        munmap(image->mapped_base, image->mapped_size);
        image->mapped_base = NULL;
    }
    if (image->fd >= 0) {
        close(image->fd);
        image->fd = -1;
    }
}

void *pe_rva_to_ptr(const pe_image_t *image, uint32_t rva)
{
    if (!image->mapped_base)
        return NULL;
    if (rva >= image->mapped_size)
        return NULL;
    return image->mapped_base + rva;
}

void *pe_get_entry_point(const pe_image_t *image)
{
    return pe_rva_to_ptr(image, image->address_of_entry_point);
}
