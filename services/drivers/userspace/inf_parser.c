/*
 * inf_parser.c - Windows .inf file parser
 *
 * Parses INI-style Windows .inf driver installation files used to describe
 * driver packages. Extracts key sections:
 *   [Version]          - Driver versioning and signature info
 *   [Manufacturer]     - Hardware manufacturer entries
 *   [DefaultInstall]   - Default installation directives
 *   [SourceDisksFiles] - Source file listing on install media
 *   [DestinationDirs]  - Target directories for file copy operations
 *
 * Also extracts driver binary paths (.sys files) and registry entries
 * referenced by CopyFiles and AddReg directives.
 *
 * The parser builds an in-memory representation of sections and key-value
 * pairs that can be queried after parsing completes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define INF_LOG_PREFIX      "[inf_parser] "
#define INF_MAX_SECTIONS    128
#define INF_MAX_ENTRIES     512
#define INF_MAX_LINE        2048
#define INF_MAX_DRIVERS     64
#define INF_MAX_REG_ENTRIES 128

/* A single key=value (or key-only) entry within a section */
typedef struct {
    char    key[256];
    char    value[1024];
} inf_entry_t;

/* A named section containing key-value entries */
typedef struct {
    char            name[256];
    inf_entry_t     entries[INF_MAX_ENTRIES];
    int             num_entries;
} inf_section_t;

/* A driver file reference extracted from CopyFiles/SourceDisksFiles */
typedef struct {
    char    filename[256];      /* e.g., "mydriver.sys" */
    char    source_dir[512];    /* source directory on install media */
    char    dest_dir[512];      /* destination directory on target */
    int     is_sys;             /* 1 if this is a .sys kernel driver */
} inf_driver_file_t;

/* A registry entry extracted from AddReg directives */
typedef struct {
    char    root_key[64];       /* e.g., "HKLM" */
    char    subkey[512];        /* e.g., "System\\CurrentControlSet\\Services\\MyDrv" */
    char    value_name[256];    /* e.g., "Start" */
    char    value_data[512];    /* e.g., "3" */
    int     value_type;         /* 0=REG_SZ, 1=REG_DWORD, etc. */
} inf_reg_entry_t;

/* Parsed .inf file context */
typedef struct {
    char                filepath[1024];
    inf_section_t       sections[INF_MAX_SECTIONS];
    int                 num_sections;
    inf_driver_file_t   driver_files[INF_MAX_DRIVERS];
    int                 num_driver_files;
    inf_reg_entry_t     reg_entries[INF_MAX_REG_ENTRIES];
    int                 num_reg_entries;
} inf_file_t;

/* Registry value type constants (matching Windows REG_* values) */
#define INF_REG_SZ          0x00000000
#define INF_REG_BINARY      0x00000001
#define INF_REG_DWORD       0x00010001
#define INF_REG_EXPAND_SZ   0x00020000
#define INF_REG_MULTI_SZ    0x00010000

/* Forward declarations */
static void str_trim(char *s);
static void str_lower(char *dst, const char *src, size_t maxlen);
static int  is_sys_file(const char *filename);
static inf_section_t *find_or_create_section(inf_file_t *inf, const char *name);
static int  parse_copyfiles_directive(inf_file_t *inf, const char *value);
static int  parse_addreg_directive(inf_file_t *inf, const char *section_name);
static int  extract_driver_files(inf_file_t *inf);
static int  extract_registry_entries(inf_file_t *inf);

/*
 * str_trim - Remove leading and trailing whitespace from a string in place.
 */
static void str_trim(char *s)
{
    if (!s || !*s) return;

    /* Leading whitespace */
    char *start = s;
    while (isspace((unsigned char)*start))
        start++;

    if (start != s)
        memmove(s, start, strlen(start) + 1);

    /* Trailing whitespace */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

/*
 * str_lower - Copy src to dst in lowercase.
 */
static void str_lower(char *dst, const char *src, size_t maxlen)
{
    size_t i;
    for (i = 0; i < maxlen - 1 && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

/*
 * is_sys_file - Check if filename ends with .sys (case-insensitive).
 */
static int is_sys_file(const char *filename)
{
    size_t len = strlen(filename);
    if (len < 4) return 0;

    const char *ext = filename + len - 4;
    return (strcasecmp(ext, ".sys") == 0);
}

/*
 * find_or_create_section - Locate an existing section by name or create a new one.
 * Section name comparison is case-insensitive.
 */
static inf_section_t *find_or_create_section(inf_file_t *inf, const char *name)
{
    char lower_name[256];
    str_lower(lower_name, name, sizeof(lower_name));

    for (int i = 0; i < inf->num_sections; i++) {
        char lower_existing[256];
        str_lower(lower_existing, inf->sections[i].name, sizeof(lower_existing));
        if (strcmp(lower_name, lower_existing) == 0)
            return &inf->sections[i];
    }

    if (inf->num_sections >= INF_MAX_SECTIONS) {
        fprintf(stderr, INF_LOG_PREFIX "Maximum sections (%d) reached\n",
                INF_MAX_SECTIONS);
        return NULL;
    }

    inf_section_t *sec = &inf->sections[inf->num_sections++];
    memset(sec, 0, sizeof(*sec));
    strncpy(sec->name, name, sizeof(sec->name) - 1);
    return sec;
}

/*
 * parse_copyfiles_directive - Parse a CopyFiles directive value.
 * CopyFiles can reference one or more section names (comma-separated)
 * or use @filename for single-file copy.
 */
static int parse_copyfiles_directive(inf_file_t *inf, const char *value)
{
    char buf[1024];
    strncpy(buf, value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *token = strtok(buf, ",");
    while (token) {
        str_trim(token);

        if (token[0] == '@') {
            /* Direct file reference: @filename.sys */
            const char *fname = token + 1;
            if (inf->num_driver_files < INF_MAX_DRIVERS) {
                inf_driver_file_t *df = &inf->driver_files[inf->num_driver_files];
                memset(df, 0, sizeof(*df));
                strncpy(df->filename, fname, sizeof(df->filename) - 1);
                df->is_sys = is_sys_file(fname);
                inf->num_driver_files++;
                fprintf(stderr, INF_LOG_PREFIX "CopyFiles direct: %s (sys=%d)\n",
                        fname, df->is_sys);
            }
        } else {
            /* Section reference - look up the section for file list */
            inf_section_t *sec = find_or_create_section(inf, token);
            if (sec) {
                for (int i = 0; i < sec->num_entries; i++) {
                    const char *fname = sec->entries[i].key;
                    if (fname[0] && inf->num_driver_files < INF_MAX_DRIVERS) {
                        inf_driver_file_t *df =
                            &inf->driver_files[inf->num_driver_files];
                        memset(df, 0, sizeof(*df));
                        strncpy(df->filename, fname, sizeof(df->filename) - 1);
                        df->is_sys = is_sys_file(fname);
                        inf->num_driver_files++;
                        fprintf(stderr, INF_LOG_PREFIX "CopyFiles section '%s': %s\n",
                                token, fname);
                    }
                }
            }
        }

        token = strtok(NULL, ",");
    }

    return 0;
}

/*
 * parse_addreg_directive - Parse entries from an AddReg-referenced section.
 * Each entry has the form: root, subkey, value_name, flags, value_data
 */
static int parse_addreg_directive(inf_file_t *inf, const char *section_name)
{
    inf_section_t *sec = NULL;

    /* Find the section (case-insensitive) */
    char lower_name[256];
    str_lower(lower_name, section_name, sizeof(lower_name));

    for (int i = 0; i < inf->num_sections; i++) {
        char lower_existing[256];
        str_lower(lower_existing, inf->sections[i].name, sizeof(lower_existing));
        if (strcmp(lower_name, lower_existing) == 0) {
            sec = &inf->sections[i];
            break;
        }
    }

    if (!sec) return 0;

    for (int i = 0; i < sec->num_entries; i++) {
        /* Registry entries are stored as full line in the key field */
        char line[1024];
        if (sec->entries[i].value[0])
            snprintf(line, sizeof(line), "%s=%s",
                     sec->entries[i].key, sec->entries[i].value);
        else
            snprintf(line, sizeof(line), "%s", sec->entries[i].key);

        if (inf->num_reg_entries >= INF_MAX_REG_ENTRIES)
            break;

        inf_reg_entry_t *reg = &inf->reg_entries[inf->num_reg_entries];
        memset(reg, 0, sizeof(*reg));

        /* Parse comma-separated fields: root, subkey[, valuename[, flags[, data]]] */
        char *fields[5] = { NULL };
        int nfields = 0;
        char parsebuf[1024];
        strncpy(parsebuf, line, sizeof(parsebuf) - 1);
        parsebuf[sizeof(parsebuf) - 1] = '\0';

        char *p = parsebuf;
        while (nfields < 5 && p) {
            /* Handle quoted strings */
            while (isspace((unsigned char)*p)) p++;
            if (*p == '"') {
                p++;
                fields[nfields] = p;
                char *end = strchr(p, '"');
                if (end) {
                    *end = '\0';
                    p = end + 1;
                    if (*p == ',') p++;
                } else {
                    p = NULL;
                }
            } else {
                fields[nfields] = p;
                char *comma = strchr(p, ',');
                if (comma) {
                    *comma = '\0';
                    p = comma + 1;
                } else {
                    p = NULL;
                }
            }
            if (fields[nfields])
                str_trim(fields[nfields]);
            nfields++;
        }

        if (nfields >= 2) {
            strncpy(reg->root_key, fields[0], sizeof(reg->root_key) - 1);
            strncpy(reg->subkey, fields[1], sizeof(reg->subkey) - 1);
            if (nfields >= 3 && fields[2])
                strncpy(reg->value_name, fields[2], sizeof(reg->value_name) - 1);
            if (nfields >= 4 && fields[3])
                reg->value_type = (int)strtol(fields[3], NULL, 0);
            if (nfields >= 5 && fields[4])
                strncpy(reg->value_data, fields[4], sizeof(reg->value_data) - 1);

            inf->num_reg_entries++;
            fprintf(stderr, INF_LOG_PREFIX "AddReg: %s\\%s  '%s' = '%s'\n",
                    reg->root_key, reg->subkey,
                    reg->value_name, reg->value_data);
        }
    }

    return 0;
}

/*
 * extract_driver_files - Walk parsed sections to find CopyFiles directives
 * and extract driver file references.
 */
static int extract_driver_files(inf_file_t *inf)
{
    /* Check DefaultInstall, DefaultInstall.NT, DefaultInstall.NTamd64, etc. */
    const char *install_sections[] = {
        "DefaultInstall",
        "DefaultInstall.NT",
        "DefaultInstall.NTamd64",
        "DefaultInstall.NTx86",
        NULL
    };

    for (const char **secname = install_sections; *secname; secname++) {
        for (int i = 0; i < inf->num_sections; i++) {
            if (strcasecmp(inf->sections[i].name, *secname) == 0) {
                inf_section_t *sec = &inf->sections[i];
                for (int j = 0; j < sec->num_entries; j++) {
                    if (strcasecmp(sec->entries[j].key, "CopyFiles") == 0) {
                        parse_copyfiles_directive(inf, sec->entries[j].value);
                    }
                }
            }
        }
    }

    /* Also check SourceDisksFiles for .sys files */
    for (int i = 0; i < inf->num_sections; i++) {
        if (strcasecmp(inf->sections[i].name, "SourceDisksFiles") == 0 ||
            strcasecmp(inf->sections[i].name, "SourceDisksFiles.amd64") == 0 ||
            strcasecmp(inf->sections[i].name, "SourceDisksFiles.x86") == 0) {

            inf_section_t *sec = &inf->sections[i];
            for (int j = 0; j < sec->num_entries; j++) {
                if (is_sys_file(sec->entries[j].key)) {
                    /* Check if already in driver_files list */
                    int found = 0;
                    for (int k = 0; k < inf->num_driver_files; k++) {
                        if (strcasecmp(inf->driver_files[k].filename,
                                       sec->entries[j].key) == 0) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found && inf->num_driver_files < INF_MAX_DRIVERS) {
                        inf_driver_file_t *df =
                            &inf->driver_files[inf->num_driver_files++];
                        memset(df, 0, sizeof(*df));
                        strncpy(df->filename, sec->entries[j].key,
                                sizeof(df->filename) - 1);
                        df->is_sys = 1;
                        fprintf(stderr, INF_LOG_PREFIX
                                "SourceDisksFiles .sys: %s\n", df->filename);
                    }
                }
            }
        }
    }

    /* Resolve destination directories from [DestinationDirs] */
    for (int i = 0; i < inf->num_sections; i++) {
        if (strcasecmp(inf->sections[i].name, "DestinationDirs") == 0) {
            inf_section_t *sec = &inf->sections[i];
            for (int j = 0; j < sec->num_entries; j++) {
                /* DefaultDestDir = 12 means %windir%\system32\drivers */
                if (strcasecmp(sec->entries[j].key, "DefaultDestDir") == 0) {
                    int dirid = atoi(sec->entries[j].value);
                    const char *dest = NULL;
                    switch (dirid) {
                    case 10: dest = "%SystemRoot%"; break;
                    case 11: dest = "%SystemRoot%\\system32"; break;
                    case 12: dest = "%SystemRoot%\\system32\\drivers"; break;
                    case 13: dest = "%DriverSource%"; break;
                    default: dest = "%SystemRoot%\\system32"; break;
                    }
                    /* Apply to all driver files without a dest_dir */
                    for (int k = 0; k < inf->num_driver_files; k++) {
                        if (!inf->driver_files[k].dest_dir[0])
                            strncpy(inf->driver_files[k].dest_dir, dest,
                                    sizeof(inf->driver_files[k].dest_dir) - 1);
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * extract_registry_entries - Walk parsed sections to find AddReg directives
 * and extract registry modification entries.
 */
static int extract_registry_entries(inf_file_t *inf)
{
    const char *install_sections[] = {
        "DefaultInstall",
        "DefaultInstall.NT",
        "DefaultInstall.NTamd64",
        "DefaultInstall.NTx86",
        NULL
    };

    for (const char **secname = install_sections; *secname; secname++) {
        for (int i = 0; i < inf->num_sections; i++) {
            if (strcasecmp(inf->sections[i].name, *secname) == 0) {
                inf_section_t *sec = &inf->sections[i];
                for (int j = 0; j < sec->num_entries; j++) {
                    if (strcasecmp(sec->entries[j].key, "AddReg") == 0) {
                        /* AddReg value is comma-separated list of section names */
                        char buf[1024];
                        strncpy(buf, sec->entries[j].value, sizeof(buf) - 1);
                        buf[sizeof(buf) - 1] = '\0';

                        char *tok = strtok(buf, ",");
                        while (tok) {
                            str_trim(tok);
                            parse_addreg_directive(inf, tok);
                            tok = strtok(NULL, ",");
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * inf_parse_file - Parse a Windows .inf file and build the in-memory representation.
 *
 * Returns a heap-allocated inf_file_t on success, NULL on failure.
 * Caller must free with inf_free().
 */
inf_file_t *inf_parse_file(const char *filepath)
{
    if (!filepath) {
        fprintf(stderr, INF_LOG_PREFIX "NULL filepath\n");
        return NULL;
    }

    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, INF_LOG_PREFIX "Failed to open '%s': %s\n",
                filepath, strerror(errno));
        return NULL;
    }

    inf_file_t *inf = calloc(1, sizeof(inf_file_t));
    if (!inf) {
        fprintf(stderr, INF_LOG_PREFIX "Out of memory\n");
        fclose(f);
        return NULL;
    }

    strncpy(inf->filepath, filepath, sizeof(inf->filepath) - 1);

    char line[INF_MAX_LINE];
    inf_section_t *current_section = NULL;
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        /* Strip newline and carriage return (handle both Unix and Windows line endings) */
        line[strcspn(line, "\r\n")] = '\0';
        str_trim(line);

        /* Skip empty lines */
        if (!line[0]) continue;

        /* Skip comments (lines starting with ; or #) */
        if (line[0] == ';' || line[0] == '#') continue;

        /* Handle line continuations (trailing backslash) */
        while (line[0] && line[strlen(line) - 1] == '\\') {
            line[strlen(line) - 1] = '\0';
            char cont[INF_MAX_LINE];
            if (!fgets(cont, sizeof(cont), f)) break;
            line_num++;
            cont[strcspn(cont, "\r\n")] = '\0';
            str_trim(cont);
            /* Append continuation, respecting buffer size */
            size_t remaining = sizeof(line) - strlen(line) - 1;
            if (remaining > 0)
                strncat(line, cont, remaining);
        }

        /* Section header: [SectionName] */
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (!end) {
                fprintf(stderr, INF_LOG_PREFIX
                        "Line %d: malformed section header: %s\n",
                        line_num, line);
                continue;
            }
            *end = '\0';
            const char *secname = line + 1;

            current_section = find_or_create_section(inf, secname);
            if (!current_section) {
                fprintf(stderr, INF_LOG_PREFIX
                        "Line %d: failed to create section '%s'\n",
                        line_num, secname);
            } else {
                fprintf(stderr, INF_LOG_PREFIX "Section: [%s]\n", secname);
            }
            continue;
        }

        /* Key=value or bare entry within a section */
        if (!current_section) {
            fprintf(stderr, INF_LOG_PREFIX
                    "Line %d: entry outside section: %s\n", line_num, line);
            continue;
        }

        if (current_section->num_entries >= INF_MAX_ENTRIES) {
            fprintf(stderr, INF_LOG_PREFIX
                    "Line %d: section '%s' entry limit reached\n",
                    line_num, current_section->name);
            continue;
        }

        inf_entry_t *entry = &current_section->entries[current_section->num_entries];
        memset(entry, 0, sizeof(*entry));

        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            strncpy(entry->key, line, sizeof(entry->key) - 1);
            str_trim(entry->key);
            strncpy(entry->value, eq + 1, sizeof(entry->value) - 1);
            str_trim(entry->value);

            /* Strip surrounding quotes from value */
            size_t vlen = strlen(entry->value);
            if (vlen >= 2 && entry->value[0] == '"' &&
                entry->value[vlen - 1] == '"') {
                memmove(entry->value, entry->value + 1, vlen - 2);
                entry->value[vlen - 2] = '\0';
            }
        } else {
            /* Bare entry (e.g., filename in a file-list section) */
            strncpy(entry->key, line, sizeof(entry->key) - 1);
            str_trim(entry->key);
        }

        current_section->num_entries++;
    }

    fclose(f);

    fprintf(stderr, INF_LOG_PREFIX "Parsed %d sections from '%s'\n",
            inf->num_sections, filepath);

    /* Post-parse extraction */
    extract_driver_files(inf);
    extract_registry_entries(inf);

    fprintf(stderr, INF_LOG_PREFIX "Extracted %d driver files, %d registry entries\n",
            inf->num_driver_files, inf->num_reg_entries);

    return inf;
}

/*
 * inf_get_section - Find a section by name (case-insensitive).
 *
 * Returns a pointer to the section, or NULL if not found.
 */
inf_section_t *inf_get_section(inf_file_t *inf, const char *name)
{
    if (!inf || !name) return NULL;

    char lower_name[256];
    str_lower(lower_name, name, sizeof(lower_name));

    for (int i = 0; i < inf->num_sections; i++) {
        char lower_existing[256];
        str_lower(lower_existing, inf->sections[i].name, sizeof(lower_existing));
        if (strcmp(lower_name, lower_existing) == 0)
            return &inf->sections[i];
    }

    return NULL;
}

/*
 * inf_get_value - Get a value from a specific section by key name.
 *
 * Returns the value string, or NULL if not found.
 * The returned pointer is valid until the inf_file_t is freed.
 */
const char *inf_get_value(inf_file_t *inf, const char *section,
                          const char *key)
{
    if (!inf || !section || !key) return NULL;

    inf_section_t *sec = inf_get_section(inf, section);
    if (!sec) return NULL;

    for (int i = 0; i < sec->num_entries; i++) {
        if (strcasecmp(sec->entries[i].key, key) == 0)
            return sec->entries[i].value;
    }

    return NULL;
}

/*
 * inf_get_driver_files - Get the list of extracted driver files.
 *
 * out_files: receives pointer to the internal array (do not free)
 * out_count: receives the number of driver file entries
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int inf_get_driver_files(inf_file_t *inf, inf_driver_file_t **out_files,
                         int *out_count)
{
    if (!inf || !out_files || !out_count) return -1;

    *out_files = inf->driver_files;
    *out_count = inf->num_driver_files;
    return 0;
}

/*
 * inf_get_registry_entries - Get the list of extracted registry entries.
 *
 * out_entries: receives pointer to the internal array (do not free)
 * out_count:   receives the number of registry entries
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int inf_get_registry_entries(inf_file_t *inf, inf_reg_entry_t **out_entries,
                             int *out_count)
{
    if (!inf || !out_entries || !out_count) return -1;

    *out_entries = inf->reg_entries;
    *out_count = inf->num_reg_entries;
    return 0;
}

/*
 * inf_free - Release all memory associated with a parsed .inf file.
 */
void inf_free(inf_file_t *inf)
{
    if (!inf) return;
    /* All storage is inline within the struct, just free the root */
    free(inf);
}

/*
 * inf_dump - Debug helper: print entire parsed .inf structure to stderr.
 */
void inf_dump(const inf_file_t *inf)
{
    if (!inf) return;

    fprintf(stderr, INF_LOG_PREFIX "=== INF dump: %s ===\n", inf->filepath);
    fprintf(stderr, INF_LOG_PREFIX "Sections: %d\n", inf->num_sections);

    for (int i = 0; i < inf->num_sections; i++) {
        const inf_section_t *sec = &inf->sections[i];
        fprintf(stderr, INF_LOG_PREFIX "  [%s] (%d entries)\n",
                sec->name, sec->num_entries);
        for (int j = 0; j < sec->num_entries; j++) {
            if (sec->entries[j].value[0])
                fprintf(stderr, INF_LOG_PREFIX "    %s = %s\n",
                        sec->entries[j].key, sec->entries[j].value);
            else
                fprintf(stderr, INF_LOG_PREFIX "    %s\n",
                        sec->entries[j].key);
        }
    }

    fprintf(stderr, INF_LOG_PREFIX "Driver files: %d\n", inf->num_driver_files);
    for (int i = 0; i < inf->num_driver_files; i++) {
        const inf_driver_file_t *df = &inf->driver_files[i];
        fprintf(stderr, INF_LOG_PREFIX "  %s (sys=%d, dest=%s)\n",
                df->filename, df->is_sys,
                df->dest_dir[0] ? df->dest_dir : "<default>");
    }

    fprintf(stderr, INF_LOG_PREFIX "Registry entries: %d\n", inf->num_reg_entries);
    for (int i = 0; i < inf->num_reg_entries; i++) {
        const inf_reg_entry_t *reg = &inf->reg_entries[i];
        fprintf(stderr, INF_LOG_PREFIX "  %s\\%s\\%s = %s (type=0x%x)\n",
                reg->root_key, reg->subkey, reg->value_name,
                reg->value_data, reg->value_type);
    }

    fprintf(stderr, INF_LOG_PREFIX "=== end dump ===\n");
}
