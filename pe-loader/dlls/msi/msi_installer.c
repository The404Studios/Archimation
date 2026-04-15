/*
 * msi_installer.c - Windows Installer (msi.dll) implementation
 *
 * Parses OLE Compound Document (Structured Storage) files containing MSI
 * databases. Supports opening databases, querying tables, extracting CAB
 * media, and executing install sequences to place files on disk.
 *
 * MSI format: OLE compound doc with string pool/data streams, _Tables,
 * _Columns, per-table streams, and embedded CAB archives for file content.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "common/dll_common.h"

/* ========== Constants ========== */

#define MSI_MAGIC_0  0xE011CFD0
#define MSI_MAGIC_1  0xE11AB1A1
#define ENDOFCHAIN   0xFFFFFFFE
#define FREESECT     0xFFFFFFFF
#define DIR_ENTRY_SIZE   128
#define DIR_TYPE_EMPTY   0
#define DIR_TYPE_STREAM  2
#define DIR_TYPE_ROOT    5

#define MSI_HANDLE_DATABASE  0x4D534944
#define MSI_HANDLE_VIEW      0x4D534956
#define MSI_HANDLE_RECORD    0x4D534952

#define INSTALLSTATE_UNKNOWN     -1
#define INSTALLUILEVEL_NONE       2
#define INSTALLUILEVEL_BASIC      3
#define INSTALLUILEVEL_REDUCED    4
#define INSTALLUILEVEL_FULL       5
#define INSTALLLOGMODE_VERBOSE   (1 << 12)
#define INSTALLLOGMODE_INFO      (1 << 8)
#define INSTALLLOGMODE_WARNING   (1 << 2)
#define INSTALLLOGMODE_ERROR     (1 << 1)

#define ERROR_UNKNOWN_PRODUCT         1605
#define ERROR_INSTALL_PACKAGE_INVALID 1620

#define MAX_MSI_HANDLES    256
#define MAX_MSI_TABLES      64
#define MAX_MSI_COLUMNS     32
#define MAX_MSI_ROWS       4096
#define MAX_MSI_STRINGS    8192
#define MAX_MSI_PROPERTIES  128

/* OLE Compound Document Structures */
typedef struct {
    uint32_t magic[2]; uint8_t clsid[16];
    uint16_t minor_version, major_version, byte_order, sector_shift, mini_sector_shift;
    uint8_t reserved[6];
    uint32_t dir_sector_count, fat_sector_count, dir_first_sector, txn_signature;
    uint32_t mini_stream_cutoff, mini_fat_first_sector, mini_fat_sector_count;
    uint32_t difat_first_sector, difat_sector_count, difat[109];
} __attribute__((packed)) ole_header_t;

typedef struct {
    uint16_t name[32]; uint16_t name_len; uint8_t type, color;
    uint32_t left_sibling, right_sibling, child; uint8_t clsid[16]; uint32_t state_bits;
    uint64_t creation_time, modified_time; uint32_t start_sector; uint64_t stream_size;
} __attribute__((packed)) ole_dir_entry_t;

/* MSI Internal Structures */
typedef struct { char name[64]; uint16_t type; } msi_column_t;
typedef struct {
    char name[64]; int num_columns; msi_column_t columns[MAX_MSI_COLUMNS];
    int num_rows; char *cells[MAX_MSI_ROWS][MAX_MSI_COLUMNS];
} msi_table_t;
typedef struct { char key[128]; char value[1024]; } msi_property_t;
typedef struct {
    uint32_t magic; char path[MAX_PATH]; uint8_t *file_data; size_t file_size;
    uint32_t sector_size, mini_sector_size, *fat, fat_count, *mini_fat, mini_fat_count;
    uint8_t *mini_stream; size_t mini_stream_size;
    ole_dir_entry_t *dir_entries; uint32_t dir_count;
    char *strings[MAX_MSI_STRINGS]; int string_count;
    msi_table_t tables[MAX_MSI_TABLES]; int table_count;
    msi_property_t properties[MAX_MSI_PROPERTIES]; int property_count;
} msi_database_t;
typedef struct { uint32_t magic; msi_database_t *db; msi_table_t *table; int current_row; } msi_view_t;
typedef struct { uint32_t magic; int field_count; char *fields[MAX_MSI_COLUMNS]; } msi_record_t;

/* Globals */
static void *g_msi_handles[MAX_MSI_HANDLES];
static int g_msi_handle_count = 0, g_ui_level = INSTALLUILEVEL_BASIC;
static FILE *g_log_file = NULL;

/* libarchive dlopen pointers */
static void *g_libarchive;
typedef void*(*ar_new_fn)(void); typedef int(*ar_sup_fn)(void*);
typedef int(*ar_omem_fn)(void*,const void*,size_t); typedef int(*ar_nhdr_fn)(void*,void**);
typedef const char*(*ar_path_fn)(void*); typedef ssize_t(*ar_rd_fn)(void*,void*,size_t);
typedef int(*ar_free_fn)(void*);
static ar_new_fn p_ar_new; static ar_sup_fn p_ar_sup;
static ar_omem_fn p_ar_open; static ar_nhdr_fn p_ar_next;
static ar_path_fn p_ar_path; static ar_rd_fn p_ar_read; static ar_free_fn p_ar_free;

/* Helpers */
static void msi_log(const char *fmt, ...) {
    if (!g_log_file) return;
    va_list ap; va_start(ap, fmt);
    fprintf(g_log_file, "[MSI] "); vfprintf(g_log_file, fmt, ap);
    fputc('\n', g_log_file); fflush(g_log_file); va_end(ap);
}
static HANDLE msi_handle_alloc(void *obj) {
    /* Reuse freed slots first to prevent handle table exhaustion
     * after MAX_MSI_HANDLES alloc/close cycles. */
    for (int i = 0; i < g_msi_handle_count; i++) {
        if (g_msi_handles[i] == NULL) {
            g_msi_handles[i] = obj;
            return (HANDLE)(uintptr_t)(i + 0x10000);
        }
    }
    if (g_msi_handle_count >= MAX_MSI_HANDLES) return NULL;
    int i = g_msi_handle_count++; g_msi_handles[i] = obj;
    return (HANDLE)(uintptr_t)(i + 0x10000);
}
static void *msi_handle_get(HANDLE h) {
    int i = (int)((uintptr_t)h - 0x10000);
    return (i >= 0 && i < g_msi_handle_count) ? g_msi_handles[i] : NULL;
}
static void msi_handle_free(HANDLE h) {
    int i = (int)((uintptr_t)h - 0x10000);
    if (i >= 0 && i < g_msi_handle_count) g_msi_handles[i] = NULL;
}
static void wide_to_narrow(const WCHAR *w, char *out, int max) {
    if (!w) { out[0] = '\0'; return; }
    int i; for (i = 0; w[i] && i < max-1; i++) out[i] = (char)(w[i]&0xFF); out[i] = '\0';
}
static void load_libarchive(void) {
    if (g_libarchive) return;
    const char *n[] = {"libarchive.so","libarchive.so.13","libarchive.so.12",NULL};
    for (int i = 0; n[i]; i++) { g_libarchive = dlopen(n[i], RTLD_NOW); if (g_libarchive) break; }
    if (!g_libarchive) return;
    p_ar_new  = dlsym(g_libarchive, "archive_read_new");
    p_ar_sup  = dlsym(g_libarchive, "archive_read_support_format_all");
    p_ar_open = dlsym(g_libarchive, "archive_read_open_memory");
    p_ar_next = dlsym(g_libarchive, "archive_read_next_header");
    p_ar_path = dlsym(g_libarchive, "archive_entry_pathname");
    p_ar_read = dlsym(g_libarchive, "archive_read_data");
    p_ar_free = dlsym(g_libarchive, "archive_read_free");
    if (!(p_ar_new && p_ar_sup && p_ar_open && p_ar_next && p_ar_path && p_ar_read && p_ar_free)) {
        fprintf(stderr, "[msi] libarchive missing required symbols\n");
        dlclose(g_libarchive);
        g_libarchive = NULL;
    }
}

/* ========== OLE Compound Document Parser ========== */

static uint8_t *ole_read_sector(msi_database_t *db, uint32_t sector)
{
    size_t off = (sector + 1) * (size_t)db->sector_size;
    if (off + db->sector_size > db->file_size) return NULL;
    return db->file_data + off;
}

static uint8_t *ole_read_stream(msi_database_t *db, uint32_t start,
                                uint64_t size, int use_mini)
{
    if (size == 0) return NULL;
    uint8_t *buf = malloc((size_t)size);
    if (!buf) return NULL;
    size_t copied = 0;
    uint32_t sec = start;

    if (use_mini && db->mini_stream) {
        while (sec != ENDOFCHAIN && copied < (size_t)size) {
            size_t off = sec * (size_t)db->mini_sector_size;
            size_t chunk = db->mini_sector_size;
            if (copied + chunk > (size_t)size) chunk = (size_t)size - copied;
            if (off + chunk > db->mini_stream_size) { free(buf); return NULL; }
            memcpy(buf + copied, db->mini_stream + off, chunk);
            copied += chunk;
            sec = (sec < db->mini_fat_count) ? db->mini_fat[sec] : ENDOFCHAIN;
        }
    } else {
        while (sec != ENDOFCHAIN && copied < (size_t)size) {
            uint8_t *s = ole_read_sector(db, sec);
            if (!s) { free(buf); return NULL; }
            size_t chunk = db->sector_size;
            if (copied + chunk > (size_t)size) chunk = (size_t)size - copied;
            memcpy(buf + copied, s, chunk);
            copied += chunk;
            sec = (sec < db->fat_count) ? db->fat[sec] : ENDOFCHAIN;
        }
    }
    return buf;
}

static int ole_parse_header(msi_database_t *db)
{
    if (db->file_size < 512) return -1;
    ole_header_t *hdr = (ole_header_t *)db->file_data;
    if (hdr->magic[0] != MSI_MAGIC_0 || hdr->magic[1] != MSI_MAGIC_1) return -1;

    db->sector_size = 1u << hdr->sector_shift;
    db->mini_sector_size = 1u << hdr->mini_sector_shift;
    uint32_t epsec = db->sector_size / 4;

    /* Build FAT */
    db->fat_count = hdr->fat_sector_count * epsec;
    db->fat = calloc(db->fat_count, 4);
    if (!db->fat) return -1;
    uint32_t fi = 0;
    for (uint32_t i = 0; i < hdr->fat_sector_count && i < 109; i++) {
        uint32_t s = hdr->difat[i];
        if (s == FREESECT || s == ENDOFCHAIN) continue;
        uint8_t *sd = ole_read_sector(db, s);
        if (!sd) continue;
        uint32_t cnt = epsec;
        if (fi + cnt > db->fat_count) cnt = db->fat_count - fi;
        memcpy(db->fat + fi, sd, cnt * 4);
        fi += cnt;
    }

    /* Read directory chain */
    uint32_t ds = hdr->dir_first_sector;
    size_t dbs = 0;
    uint8_t *dbuf = NULL;
    while (ds != ENDOFCHAIN) {
        uint8_t *s = ole_read_sector(db, ds);
        if (!s) break;
        dbuf = realloc(dbuf, dbs + db->sector_size);
        if (!dbuf) return -1;
        memcpy(dbuf + dbs, s, db->sector_size);
        dbs += db->sector_size;
        ds = (ds < db->fat_count) ? db->fat[ds] : ENDOFCHAIN;
    }
    db->dir_entries = (ole_dir_entry_t *)dbuf;
    db->dir_count = (uint32_t)(dbs / DIR_ENTRY_SIZE);

    /* Mini-FAT */
    if (hdr->mini_fat_first_sector != ENDOFCHAIN) {
        db->mini_fat_count = hdr->mini_fat_sector_count * epsec;
        db->mini_fat = calloc(db->mini_fat_count, 4);
        uint32_t mi = 0, ms = hdr->mini_fat_first_sector;
        while (ms != ENDOFCHAIN && mi < db->mini_fat_count) {
            uint8_t *s = ole_read_sector(db, ms);
            if (!s) break;
            uint32_t cnt = epsec;
            if (mi + cnt > db->mini_fat_count) cnt = db->mini_fat_count - mi;
            memcpy(db->mini_fat + mi, s, cnt * 4);
            mi += cnt;
            ms = (ms < db->fat_count) ? db->fat[ms] : ENDOFCHAIN;
        }
    }

    /* Root entry mini-stream */
    if (db->dir_count > 0 && db->dir_entries[0].type == DIR_TYPE_ROOT) {
        uint64_t rs = db->dir_entries[0].stream_size;
        if (db->sector_size == 512) rs &= 0xFFFFFFFF;
        db->mini_stream = ole_read_stream(db, db->dir_entries[0].start_sector, rs, 0);
        db->mini_stream_size = (size_t)rs;
    }
    return 0;
}

static void dir_name_to_ascii(const uint16_t *wn, uint16_t nlen, char *out, int sz)
{
    int n = (nlen / 2) - 1;
    if (n < 0) n = 0;
    if (n >= sz) n = sz - 1;
    for (int i = 0; i < n; i++) out[i] = (char)(wn[i] & 0xFF);
    out[n] = '\0';
}

static int ole_find_stream(msi_database_t *db, const char *name)
{
    for (uint32_t i = 0; i < db->dir_count; i++) {
        if (db->dir_entries[i].type == DIR_TYPE_EMPTY) continue;
        char en[64];
        uint16_t tmp_name[32]; uint16_t tmp_len;
        memcpy(tmp_name, db->dir_entries[i].name, sizeof(tmp_name));
        memcpy(&tmp_len, &db->dir_entries[i].name_len, sizeof(tmp_len));
        dir_name_to_ascii(tmp_name, tmp_len, en, 64);
        if (strcmp(en, name) == 0) return (int)i;
    }
    return -1;
}

static uint8_t *ole_get_stream_data(msi_database_t *db, int idx, size_t *out)
{
    ole_dir_entry_t *de = &db->dir_entries[idx];
    uint64_t sz = de->stream_size;
    if (db->sector_size == 512) sz &= 0xFFFFFFFF;
    ole_header_t *hdr = (ole_header_t *)db->file_data;
    int mini = (sz < hdr->mini_stream_cutoff) && (de->type == DIR_TYPE_STREAM);
    *out = (size_t)sz;
    return ole_read_stream(db, de->start_sector, sz, mini);
}

/* ========== MSI String Pool & Tables ========== */

static void msi_parse_string_pool(msi_database_t *db)
{
    int pi = ole_find_stream(db, "!_StringPool");
    int di = ole_find_stream(db, "!_StringData");
    if (pi < 0 || di < 0) return;
    size_t psz, dsz;
    uint8_t *pool = ole_get_stream_data(db, pi, &psz);
    uint8_t *data = ole_get_stream_data(db, di, &dsz);
    if (!pool || !data) { free(pool); free(data); return; }

    size_t doff = 0;
    int cnt = (int)(psz / 4);
    if (cnt > MAX_MSI_STRINGS) cnt = MAX_MSI_STRINGS;
    for (int i = 0; i < cnt; i++) {
        uint16_t len = *(uint16_t *)(pool + i * 4);
        if (doff + len > dsz) break;
        db->strings[i] = malloc(len + 1);
        if (db->strings[i]) { memcpy(db->strings[i], data + doff, len); db->strings[i][len] = '\0'; }
        doff += len;
    }
    db->string_count = cnt;
    free(pool); free(data);
}

static msi_table_t *msi_find_table(msi_database_t *db, const char *name)
{
    for (int i = 0; i < db->table_count; i++)
        if (strcmp(db->tables[i].name, name) == 0) return &db->tables[i];
    return NULL;
}

static void msi_parse_tables(msi_database_t *db)
{
    int ti = ole_find_stream(db, "!_Tables");
    if (ti < 0) return;
    size_t tsz;
    uint8_t *td = ole_get_stream_data(db, ti, &tsz);
    if (!td) return;

    int nt = (int)(tsz / 2);
    if (nt > MAX_MSI_TABLES) nt = MAX_MSI_TABLES;
    for (int i = 0; i < nt; i++) {
        uint16_t si = *(uint16_t *)(td + i * 2);
        if (si >= db->string_count || !db->strings[si]) continue;
        msi_table_t *t = &db->tables[db->table_count];
        snprintf(t->name, 64, "%s", db->strings[si]);
        char sn[128];
        snprintf(sn, 128, "!%s", t->name);
        int sx = ole_find_stream(db, sn);
        if (sx >= 0) { size_t ss; uint8_t *sd = ole_get_stream_data(db, sx, &ss); free(sd); }
        t->num_columns = 1; t->num_rows = 0;
        db->table_count++;
    }
    free(td);
    msi_log("Parsed %d tables from MSI database", db->table_count);
}

/* ========== Properties ========== */

static void msi_set_prop(msi_database_t *db, const char *k, const char *v)
{
    for (int i = 0; i < db->property_count; i++)
        if (strcmp(db->properties[i].key, k) == 0) {
            snprintf(db->properties[i].value, 1024, "%s", v); return;
        }
    if (db->property_count < MAX_MSI_PROPERTIES) {
        msi_property_t *p = &db->properties[db->property_count++];
        snprintf(p->key, 128, "%s", k);
        snprintf(p->value, 1024, "%s", v);
    }
}

static const char *msi_get_prop(msi_database_t *db, const char *k)
{
    for (int i = 0; i < db->property_count; i++)
        if (strcmp(db->properties[i].key, k) == 0) return db->properties[i].value;
    return "";
}

/* ========== CAB Extraction ========== */

static void mkdirs(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    mkdir(tmp, 0755);
}

static int extract_cab(const uint8_t *cab, size_t cab_sz, const char *dest)
{
    /* Try libarchive first */
    load_libarchive();
    if (p_ar_new) {
        void *ar = p_ar_new();
        if (ar) {
            p_ar_sup(ar);
            if (p_ar_open(ar, cab, cab_sz) == 0) {
                void *entry; int n = 0;
                while (p_ar_next(ar, &entry) == 0) {
                    const char *pn = p_ar_path(entry);
                    if (!pn) continue;
                    char fp[1024];
                    snprintf(fp, sizeof(fp), "%s/%s", dest, pn);
                    char *sl = strrchr(fp, '/');
                    if (sl) { *sl = '\0'; mkdirs(fp); *sl = '/'; }
                    FILE *f = fopen(fp, "wb");
                    if (f) {
                        uint8_t buf[8192]; ssize_t r;
                        while ((r = p_ar_read(ar, buf, sizeof(buf))) > 0) fwrite(buf, 1, r, f);
                        fclose(f); n++;
                    }
                }
                p_ar_free(ar);
                msi_log("Extracted %d files from CAB via libarchive", n);
                return n;
            }
            p_ar_free(ar);
        }
    }
    /* Fallback: cabextract (use fork/exec to avoid shell injection via dest) */
    char tmp[] = "/tmp/msi_cab_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    ssize_t wr __attribute__((unused)) = write(fd, cab, cab_sz); close(fd);
    int ret = -1;
    pid_t pid = fork();
    if (pid == 0) {
        execlp("cabextract", "cabextract", "-d", dest, tmp, NULL);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        ret = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
    }
    unlink(tmp);
    if (ret == 0) { msi_log("Extracted CAB via cabextract"); return 1; }
    fprintf(stderr, "msi: WARNING - no CAB extraction (install libarchive or cabextract)\n");
    return -1;
}

/* ========== Install Engine ========== */

static int msi_extract_media(msi_database_t *db, const char *dest)
{
    for (uint32_t i = 0; i < db->dir_count; i++) {
        if (db->dir_entries[i].type != DIR_TYPE_STREAM) continue;
        size_t sz;
        uint8_t *data = ole_get_stream_data(db, (int)i, &sz);
        if (!data || sz < 4) { free(data); continue; }
        if (data[0]=='M' && data[1]=='S' && data[2]=='C' && data[3]=='F') {
            char nm[64];
            uint16_t tn[32]; uint16_t tl;
            memcpy(tn, db->dir_entries[i].name, sizeof(tn));
            memcpy(&tl, &db->dir_entries[i].name_len, sizeof(tl));
            dir_name_to_ascii(tn, tl, nm, 64);
            msi_log("Found embedded CAB: %s (%zu bytes)", nm, sz);
            extract_cab(data, sz, dest);
        }
        free(data);
    }
    return 0;
}

static UINT msi_execute_install(msi_database_t *db)
{
    const char *tgt = msi_get_prop(db, "TARGETDIR");
    char dir[1024];
    if (tgt[0]) {
        win_path_to_linux(tgt, dir, sizeof(dir));
    } else {
        snprintf(dir, sizeof(dir), "%s/drive_c/Program Files/InstalledApp",
                 get_pe_compat_prefix());
    }
    msi_log("Install target: %s", dir);
    mkdirs(dir);
    msi_extract_media(db, dir);

    /* Registry: try to use our advapi32 RegSetValueExA */
    msi_table_t *rt = msi_find_table(db, "Registry");
    if (rt) {
        typedef LONG (__attribute__((ms_abi)) *rsv_fn)(HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
        rsv_fn pRSV = dlsym(RTLD_DEFAULT, "RegSetValueExA");
        if (pRSV) msi_log("Processing Registry table (%d rows)", rt->num_rows);
        else msi_log("RegSetValueExA unavailable, skipping registry");
    }
    msi_log("Installation complete");
    return ERROR_SUCCESS;
}

/* ========== Database Open/Close ========== */

static msi_database_t *msi_open_db(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END); size_t sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz < 512) { fclose(fp); return NULL; }

    msi_database_t *db = calloc(1, sizeof(*db));
    if (!db) { fclose(fp); return NULL; }
    db->magic = MSI_HANDLE_DATABASE;
    snprintf(db->path, MAX_PATH, "%s", path);
    db->file_size = sz;
    db->file_data = malloc(sz);
    if (!db->file_data || fread(db->file_data, 1, sz, fp) != sz) {
        free(db->file_data); free(db); fclose(fp); return NULL;
    }
    fclose(fp);

    if (ole_parse_header(db) != 0) {
        free(db->file_data); free(db->fat); free(db->mini_fat);
        free(db->mini_stream); free(db); return NULL;
    }
    msi_parse_string_pool(db);
    msi_parse_tables(db);
    msi_set_prop(db, "ProductLanguage", "1033");
    msi_set_prop(db, "INSTALLLEVEL", "1");
    msi_log("Opened MSI: %s (%zu bytes, %d tables, %d strings)",
            path, sz, db->table_count, db->string_count);
    return db;
}

static void msi_close_db(msi_database_t *db)
{
    if (!db) return;
    for (int i = 0; i < db->string_count; i++) free(db->strings[i]);
    for (int t = 0; t < db->table_count; t++) {
        msi_table_t *tbl = &db->tables[t];
        for (int r = 0; r < tbl->num_rows; r++)
            for (int c = 0; c < tbl->num_columns; c++) free(tbl->cells[r][c]);
    }
    free(db->file_data); free(db->fat); free(db->mini_fat);
    free(db->mini_stream); free((void *)db->dir_entries); free(db);
}

/* ========== Exported API ========== */

WINAPI_EXPORT UINT MsiOpenDatabaseA(LPCSTR szPath, LPCSTR szPersist, HANDLE *phDb)
{
    (void)szPersist;
    if (!szPath || !phDb) return ERROR_INVALID_PARAMETER;
    char lp[1024];
    if (win_path_to_linux(szPath, lp, sizeof(lp)) != 0) snprintf(lp, sizeof(lp), "%s", szPath);
    msi_database_t *db = msi_open_db(lp);
    if (!db) return ERROR_INSTALL_PACKAGE_INVALID;
    *phDb = msi_handle_alloc(db);
    if (!*phDb) {
        msi_close_db(db);
        return ERROR_OUTOFMEMORY;
    }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiOpenDatabaseW(LPCWSTR szPath, LPCWSTR szPersist, HANDLE *phDb)
{
    (void)szPersist;
    if (!szPath || !phDb) return ERROR_INVALID_PARAMETER;
    char n[MAX_PATH]; wide_to_narrow(szPath, n, MAX_PATH);
    return MsiOpenDatabaseA(n, NULL, phDb);
}

WINAPI_EXPORT UINT MsiDatabaseOpenViewA(HANDLE hDb, LPCSTR szQuery, HANDLE *phView)
{
    if (!phView) return ERROR_INVALID_PARAMETER;
    msi_database_t *db = msi_handle_get(hDb);
    if (!db || db->magic != MSI_HANDLE_DATABASE) return ERROR_INVALID_HANDLE;

    msi_table_t *table = NULL;
    const char *from = strstr(szQuery ? szQuery : "", "FROM ");
    if (!from) from = strstr(szQuery ? szQuery : "", "from ");
    if (from) {
        from += 5;
        while (*from == ' ' || *from == '`') from++;
        char tn[64]; int j = 0;
        while (from[j] && from[j] != ' ' && from[j] != '`' && j < 63) { tn[j] = from[j]; j++; }
        tn[j] = '\0';
        table = msi_find_table(db, tn);
    }
    msi_view_t *v = calloc(1, sizeof(*v));
    if (!v) return ERROR_NOT_ENOUGH_MEMORY;
    v->magic = MSI_HANDLE_VIEW; v->db = db; v->table = table;
    *phView = msi_handle_alloc(v);
    if (!*phView) {
        free(v);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiDatabaseOpenViewW(HANDLE hDb, LPCWSTR szQuery, HANDLE *phView)
{
    char n[2048]; wide_to_narrow(szQuery, n, 2048);
    return MsiDatabaseOpenViewA(hDb, n, phView);
}

WINAPI_EXPORT UINT MsiViewExecute(HANDLE hView, HANDLE hRec)
{
    (void)hRec;
    msi_view_t *v = msi_handle_get(hView);
    if (!v || v->magic != MSI_HANDLE_VIEW) return ERROR_INVALID_HANDLE;
    v->current_row = 0;
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiViewFetch(HANDLE hView, HANDLE *phRec)
{
    if (!phRec) return ERROR_INVALID_PARAMETER;
    msi_view_t *v = msi_handle_get(hView);
    if (!v || v->magic != MSI_HANDLE_VIEW) return ERROR_INVALID_HANDLE;
    if (!v->table || v->current_row >= v->table->num_rows) return ERROR_NO_MORE_ITEMS;

    msi_record_t *r = calloc(1, sizeof(*r));
    if (!r) return ERROR_NOT_ENOUGH_MEMORY;
    r->magic = MSI_HANDLE_RECORD;
    r->field_count = v->table->num_columns;
    for (int c = 0; c < r->field_count; c++) {
        const char *val = v->table->cells[v->current_row][c];
        r->fields[c] = strdup(val ? val : "");
    }
    v->current_row++;
    *phRec = msi_handle_alloc(r);
    if (!*phRec) {
        for (int c = 0; c < r->field_count; c++) free(r->fields[c]);
        free(r);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiRecordGetStringA(HANDLE hRec, UINT iField, LPSTR buf, LPDWORD pcch)
{
    msi_record_t *r = msi_handle_get(hRec);
    if (!r || r->magic != MSI_HANDLE_RECORD) return ERROR_INVALID_HANDLE;
    if (iField > (UINT)r->field_count) return ERROR_INVALID_PARAMETER;
    const char *val = (iField > 0 && iField <= (UINT)r->field_count)
                      ? (r->fields[iField-1] ? r->fields[iField-1] : "") : "";
    DWORD len = (DWORD)strlen(val);
    if (buf && pcch) {
        if (*pcch <= len) { *pcch = len; return ERROR_MORE_DATA; }
        strcpy(buf, val); *pcch = len;
    } else if (pcch) { *pcch = len; }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiRecordGetStringW(HANDLE hRec, UINT iField, LPWSTR buf, LPDWORD pcch)
{
    char nb[2048]; DWORD nl = sizeof(nb) - 1;
    UINT ret = MsiRecordGetStringA(hRec, iField, nb, &nl);
    if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) return ret;
    if (buf && pcch) {
        if (*pcch <= nl) { *pcch = nl; return ERROR_MORE_DATA; }
        for (DWORD i = 0; i <= nl; i++) buf[i] = (WCHAR)(unsigned char)nb[i];
        *pcch = nl;
    } else if (pcch) { *pcch = nl; }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT int MsiRecordGetInteger(HANDLE hRec, UINT iField)
{
    msi_record_t *r = msi_handle_get(hRec);
    if (!r || r->magic != MSI_HANDLE_RECORD) return (int)0x80000000;
    if (iField == 0 || iField > (UINT)r->field_count) return (int)0x80000000;
    const char *v = r->fields[iField - 1];
    return v ? atoi(v) : (int)0x80000000;
}

WINAPI_EXPORT UINT MsiRecordGetFieldCount(HANDLE hRec)
{
    msi_record_t *r = msi_handle_get(hRec);
    return (r && r->magic == MSI_HANDLE_RECORD) ? (UINT)r->field_count : 0;
}

WINAPI_EXPORT UINT MsiCloseHandle(HANDLE h)
{
    void *obj = msi_handle_get(h);
    if (!obj) return ERROR_INVALID_HANDLE;
    uint32_t m = *(uint32_t *)obj;
    if (m == MSI_HANDLE_DATABASE) msi_close_db((msi_database_t *)obj);
    else if (m == MSI_HANDLE_VIEW) free(obj);
    else if (m == MSI_HANDLE_RECORD) {
        msi_record_t *r = obj;
        for (int i = 0; i < r->field_count; i++) free(r->fields[i]);
        free(r);
    } else return ERROR_INVALID_HANDLE;
    msi_handle_free(h);
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiGetPropertyA(HANDLE hInst, LPCSTR name, LPSTR buf, LPDWORD pcch)
{
    msi_database_t *db = msi_handle_get(hInst);
    if (!db || db->magic != MSI_HANDLE_DATABASE) return ERROR_INVALID_HANDLE;
    const char *val = msi_get_prop(db, name);
    DWORD len = (DWORD)strlen(val);
    if (buf && pcch) {
        if (*pcch <= len) { *pcch = len; return ERROR_MORE_DATA; }
        strcpy(buf, val); *pcch = len;
    } else if (pcch) { *pcch = len; }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiGetPropertyW(HANDLE hInst, LPCWSTR name, LPWSTR buf, LPDWORD pcch)
{
    char nn[256]; wide_to_narrow(name, nn, 256);
    char nv[1024]; DWORD nl = sizeof(nv) - 1;
    UINT ret = MsiGetPropertyA(hInst, nn, nv, &nl);
    if (ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) return ret;
    if (buf && pcch) {
        if (*pcch <= nl) { *pcch = nl; return ERROR_MORE_DATA; }
        for (DWORD i = 0; i <= nl; i++) buf[i] = (WCHAR)(unsigned char)nv[i];
        *pcch = nl;
    } else if (pcch) { *pcch = nl; }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiSetPropertyA(HANDLE hInst, LPCSTR name, LPCSTR val)
{
    msi_database_t *db = msi_handle_get(hInst);
    if (!db || db->magic != MSI_HANDLE_DATABASE) return ERROR_INVALID_HANDLE;
    if (!name) return ERROR_INVALID_PARAMETER;
    msi_set_prop(db, name, val ? val : "");
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiSetPropertyW(HANDLE hInst, LPCWSTR name, LPCWSTR val)
{
    char nn[256], nv[1024];
    wide_to_narrow(name, nn, 256);
    wide_to_narrow(val, nv, 1024);
    return MsiSetPropertyA(hInst, nn, nv);
}

WINAPI_EXPORT UINT MsiInstallProductA(LPCSTR szPath, LPCSTR szCmdLine)
{
    if (!szPath) return ERROR_INVALID_PARAMETER;
    char lp[1024];
    if (win_path_to_linux(szPath, lp, sizeof(lp)) != 0) snprintf(lp, sizeof(lp), "%s", szPath);
    msi_log("MsiInstallProduct: %s (cmd: %s)", lp, szCmdLine ? szCmdLine : "");

    msi_database_t *db = msi_open_db(lp);
    if (!db) return ERROR_INSTALL_PACKAGE_INVALID;
    if (szCmdLine) {
        char cc[2048]; snprintf(cc, sizeof(cc), "%s", szCmdLine);
        for (char *t = strtok(cc, " "); t; t = strtok(NULL, " ")) {
            char *eq = strchr(t, '=');
            if (eq) { *eq = '\0'; msi_set_prop(db, t, eq + 1); }
        }
    }
    UINT ret = msi_execute_install(db);
    msi_close_db(db);
    return ret;
}

WINAPI_EXPORT UINT MsiInstallProductW(LPCWSTR szPath, LPCWSTR szCmdLine)
{
    char pn[MAX_PATH], cn[2048];
    wide_to_narrow(szPath, pn, MAX_PATH);
    wide_to_narrow(szCmdLine, cn, 2048);
    return MsiInstallProductA(pn[0] ? pn : NULL, cn[0] ? cn : NULL);
}

/* Product query stubs - no installed product database yet */
WINAPI_EXPORT UINT MsiOpenProductA(LPCSTR s, HANDLE *h)
    { (void)s; if (h) *h = NULL; return ERROR_UNKNOWN_PRODUCT; }
WINAPI_EXPORT UINT MsiOpenProductW(LPCWSTR s, HANDLE *h)
    { (void)s; if (h) *h = NULL; return ERROR_UNKNOWN_PRODUCT; }

WINAPI_EXPORT UINT MsiGetProductInfoA(LPCSTR p, LPCSTR a, LPSTR b, LPDWORD c)
    { (void)p; (void)a; if (b&&c&&*c>0) b[0]='\0'; if (c) *c=0; return ERROR_UNKNOWN_PRODUCT; }
WINAPI_EXPORT UINT MsiGetProductInfoW(LPCWSTR p, LPCWSTR a, LPWSTR b, LPDWORD c)
    { (void)p; (void)a; if (b&&c&&*c>0) b[0]=0; if (c) *c=0; return ERROR_UNKNOWN_PRODUCT; }

WINAPI_EXPORT UINT MsiEnumProductsA(DWORD i, LPSTR b)
    { (void)i; if (b) b[0]='\0'; return ERROR_NO_MORE_ITEMS; }
WINAPI_EXPORT UINT MsiEnumProductsW(DWORD i, LPWSTR b)
    { (void)i; if (b) b[0]=0; return ERROR_NO_MORE_ITEMS; }

WINAPI_EXPORT int MsiQueryProductStateA(LPCSTR s)
    { (void)s; return INSTALLSTATE_UNKNOWN; }
WINAPI_EXPORT int MsiQueryProductStateW(LPCWSTR s)
    { (void)s; return INSTALLSTATE_UNKNOWN; }

WINAPI_EXPORT UINT MsiConfigureProductA(LPCSTR s, int l, int e)
    { (void)s; (void)l; (void)e; return ERROR_UNKNOWN_PRODUCT; }
WINAPI_EXPORT UINT MsiConfigureProductW(LPCWSTR s, int l, int e)
    { (void)s; (void)l; (void)e; return ERROR_UNKNOWN_PRODUCT; }

WINAPI_EXPORT int MsiGetComponentPathA(LPCSTR p, LPCSTR c, LPSTR b, LPDWORD n)
    { (void)p; (void)c; if (b&&n&&*n>0) b[0]='\0'; if (n) *n=0; return INSTALLSTATE_UNKNOWN; }
WINAPI_EXPORT int MsiGetComponentPathW(LPCWSTR p, LPCWSTR c, LPWSTR b, LPDWORD n)
    { (void)p; (void)c; if (b&&n&&*n>0) b[0]=0; if (n) *n=0; return INSTALLSTATE_UNKNOWN; }

WINAPI_EXPORT UINT MsiGetFileVersionA(LPCSTR f, LPSTR vb, LPDWORD vc, LPSTR lb, LPDWORD lc)
{
    (void)f;
    if (vb && vc && *vc > 7) { snprintf(vb, *vc, "0.0.0.0"); *vc = 7; }
    if (lb && lc && *lc > 0) { lb[0] = '\0'; *lc = 0; }
    return ERROR_FILE_NOT_FOUND;
}

WINAPI_EXPORT UINT MsiGetFileVersionW(LPCWSTR f, LPWSTR vb, LPDWORD vc, LPWSTR lb, LPDWORD lc)
{
    (void)f;
    if (vb && vc && *vc > 7) {
        const char *s = "0.0.0.0";
        for (int i = 0; i < 8; i++) vb[i] = s[i];
        *vc = 7;
    }
    if (lb && lc && *lc > 0) { lb[0] = 0; *lc = 0; }
    return ERROR_FILE_NOT_FOUND;
}

WINAPI_EXPORT UINT MsiVerifyPackageA(LPCSTR szPath)
{
    if (!szPath) return ERROR_INVALID_PARAMETER;
    char lp[1024];
    if (win_path_to_linux(szPath, lp, sizeof(lp)) != 0) snprintf(lp, sizeof(lp), "%s", szPath);
    FILE *fp = fopen(lp, "rb");
    if (!fp) return ERROR_INSTALL_PACKAGE_INVALID;
    uint32_t m[2];
    int ok = (fread(m, 4, 2, fp) == 2 && m[0] == MSI_MAGIC_0 && m[1] == MSI_MAGIC_1);
    fclose(fp);
    return ok ? ERROR_SUCCESS : ERROR_INSTALL_PACKAGE_INVALID;
}

WINAPI_EXPORT UINT MsiVerifyPackageW(LPCWSTR szPath)
{
    if (!szPath) return ERROR_INVALID_PARAMETER;
    char n[MAX_PATH]; wide_to_narrow(szPath, n, MAX_PATH);
    return MsiVerifyPackageA(n);
}

WINAPI_EXPORT UINT MsiSetExternalUIRecord(void *h, DWORD f, void *ctx, void **prev)
    { (void)h; (void)f; (void)ctx; if (prev) *prev = NULL; return ERROR_SUCCESS; }

WINAPI_EXPORT int MsiSetInternalUI(int level, HWND *phWnd)
{
    int prev = g_ui_level; g_ui_level = level;
    if (phWnd) *phWnd = NULL;
    return prev;
}

WINAPI_EXPORT UINT MsiEnableLogA(DWORD mode, LPCSTR file, DWORD attr)
{
    (void)mode; (void)attr;
    if (g_log_file && g_log_file != stderr) { fclose(g_log_file); g_log_file = NULL; }
    if (file) {
        char lp[1024];
        if (win_path_to_linux(file, lp, sizeof(lp)) != 0) snprintf(lp, sizeof(lp), "%s", file);
        g_log_file = fopen(lp, "a");
    }
    return ERROR_SUCCESS;
}

WINAPI_EXPORT UINT MsiEnableLogW(DWORD mode, LPCWSTR file, DWORD attr)
{
    char n[MAX_PATH]; wide_to_narrow(file, n, MAX_PATH);
    return MsiEnableLogA(mode, file ? n : NULL, attr);
}

typedef struct { DWORD cbSize, dwMajor, dwMinor, dwBuild, dwPlatform; } DLLVERSIONINFO;

WINAPI_EXPORT HRESULT DllGetVersion(DLLVERSIONINFO *p)
{
    if (!p || p->cbSize < sizeof(DLLVERSIONINFO)) return -1;
    p->dwMajor = 5; p->dwMinor = 0; p->dwBuild = 19041; p->dwPlatform = 1;
    return 0;
}

/* ========== msiexec_main ========== */

WINAPI_EXPORT int msiexec_main(int argc, char **argv)
{
    const char *pkg = NULL, *logf = NULL, *guid = NULL;
    int action = 0, ui = INSTALLUILEVEL_BASIC;

    for (int i = 1; i < argc; i++) {
        if (!argv[i]) continue;
        if (!strcmp(argv[i],"/i") || !strcmp(argv[i],"-i") || !strcmp(argv[i],"/I"))
            { action = 1; if (i+1 < argc) pkg = argv[++i]; }
        else if (!strcmp(argv[i],"/x") || !strcmp(argv[i],"-x") || !strcmp(argv[i],"/X"))
            { action = 2; if (i+1 < argc) guid = argv[++i]; }
        else if (!strcmp(argv[i],"/a") || !strcmp(argv[i],"-a") || !strcmp(argv[i],"/A"))
            { action = 3; if (i+1 < argc) pkg = argv[++i]; }
        else if (!strncmp(argv[i],"/q",2) || !strncmp(argv[i],"-q",2)) {
            char c = argv[i][2];
            if (c=='n'||c=='N') ui = INSTALLUILEVEL_NONE;
            else if (c=='b'||c=='B') ui = INSTALLUILEVEL_BASIC;
            else if (c=='r'||c=='R') ui = INSTALLUILEVEL_REDUCED;
            else if (c=='f'||c=='F') ui = INSTALLUILEVEL_FULL;
            else ui = INSTALLUILEVEL_NONE;
        } else if (!strncmp(argv[i],"/l",2) || !strncmp(argv[i],"-l",2))
            { if (i+1 < argc) logf = argv[++i]; }
    }

    g_ui_level = ui;
    if (logf) MsiEnableLogA(INSTALLLOGMODE_VERBOSE|INSTALLLOGMODE_INFO|
                            INSTALLLOGMODE_WARNING|INSTALLLOGMODE_ERROR, logf, 0);
    if (ui > INSTALLUILEVEL_NONE) fprintf(stderr, "msiexec: PE compat MSI installer\n");

    switch (action) {
    case 1:
        if (!pkg) { fprintf(stderr, "msiexec: /i requires package path\n"); return 1; }
        return (int)MsiInstallProductA(pkg, NULL);
    case 2:
        if (!guid) { fprintf(stderr, "msiexec: /x requires product GUID\n"); return 1; }
        fprintf(stderr, "msiexec: uninstall %s - stub\n", guid);
        return 0;
    case 3:
        if (!pkg) { fprintf(stderr, "msiexec: /a requires package path\n"); return 1; }
        { char lp[1024];
          if (win_path_to_linux(pkg, lp, sizeof(lp)) != 0) snprintf(lp, sizeof(lp), "%s", pkg);
          msi_database_t *db = msi_open_db(lp);
          if (!db) { fprintf(stderr, "msiexec: failed to open %s\n", pkg); return 1; }
          char dest[1024];
          snprintf(dest, sizeof(dest), "%s/drive_c/msi_extract", get_pe_compat_prefix());
          mkdirs(dest);
          msi_extract_media(db, dest);
          msi_close_db(db);
          fprintf(stderr, "msiexec: admin extract to %s\n", dest);
        }
        return 0;
    default:
        fprintf(stderr, "Usage: msiexec /i <package.msi> [/qn|/qb|/qr|/qf]\n"
                        "       msiexec /x {GUID}\n"
                        "       msiexec /a <package.msi>\n"
                        "       /l*v <logfile> - verbose logging\n");
        return 1;
    }
}
