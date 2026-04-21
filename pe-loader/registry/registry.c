/*
 * registry.c - Windows Registry emulation
 *
 * Two-tier architecture (rewritten in Session 30 perf pass):
 *   Tier 1 - in-memory tree cache (hot path):
 *     - tree rooted at g_root with 5 pre-allocated hive nodes (HKLM/HKCU/HKCR/HKU/HKCC)
 *     - each node owns a hash table of child subkeys and a hash table of values
 *     - FNV-1a case-insensitive hashing (Windows registry is case-insensitive)
 *     - global per-path hash cache maps full backslash-path -> reg_node_t*
 *       for O(1) RegOpenKeyEx on repeat reads (the anti-cheat workload)
 *     - reader-writer lock: unlimited parallel readers, writers rare
 *
 *   Tier 2 - filesystem-backed persistence:
 *     - keys -> directories, values -> files under ~/.pe-compat/registry/
 *     - read-through lazy load: node's disk contents are slurped on first touch
 *     - write-through: RegSetValueEx / RegCreateKeyEx mirror to disk
 *
 * Design goals: anti-cheat issues ~80 registry reads per scan; each used to
 * do 2-3 syscalls (stat + fopen + fread + fclose).  With the tree cache hot,
 * each read becomes 2 hash lookups + memcpy -- roughly 100x faster.
 *
 * HKCR merge-view semantics (HKCU\SOFTWARE\Classes overlays HKLM\SOFTWARE\Classes)
 * is preserved.  Legacy ~/.pe-compat/registry/HKCR/ directory is still checked
 * as a fallback for older callers that wrote there directly.
 */

/* Path operations intentionally allow truncation for safety */
#pragma GCC diagnostic ignored "-Wformat-truncation"
#pragma GCC diagnostic ignored "-Wstringop-truncation"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strcasecmp, strncasecmp */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>

#include "registry.h"

/* ---------------------------------------------------------------------- */
/* Constants                                                              */
/* ---------------------------------------------------------------------- */

/* Predefined HKEY values (same as Windows) */
#define HKEY_CLASSES_ROOT     ((HKEY)(uintptr_t)0x80000000)
#define HKEY_CURRENT_USER     ((HKEY)(uintptr_t)0x80000001)
#define HKEY_LOCAL_MACHINE    ((HKEY)(uintptr_t)0x80000002)
#define HKEY_USERS            ((HKEY)(uintptr_t)0x80000003)
#define HKEY_CURRENT_CONFIG   ((HKEY)(uintptr_t)0x80000005)

/* Registry value types */
#define REG_NONE         0
#define REG_SZ           1
#define REG_EXPAND_SZ    2
#define REG_BINARY       3
#define REG_DWORD        4
#define REG_DWORD_BIG_ENDIAN 5
#define REG_MULTI_SZ     7
#define REG_QWORD        11

/* Error codes */
#define ERROR_SUCCESS           0
#define ERROR_FILE_NOT_FOUND    2
#define ERROR_ACCESS_DENIED     5
#define ERROR_INVALID_HANDLE    6
#define ERROR_OUTOFMEMORY       14
#define ERROR_INVALID_PARAMETER 87
#define ERROR_MORE_DATA         234
#define ERROR_NO_MORE_ITEMS     259

/* Path-cache bucket count (power of two).  Kept small for old-HW memory
 * budgets: 512 * sizeof(void*) = 4KB on x86_64. Collisions resolved by
 * open-addressing linear probing. */
#define PATH_CACHE_BUCKETS  512
#define PATH_CACHE_MASK     (PATH_CACHE_BUCKETS - 1)

/* Per-key child/value hash table - small power-of-two initial size.
 * Grown adaptively when load factor exceeds 0.75. */
#define NODE_HASH_INITIAL   8

/* Per-component max length.  Windows says 255 for key names, 16383 for values. */
#define KEY_NAME_MAX        256
#define VALUE_NAME_MAX      256
#define PATH_BUF_MAX        4096

/* ---------------------------------------------------------------------- */
/* Hashing (FNV-1a, case-insensitive ASCII)                               */
/* ---------------------------------------------------------------------- */

#define FNV1A_OFFSET_64   0xcbf29ce484222325ULL
#define FNV1A_PRIME_64    0x100000001b3ULL

/* Branchless ASCII tolower: for 'A'..'Z', OR with 0x20; for other bytes
 * this may also flip bit 0x20 but we only use this for hashing/compare,
 * and we apply the same transform to both sides, so mismatch is impossible. */
static inline unsigned char ci_fold(unsigned char c)
{
    /* Only fold ASCII letters; preserve everything else unchanged. */
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20) : c;
}

static inline uint64_t fnv1a_ci(const char *s)
{
    uint64_t h = FNV1A_OFFSET_64;
    if (!s) return h;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= (uint64_t)ci_fold(*p);
        h *= FNV1A_PRIME_64;
    }
    return h;
}

/* Hash a path but normalise '/' and '\\' to '\\' to make
 * "Software/Foo" and "Software\\Foo" hash the same. */
static inline uint64_t fnv1a_ci_path(const char *s)
{
    uint64_t h = FNV1A_OFFSET_64;
    if (!s) return h;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '/') c = '\\';
        else c = ci_fold(c);
        h ^= (uint64_t)c;
        h *= FNV1A_PRIME_64;
    }
    return h;
}

/* Case-insensitive equality, optimised: compares folded bytes inline. */
static inline int ci_streq(const char *a, const char *b)
{
    if (a == b) return 1;
    if (!a || !b) return 0;
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    while (*pa && *pb) {
        if (ci_fold(*pa) != ci_fold(*pb)) return 0;
        pa++; pb++;
    }
    return *pa == 0 && *pb == 0;
}

/* ---------------------------------------------------------------------- */
/* In-memory registry node                                                */
/* ---------------------------------------------------------------------- */

typedef struct reg_value {
    char    *name;        /* interned (owned); "" means default value ("@") */
    DWORD    type;
    DWORD    size;        /* bytes */
    void    *data;        /* owned, malloc'd (may be NULL if size==0) */
    uint64_t name_hash;   /* cached FNV-1a of name for fast probe */
} reg_value_t;

typedef struct reg_node {
    char              *name;          /* component name (owned); NULL for root */
    uint64_t           name_hash;     /* cached hash of name (for parent lookups) */

    struct reg_node   *parent;

    /* Child subkey hash table (open addressing, NULL = empty slot).
     * Indexed by ci-fold FNV-1a of child name. */
    struct reg_node  **children;
    uint32_t           child_count;
    uint32_t           child_cap;     /* must be power of two */

    /* Value hash table (same open-addressing layout as children). */
    reg_value_t      **values;
    uint32_t           value_count;
    uint32_t           value_cap;

    /* Filesystem backing (absolute path).  NULL for virtual-only nodes
     * (e.g. synthetic HKCR root, which is a merge view of HKLM/HKCU).
     * Non-NULL means we may write-through to this location. */
    char              *fs_path;

    /* true once we've run our one-time lazy scan of fs_path into this
     * node's children/values.  Prevents re-scanning on every read. */
    unsigned int       loaded : 1;

    /* true for the 5 predefined hive roots + their ancestors used by the
     * HKCR merge resolver.  Never freed. */
    unsigned int       is_hive : 1;
} reg_node_t;

/* Handle data (what we hang off a registry HKEY handle). */
typedef struct {
    reg_node_t *node;        /* owning pointer stable for lifetime of handle */
    DWORD       enum_index;  /* for RegEnumKeyEx / RegEnumValue */
    /* Keep a copy of the filesystem path in case callers want to use it
     * (e.g. legacy reg_key_data_t consumers).  Not required for reads. */
    char        path[PATH_BUF_MAX];
} reg_key_data_t;

/* ---------------------------------------------------------------------- */
/* Global state                                                           */
/* ---------------------------------------------------------------------- */

static char g_registry_root[PATH_BUF_MAX] = {0};

/* Hive roots.  Pointers are stable after first init.  HKCR is a
 * synthetic virtual node; its children are resolved by merge lookup. */
static reg_node_t *g_hive_hklm = NULL;
static reg_node_t *g_hive_hkcu = NULL;
static reg_node_t *g_hive_hkcr = NULL;
static reg_node_t *g_hive_hku  = NULL;
static reg_node_t *g_hive_hkcc = NULL;

/* Path cache: maps canonical "HIVE\\subkey\\path" -> reg_node_t*.
 * Open-addressing linear probing.  key stored by pointer (owned). */
typedef struct {
    uint64_t    hash;
    char       *key;        /* canonical uppercase-folded path, owned */
    reg_node_t *node;       /* not owned (the tree owns it) */
} path_cache_entry_t;

static path_cache_entry_t g_path_cache[PATH_CACHE_BUCKETS];

/* Global registry lock.  Reads are 99%+ of traffic (anti-cheat scans)
 * so we use rwlock for maximum parallelism. */
static pthread_rwlock_t g_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static pthread_once_t g_reg_once = PTHREAD_ONCE_INIT;

/* ---------------------------------------------------------------------- */
/* Forward decls                                                          */
/* ---------------------------------------------------------------------- */

static void reg_init_once(void);
static reg_node_t *node_new(const char *name, reg_node_t *parent, const char *fs_path, int is_hive);
static reg_node_t *node_find_child(reg_node_t *n, const char *name, uint64_t hash);
static reg_node_t *node_insert_child(reg_node_t *n, reg_node_t *child);
static reg_value_t *node_find_value(reg_node_t *n, const char *name, uint64_t hash);
static reg_value_t *node_upsert_value(reg_node_t *n, const char *name, DWORD type, const void *data, DWORD size);
static void node_ensure_loaded(reg_node_t *n);
static reg_node_t *resolve_path(reg_node_t *root, const char *subpath, int create);
static reg_node_t *resolve_hkey(HKEY hk);
static void path_cache_invalidate_all(void);
static int mkdir_recursive(const char *path);

/* ---------------------------------------------------------------------- */
/* Utility                                                                */
/* ---------------------------------------------------------------------- */

/* Reject path components that could escape the registry root. */
static int registry_validate_name(const char *name)
{
    if (!name || !*name)
        return 0;  /* empty is OK (root key) */
    if (name[0] == '/' || name[0] == '\\')
        return -1;

    const char *p = name;
    const char *comp = name;
    while (1) {
        char c = *p;
        if (c == '\\' || c == '/' || c == '\0') {
            size_t len = (size_t)(p - comp);
            if (len == 2 && comp[0] == '.' && comp[1] == '.')
                return -1;
            if (len == 1 && comp[0] == '.')
                return -1;
            /* Bound each component to prevent DoS via pathological names */
            if (len >= KEY_NAME_MAX)
                return -1;
            if (c == '\0') break;
            comp = p + 1;
        }
        p++;
    }
    return 0;
}

/* Mask off high 32 bits from an HKEY pseudo-handle.
 *
 * MinGW PE binaries pass HKEY as a signed LONG (HKEY in <winreg.h> is a typedef
 * of HANDLE which is a void*, but many apps cast through long). Sign extension
 * turns 0x80000001 into 0xFFFFFFFF80000001 on 64-bit, which then misses our
 * range check and switch statements. Apply this mask everywhere we compare an
 * HKEY to a 0x80000000-series constant. Session 68 audit restored this fix
 * after it drifted out of tree (S67 memory claimed it was applied; it wasn't).
 */
static inline uint32_t hkey_low32(HKEY hKey)
{
    return (uint32_t)((uintptr_t)hKey & 0xFFFFFFFFu);
}

/* Predefined HKEY? */
static int is_predefined_hkey(HKEY hKey)
{
    uint32_t v = hkey_low32(hKey);
    return (v >= 0x80000000u && v <= 0x80000005u);
}

static const char *hkey_to_prefix(HKEY hKey)
{
    switch (hkey_low32(hKey)) {
    case 0x80000000u: return "HKCR";
    case 0x80000001u: return "HKCU";
    case 0x80000002u: return "HKLM";
    case 0x80000003u: return "HKU";
    case 0x80000005u: return "HKCC";
    default:          return NULL;
    }
}

/* Create dirs recursively. */
static int mkdir_recursive(const char *path)
{
    char tmp[PATH_BUF_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/* ---------------------------------------------------------------------- */
/* Node allocation                                                        */
/* ---------------------------------------------------------------------- */

static reg_node_t *node_new(const char *name, reg_node_t *parent,
                            const char *fs_path, int is_hive)
{
    reg_node_t *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    if (name) {
        n->name = strdup(name);
        if (!n->name) { free(n); return NULL; }
        n->name_hash = fnv1a_ci(name);
    }
    n->parent = parent;
    if (fs_path) n->fs_path = strdup(fs_path);
    n->is_hive = !!is_hive;
    n->child_cap = 0;
    n->value_cap = 0;
    return n;
}

/* Grow the child hash table.  old_cap==0 triggers initial alloc. */
static int node_grow_children(reg_node_t *n)
{
    uint32_t new_cap = n->child_cap ? n->child_cap * 2 : NODE_HASH_INITIAL;
    reg_node_t **new_tbl = calloc(new_cap, sizeof(*new_tbl));
    if (!new_tbl) return -1;
    uint32_t mask = new_cap - 1;
    for (uint32_t i = 0; i < n->child_cap; i++) {
        reg_node_t *c = n->children[i];
        if (!c) continue;
        uint32_t slot = (uint32_t)(c->name_hash) & mask;
        while (new_tbl[slot]) slot = (slot + 1) & mask;
        new_tbl[slot] = c;
    }
    free(n->children);
    n->children = new_tbl;
    n->child_cap = new_cap;
    return 0;
}

static int node_grow_values(reg_node_t *n)
{
    uint32_t new_cap = n->value_cap ? n->value_cap * 2 : NODE_HASH_INITIAL;
    reg_value_t **new_tbl = calloc(new_cap, sizeof(*new_tbl));
    if (!new_tbl) return -1;
    uint32_t mask = new_cap - 1;
    for (uint32_t i = 0; i < n->value_cap; i++) {
        reg_value_t *v = n->values[i];
        if (!v) continue;
        uint32_t slot = (uint32_t)(v->name_hash) & mask;
        while (new_tbl[slot]) slot = (slot + 1) & mask;
        new_tbl[slot] = v;
    }
    free(n->values);
    n->values = new_tbl;
    n->value_cap = new_cap;
    return 0;
}

static reg_node_t *node_find_child(reg_node_t *n, const char *name, uint64_t hash)
{
    if (!n || !n->children || n->child_cap == 0) return NULL;
    uint32_t mask = n->child_cap - 1;
    uint32_t slot = (uint32_t)hash & mask;
    for (uint32_t i = 0; i < n->child_cap; i++) {
        reg_node_t *c = n->children[slot];
        if (!c) return NULL;
        if (c->name_hash == hash && ci_streq(c->name, name))
            return c;
        slot = (slot + 1) & mask;
    }
    return NULL;
}

static reg_node_t *node_insert_child(reg_node_t *n, reg_node_t *child)
{
    /* Grow if load factor > 0.75 */
    if (n->child_cap == 0 ||
        (n->child_count + 1) * 4 > n->child_cap * 3) {
        if (node_grow_children(n) < 0) return NULL;
    }
    uint32_t mask = n->child_cap - 1;
    uint32_t slot = (uint32_t)(child->name_hash) & mask;
    while (n->children[slot]) {
        /* Duplicate - caller should have checked, but return existing. */
        reg_node_t *c = n->children[slot];
        if (c->name_hash == child->name_hash && ci_streq(c->name, child->name))
            return c;
        slot = (slot + 1) & mask;
    }
    n->children[slot] = child;
    n->child_count++;
    child->parent = n;
    return child;
}

static reg_value_t *node_find_value(reg_node_t *n, const char *name, uint64_t hash)
{
    if (!n || !n->values || n->value_cap == 0) return NULL;
    uint32_t mask = n->value_cap - 1;
    uint32_t slot = (uint32_t)hash & mask;
    for (uint32_t i = 0; i < n->value_cap; i++) {
        reg_value_t *v = n->values[slot];
        if (!v) return NULL;
        if (v->name_hash == hash && ci_streq(v->name, name))
            return v;
        slot = (slot + 1) & mask;
    }
    return NULL;
}

static reg_value_t *node_upsert_value(reg_node_t *n, const char *name,
                                      DWORD type, const void *data, DWORD size)
{
    const char *vname = name ? name : "";
    uint64_t h = fnv1a_ci(vname);
    reg_value_t *existing = node_find_value(n, vname, h);
    if (existing) {
        /* Replace payload */
        void *new_data = NULL;
        if (data && size) {
            new_data = malloc(size);
            if (!new_data) return NULL;
            memcpy(new_data, data, size);
        }
        free(existing->data);
        existing->data = new_data;
        existing->size = size;
        existing->type = type;
        return existing;
    }

    if (n->value_cap == 0 ||
        (n->value_count + 1) * 4 > n->value_cap * 3) {
        if (node_grow_values(n) < 0) return NULL;
    }

    reg_value_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    v->name = strdup(vname);
    if (!v->name) { free(v); return NULL; }
    v->name_hash = h;
    v->type = type;
    v->size = size;
    if (data && size) {
        v->data = malloc(size);
        if (!v->data) { free(v->name); free(v); return NULL; }
        memcpy(v->data, data, size);
    }

    uint32_t mask = n->value_cap - 1;
    uint32_t slot = (uint32_t)h & mask;
    while (n->values[slot]) slot = (slot + 1) & mask;
    n->values[slot] = v;
    n->value_count++;
    return v;
}

static int node_remove_value(reg_node_t *n, const char *name)
{
    if (!n || !n->values || n->value_cap == 0) return -1;
    const char *vname = name ? name : "";
    uint64_t h = fnv1a_ci(vname);
    uint32_t mask = n->value_cap - 1;
    uint32_t slot = (uint32_t)h & mask;
    for (uint32_t i = 0; i < n->value_cap; i++) {
        reg_value_t *v = n->values[slot];
        if (!v) return -1;
        if (v->name_hash == h && ci_streq(v->name, vname)) {
            free(v->name);
            free(v->data);
            free(v);
            n->values[slot] = NULL;
            n->value_count--;
            /* Re-insert successors in the probe chain (Robin Hood would
             * be nicer but this is simpler & correct for open addressing). */
            uint32_t next = (slot + 1) & mask;
            while (n->values[next]) {
                reg_value_t *moved = n->values[next];
                n->values[next] = NULL;
                uint32_t ns = (uint32_t)moved->name_hash & mask;
                while (n->values[ns]) ns = (ns + 1) & mask;
                n->values[ns] = moved;
                next = (next + 1) & mask;
            }
            return 0;
        }
        slot = (slot + 1) & mask;
    }
    return -1;
}

static int node_remove_child(reg_node_t *n, const char *name)
{
    if (!n || !n->children || n->child_cap == 0) return -1;
    uint64_t h = fnv1a_ci(name);
    uint32_t mask = n->child_cap - 1;
    uint32_t slot = (uint32_t)h & mask;
    for (uint32_t i = 0; i < n->child_cap; i++) {
        reg_node_t *c = n->children[slot];
        if (!c) return -1;
        if (c->name_hash == h && ci_streq(c->name, name)) {
            /* Only allow removal if subtree empty (Windows RegDeleteKey semantics) */
            if (c->child_count > 0 || c->value_count > 0) return -2;
            free(c->name);
            free(c->fs_path);
            free(c->children);
            free(c->values);
            free(c);
            n->children[slot] = NULL;
            n->child_count--;
            uint32_t next = (slot + 1) & mask;
            while (n->children[next]) {
                reg_node_t *moved = n->children[next];
                n->children[next] = NULL;
                uint32_t ns = (uint32_t)moved->name_hash & mask;
                while (n->children[ns]) ns = (ns + 1) & mask;
                n->children[ns] = moved;
                next = (next + 1) & mask;
            }
            return 0;
        }
        slot = (slot + 1) & mask;
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/* Lazy filesystem loader                                                 */
/* ---------------------------------------------------------------------- */

/* Slurp values from this node's disk .values/ directory into the hash table.
 * Caller holds write lock.  Called at most once per node via ->loaded. */
static void node_load_values_from_disk(reg_node_t *n)
{
    if (!n || !n->fs_path) return;
    char values_dir[PATH_BUF_MAX];
    snprintf(values_dir, sizeof(values_dir), "%s/.values", n->fs_path);
    DIR *d = opendir(values_dir);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') {
            if (ent->d_name[1] == '\0') continue;
            if (ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue;
        }
        char vp[PATH_BUF_MAX];
        snprintf(vp, sizeof(vp), "%s/%s", values_dir, ent->d_name);
        FILE *f = fopen(vp, "rb");
        if (!f) continue;
        DWORD vtype = 0;
        if (fread(&vtype, sizeof(DWORD), 1, f) != 1) {
            fclose(f); continue;
        }
        fseek(f, 0, SEEK_END);
        long end = ftell(f);
        long pos = (long)sizeof(DWORD);
        long dlen = end - pos;
        if (dlen < 0) dlen = 0;
        fseek(f, pos, SEEK_SET);
        void *buf = NULL;
        if (dlen > 0) {
            buf = malloc((size_t)dlen);
            if (buf && fread(buf, 1, (size_t)dlen, f) < (size_t)dlen) {
                /* partial read - tolerate */
            }
        }
        fclose(f);
        const char *vname = strcmp(ent->d_name, "@") == 0 ? "" : ent->d_name;
        node_upsert_value(n, vname, vtype, buf, (DWORD)dlen);
        free(buf);
    }
    closedir(d);
}

/* Slurp child subkey *names* from disk.  We don't recurse - children are
 * created lazily on demand and get their own load on first touch. */
static void node_load_children_from_disk(reg_node_t *n)
{
    if (!n || !n->fs_path) return;
    DIR *d = opendir(n->fs_path);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') {
            if (ent->d_name[1] == '\0') continue;
            if (ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue;
            if (strcmp(ent->d_name, ".values") == 0) continue;
        }
        char cp[PATH_BUF_MAX];
        snprintf(cp, sizeof(cp), "%s/%s", n->fs_path, ent->d_name);
        struct stat st;
        if (stat(cp, &st) < 0 || !S_ISDIR(st.st_mode)) continue;
        /* Create empty child node (unloaded) */
        uint64_t h = fnv1a_ci(ent->d_name);
        if (!node_find_child(n, ent->d_name, h)) {
            reg_node_t *child = node_new(ent->d_name, n, cp, 0);
            if (child) node_insert_child(n, child);
        }
    }
    closedir(d);
}

/* Ensure node is populated from filesystem (one-shot). */
static void node_ensure_loaded(reg_node_t *n)
{
    if (!n || n->loaded) return;
    node_load_values_from_disk(n);
    node_load_children_from_disk(n);
    n->loaded = 1;
}

/* ---------------------------------------------------------------------- */
/* Path cache                                                             */
/* ---------------------------------------------------------------------- */

/* Caller holds write lock.  Used after RegDeleteKey so dangling
 * node pointers in the cache don't get returned. */
static void path_cache_invalidate_all(void)
{
    for (uint32_t i = 0; i < PATH_CACHE_BUCKETS; i++) {
        free(g_path_cache[i].key);
        g_path_cache[i].key = NULL;
        g_path_cache[i].node = NULL;
        g_path_cache[i].hash = 0;
    }
}

/* Lookup path in cache.  Returns node* on hit, NULL on miss.
 * Caller holds at least read lock.  Comparison is case-insensitive
 * since Windows registry paths are case-insensitive. */
static reg_node_t *path_cache_get(const char *canon_path, uint64_t hash)
{
    uint32_t slot = (uint32_t)hash & PATH_CACHE_MASK;
    for (uint32_t i = 0; i < PATH_CACHE_BUCKETS; i++) {
        path_cache_entry_t *e = &g_path_cache[slot];
        if (!e->key) return NULL;
        if (e->hash == hash && e->node &&
            ci_streq(e->key, canon_path)) {
            return e->node;
        }
        slot = (slot + 1) & PATH_CACHE_MASK;
    }
    return NULL;
}

/* Insert into path cache.  Caller holds write lock. */
static void path_cache_put(const char *canon_path, uint64_t hash, reg_node_t *node)
{
    if (!canon_path || !node) return;
    uint32_t slot = (uint32_t)hash & PATH_CACHE_MASK;
    /* Linear probe up to BUCKETS; evict first empty or hash-match entry. */
    for (uint32_t i = 0; i < PATH_CACHE_BUCKETS; i++) {
        path_cache_entry_t *e = &g_path_cache[slot];
        if (!e->key) {
            e->key = strdup(canon_path);
            e->hash = hash;
            e->node = node;
            return;
        }
        if (e->hash == hash && ci_streq(e->key, canon_path)) {
            e->node = node;  /* refresh */
            return;
        }
        slot = (slot + 1) & PATH_CACHE_MASK;
    }
    /* Table completely full - evict the slot we landed on first. */
    slot = (uint32_t)hash & PATH_CACHE_MASK;
    free(g_path_cache[slot].key);
    g_path_cache[slot].key = strdup(canon_path);
    g_path_cache[slot].hash = hash;
    g_path_cache[slot].node = node;
}

/* Build a canonical key "HIVE\\sub\\path" used for path cache lookups.
 * hive is a 4-char HIVE code ("HKLM" etc).  Backslashes normalised. */
static void build_canon_path(const char *hive, const char *sub,
                             char *out, size_t size)
{
    if (!sub || !*sub) {
        snprintf(out, size, "%s", hive);
    } else {
        snprintf(out, size, "%s\\%s", hive, sub);
    }
    /* Normalise: forward slashes -> backslashes.
     * (We leave case as-is; hash is case-insensitive and strcmp is exact
     * but since all callers go through the same canonicalisation path,
     * cache key equality is reliable.) */
    for (char *p = out; *p; p++) {
        if (*p == '/') *p = '\\';
    }
}

/* ---------------------------------------------------------------------- */
/* Initialisation                                                         */
/* ---------------------------------------------------------------------- */

static void reg_init_once(void)
{
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(g_registry_root, sizeof(g_registry_root),
             "%s/.pe-compat/registry", home);

    char buf[PATH_BUF_MAX];
    /* ~/.pe-compat may not exist yet; create parent first. */
    snprintf(buf, sizeof(buf), "%s/.pe-compat", home);
    mkdir(buf, 0755);
    mkdir(g_registry_root, 0755);

    snprintf(buf, sizeof(buf), "%s/HKLM", g_registry_root);
    mkdir(buf, 0755);
    g_hive_hklm = node_new("HKLM", NULL, buf, 1);

    snprintf(buf, sizeof(buf), "%s/HKCU", g_registry_root);
    mkdir(buf, 0755);
    g_hive_hkcu = node_new("HKCU", NULL, buf, 1);

    snprintf(buf, sizeof(buf), "%s/HKCR", g_registry_root);
    mkdir(buf, 0755);
    g_hive_hkcr = node_new("HKCR", NULL, buf, 1);

    snprintf(buf, sizeof(buf), "%s/HKU", g_registry_root);
    mkdir(buf, 0755);
    g_hive_hku  = node_new("HKU", NULL, buf, 1);

    snprintf(buf, sizeof(buf), "%s/HKCC", g_registry_root);
    mkdir(buf, 0755);
    g_hive_hkcc = node_new("HKCC", NULL, buf, 1);
}

static void ensure_init(void)
{
    pthread_once(&g_reg_once, reg_init_once);
}

static reg_node_t *resolve_hkey(HKEY hk)
{
    if (!is_predefined_hkey(hk)) return NULL;
    switch (hkey_low32(hk)) {
    case 0x80000000u: return g_hive_hkcr;
    case 0x80000001u: return g_hive_hkcu;
    case 0x80000002u: return g_hive_hklm;
    case 0x80000003u: return g_hive_hku;
    case 0x80000005u: return g_hive_hkcc;
    }
    return NULL;
}

/* ---------------------------------------------------------------------- */
/* Path resolution                                                        */
/* ---------------------------------------------------------------------- */

/*
 * HKCR semantics: HKCR is a merge view.  When looking up HKCR\X, we first
 * try HKCU\SOFTWARE\Classes\X, then HKLM\SOFTWARE\Classes\X, then the
 * legacy in-tree HKCR\X.  create==1 biases writes toward an appropriate
 * location.
 */
static reg_node_t *resolve_hkcr(const char *sub, int create)
{
    /* Build the "SOFTWARE\\Classes\\X" suffix once. */
    char classes_sub[PATH_BUF_MAX];
    if (sub && *sub)
        snprintf(classes_sub, sizeof(classes_sub), "SOFTWARE\\Classes\\%s", sub);
    else
        snprintf(classes_sub, sizeof(classes_sub), "SOFTWARE\\Classes");

    /* Read: try HKCU first, then HKLM, then legacy HKCR dir. */
    if (!create) {
        reg_node_t *n = resolve_path(g_hive_hkcu, classes_sub, 0);
        if (n) return n;
        n = resolve_path(g_hive_hklm, classes_sub, 0);
        if (n) return n;
        /* Fall back to legacy HKCR tree (for callers that wrote there). */
        return resolve_path(g_hive_hkcr, sub, 0);
    }

    /* Write: prefer existing HKCU, else HKLM, else legacy. */
    reg_node_t *hkcu = resolve_path(g_hive_hkcu, classes_sub, 0);
    if (hkcu) return hkcu;
    reg_node_t *hklm = resolve_path(g_hive_hklm, classes_sub, 0);
    if (hklm) return hklm;
    reg_node_t *legacy = resolve_path(g_hive_hkcr, sub, 0);
    if (legacy) return legacy;
    /* None exist -- create on HKLM side for Windows-canonical layout. */
    return resolve_path(g_hive_hklm, classes_sub, 1);
}

/*
 * Walk a backslash/slash-separated subpath under `root`, creating missing
 * segments if create==1.  Returns NULL if not found (when !create) or
 * out of memory.
 *
 * Lazy-loading note: calls node_ensure_loaded() on each intermediate node.
 * This MUTATES the tree, so callers must hold the WRITE lock whenever the
 * in-memory tree might not fully reflect on-disk state (i.e. always, in
 * the current single-phase resolver).  The read-lock fast path uses
 * resolve_path_ro() below which skips lazy-load.
 */
static reg_node_t *resolve_path(reg_node_t *root, const char *subpath, int create)
{
    if (!root) return NULL;
    if (!subpath || !*subpath) {
        /* Still ensure root is loaded for value lookups on root itself. */
        if (!root->loaded) node_ensure_loaded(root);
        return root;
    }

    reg_node_t *cur = root;
    const char *p = subpath;
    char comp[KEY_NAME_MAX];

    while (*p) {
        /* Skip leading separators */
        while (*p == '\\' || *p == '/') p++;
        if (!*p) break;
        /* Find end of component */
        const char *start = p;
        while (*p && *p != '\\' && *p != '/') p++;
        size_t clen = (size_t)(p - start);
        if (clen == 0) continue;
        if (clen >= sizeof(comp)) clen = sizeof(comp) - 1;
        memcpy(comp, start, clen);
        comp[clen] = '\0';

        /* Skip "." components (validate_name prevents these upstream,
         * but being defensive). */
        if (clen == 1 && comp[0] == '.') continue;
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') return NULL;

        /* Before descending, make sure current node knows about its
         * on-disk children (lazy load).  Only run once per node. */
        if (!cur->loaded) node_ensure_loaded(cur);

        uint64_t h = fnv1a_ci(comp);
        reg_node_t *next = node_find_child(cur, comp, h);
        if (!next) {
            if (!create) return NULL;
            /* Build fs_path for the new node */
            char child_fs[PATH_BUF_MAX];
            if (cur->fs_path) {
                snprintf(child_fs, sizeof(child_fs), "%s/%s", cur->fs_path, comp);
            } else {
                child_fs[0] = '\0';
            }
            next = node_new(comp, cur, child_fs[0] ? child_fs : NULL, 0);
            if (!next) return NULL;
            node_insert_child(cur, next);
            if (create && next->fs_path) {
                /* Parent fs dir already exists (we just descended through
                 * it); single mkdir is enough. */
                mkdir(next->fs_path, 0755);
            }
        }
        cur = next;
    }
    return cur;
}

/*
 * Read-only resolver: walks the in-memory tree without lazy-loading.
 * Safe to call under a reader lock.  Returns NULL if any component isn't
 * already in memory, forcing the caller to upgrade to write lock and
 * retry with resolve_path().  In the steady state (post-defaults-population
 * + a few warm-up cache fills) this is the hot path.
 */
static reg_node_t *resolve_path_ro(reg_node_t *root, const char *subpath)
{
    if (!root) return NULL;
    if (!root->loaded) return NULL;  /* root not scanned yet */
    if (!subpath || !*subpath) return root;

    reg_node_t *cur = root;
    const char *p = subpath;
    char comp[KEY_NAME_MAX];

    while (*p) {
        while (*p == '\\' || *p == '/') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != '\\' && *p != '/') p++;
        size_t clen = (size_t)(p - start);
        if (clen == 0) continue;
        if (clen >= sizeof(comp)) clen = sizeof(comp) - 1;
        memcpy(comp, start, clen);
        comp[clen] = '\0';
        if (clen == 1 && comp[0] == '.') continue;
        if (clen == 2 && comp[0] == '.' && comp[1] == '.') return NULL;

        if (!cur->loaded) return NULL;  /* can't descend safely */
        uint64_t h = fnv1a_ci(comp);
        reg_node_t *next = node_find_child(cur, comp, h);
        if (!next) return NULL;
        cur = next;
    }
    return cur;
}

/* ---------------------------------------------------------------------- */
/* Whitelist for auto-create (anti-pollution, per Session 25 Agent 9)     */
/* ---------------------------------------------------------------------- */

static int is_whitelisted_auto_create(const char *subkey)
{
    if (!subkey || !*subkey) return 1;
    static const char *prefixes[] = {
        "SOFTWARE",
        "SOFTWARE\\Microsoft",
        "SOFTWARE\\Classes",
        "SOFTWARE\\Wow6432Node",
        "SOFTWARE\\WOW6432Node",
        "SYSTEM\\CurrentControlSet",
        "SYSTEM",
        "HARDWARE",
        "SECURITY",
        "SAM",
        NULL
    };
    for (int i = 0; prefixes[i]; i++) {
        size_t len = strlen(prefixes[i]);
        if (strncasecmp(subkey, prefixes[i], len) == 0) {
            char next = subkey[len];
            if (next == '\0' || next == '\\' || next == '/')
                return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Write-through to filesystem (write-path helpers)                       */
/* ---------------------------------------------------------------------- */

/* Serialise a value to disk. */
static void fs_write_value(reg_node_t *n, const char *vname,
                           DWORD type, const void *data, DWORD size)
{
    if (!n || !n->fs_path) return;
    char vdir[PATH_BUF_MAX], vpath[PATH_BUF_MAX];
    snprintf(vdir, sizeof(vdir), "%s/.values", n->fs_path);
    mkdir_recursive(n->fs_path);   /* make sure key dir exists */
    mkdir(vdir, 0755);
    snprintf(vpath, sizeof(vpath), "%s/%s", vdir, (vname && *vname) ? vname : "@");
    FILE *f = fopen(vpath, "wb");
    if (!f) return;
    fwrite(&type, sizeof(DWORD), 1, f);
    if (data && size) fwrite(data, 1, size, f);
    fclose(f);
}

static void fs_unlink_value(reg_node_t *n, const char *vname)
{
    if (!n || !n->fs_path) return;
    char vpath[PATH_BUF_MAX];
    snprintf(vpath, sizeof(vpath), "%s/.values/%s", n->fs_path,
             (vname && *vname) ? vname : "@");
    unlink(vpath);
}

/* ---------------------------------------------------------------------- */
/* Opened-key handle helpers                                              */
/* ---------------------------------------------------------------------- */

/* Returns the node for an HKEY (predefined or opened handle).  If
 * subkey is non-empty, walks under the base. create biases lookup.
 * Caller must hold the WRITE lock (this may mutate the tree via lazy load). */
static reg_node_t *hkey_to_node_locked(HKEY hk, const char *subkey, int create)
{
    if (is_predefined_hkey(hk)) {
        /* HKCR -> merge resolver */
        if (hkey_low32(hk) == 0x80000000u) {
            return resolve_hkcr(subkey, create);
        }
        reg_node_t *root = resolve_hkey(hk);
        if (!root) return NULL;
        if (!subkey || !*subkey) {
            if (!root->loaded) node_ensure_loaded(root);
            return root;
        }
        return resolve_path(root, subkey, create);
    }
    /* Opened handle */
    handle_entry_t *entry = handle_lookup(hk);
    if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY) return NULL;
    reg_key_data_t *kd = (reg_key_data_t *)entry->data;
    if (!kd || !kd->node) return NULL;
    if (!subkey || !*subkey) {
        if (!kd->node->loaded) node_ensure_loaded(kd->node);
        return kd->node;
    }
    return resolve_path(kd->node, subkey, create);
}

/* Read-only variant: traverses in-memory tree without lazy-loading.
 * Returns NULL if the lookup can't be answered without touching disk.
 * Safe under read lock. */
static reg_node_t *hkey_to_node_ro(HKEY hk, const char *subkey)
{
    if (is_predefined_hkey(hk)) {
        if (hkey_low32(hk) == 0x80000000u) {
            /* HKCR merge: try HKCU, HKLM, legacy in RO mode */
            char classes_sub[PATH_BUF_MAX];
            if (subkey && *subkey)
                snprintf(classes_sub, sizeof(classes_sub),
                         "SOFTWARE\\Classes\\%s", subkey);
            else
                snprintf(classes_sub, sizeof(classes_sub), "SOFTWARE\\Classes");
            reg_node_t *n = resolve_path_ro(g_hive_hkcu, classes_sub);
            if (n) return n;
            n = resolve_path_ro(g_hive_hklm, classes_sub);
            if (n) return n;
            return resolve_path_ro(g_hive_hkcr, subkey);
        }
        reg_node_t *root = resolve_hkey(hk);
        if (!root || !root->loaded) return NULL;
        if (!subkey || !*subkey) return root;
        return resolve_path_ro(root, subkey);
    }
    handle_entry_t *entry = handle_lookup(hk);
    if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY) return NULL;
    reg_key_data_t *kd = (reg_key_data_t *)entry->data;
    if (!kd || !kd->node) return NULL;
    if (!kd->node->loaded) return NULL;
    if (!subkey || !*subkey) return kd->node;
    return resolve_path_ro(kd->node, subkey);
}

/* ---------------------------------------------------------------------- */
/* Public API                                                             */
/* ---------------------------------------------------------------------- */

LONG registry_open_key(HKEY hKey, const char *subkey, HKEY *result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    if (registry_validate_name(subkey) < 0) return ERROR_INVALID_PARAMETER;

    ensure_init();

    /* Path cache fast path for predefined HKEYs with non-empty subkey
     * (the overwhelmingly common case for anti-cheat reads). */
    const char *hive_str = hkey_to_prefix(hKey);
    char canon[PATH_BUF_MAX];
    uint64_t canon_hash = 0;
    int cachable = is_predefined_hkey(hKey) && hive_str != NULL;
    if (cachable) {
        build_canon_path(hive_str, subkey, canon, sizeof(canon));
        canon_hash = fnv1a_ci_path(canon);
    }

    /* Hot path: read lock + path-cache hit OR tree-walk in RO mode. */
    pthread_rwlock_rdlock(&g_reg_rwlock);
    reg_node_t *node = NULL;
    int from_cache = 0;
    if (cachable) {
        node = path_cache_get(canon, canon_hash);
        if (node) from_cache = 1;
    }
    if (!node) {
        node = hkey_to_node_ro(hKey, subkey);
    }
    pthread_rwlock_unlock(&g_reg_rwlock);

    /* Cold path: need write lock to lazy-load and/or auto-create. */
    if (!node) {
        int want_create = is_whitelisted_auto_create(subkey);
        pthread_rwlock_wrlock(&g_reg_rwlock);
        node = hkey_to_node_locked(hKey, subkey, want_create);
        if (node) {
            if (node->fs_path && want_create) mkdir_recursive(node->fs_path);
            if (cachable) path_cache_put(canon, canon_hash, node);
        }
        pthread_rwlock_unlock(&g_reg_rwlock);
    } else if (!from_cache && cachable) {
        /* Populate path cache for next hit.  try-wrlock so we don't
         * serialise readers on a best-effort cache fill. */
        if (pthread_rwlock_trywrlock(&g_reg_rwlock) == 0) {
            path_cache_put(canon, canon_hash, node);
            pthread_rwlock_unlock(&g_reg_rwlock);
        }
    }

    if (!node) return ERROR_FILE_NOT_FOUND;

    reg_key_data_t *data = calloc(1, sizeof(*data));
    if (!data) return ERROR_OUTOFMEMORY;
    data->node = node;
    data->enum_index = 0;
    if (node->fs_path) {
        strncpy(data->path, node->fs_path, sizeof(data->path) - 1);
        data->path[sizeof(data->path) - 1] = '\0';
    }

    *result = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, data);
    if (*result == INVALID_HANDLE_VALUE) {
        free(data);
        return ERROR_OUTOFMEMORY;
    }
    return ERROR_SUCCESS;
}

LONG registry_create_key(HKEY hKey, const char *subkey, HKEY *result)
{
    if (!result) return ERROR_INVALID_PARAMETER;
    if (registry_validate_name(subkey) < 0) return ERROR_INVALID_PARAMETER;
    ensure_init();

    pthread_rwlock_wrlock(&g_reg_rwlock);
    reg_node_t *node = hkey_to_node_locked(hKey, subkey, 1);
    if (node && node->fs_path) {
        mkdir_recursive(node->fs_path);
    }
    /* Seed path cache */
    if (node && is_predefined_hkey(hKey)) {
        const char *hive_str = hkey_to_prefix(hKey);
        if (hive_str) {
            char canon[PATH_BUF_MAX];
            build_canon_path(hive_str, subkey, canon, sizeof(canon));
            path_cache_put(canon, fnv1a_ci_path(canon), node);
        }
    }
    pthread_rwlock_unlock(&g_reg_rwlock);

    if (!node) return ERROR_INVALID_HANDLE;

    reg_key_data_t *data = calloc(1, sizeof(*data));
    if (!data) return ERROR_OUTOFMEMORY;
    data->node = node;
    data->enum_index = 0;
    if (node->fs_path) {
        strncpy(data->path, node->fs_path, sizeof(data->path) - 1);
        data->path[sizeof(data->path) - 1] = '\0';
    }
    *result = handle_alloc(HANDLE_TYPE_REGISTRY_KEY, -1, data);
    if (*result == INVALID_HANDLE_VALUE) {
        free(data);
        return ERROR_OUTOFMEMORY;
    }
    return ERROR_SUCCESS;
}

LONG registry_close_key(HKEY hKey)
{
    if (is_predefined_hkey(hKey)) return ERROR_SUCCESS;
    if (handle_close(hKey) < 0) return ERROR_INVALID_HANDLE;
    return ERROR_SUCCESS;
}

LONG registry_set_value(HKEY hKey, const char *name, DWORD type,
                        const void *data, DWORD size)
{
    if (registry_validate_name(name) < 0) return ERROR_INVALID_PARAMETER;
    ensure_init();

    pthread_rwlock_wrlock(&g_reg_rwlock);

    reg_node_t *node = NULL;
    if (is_predefined_hkey(hKey)) {
        /* Writing directly on a predefined root (rare) goes to that root
         * (for HKCR we use the write-biased merge resolver). */
        if (hkey_low32(hKey) == 0x80000000u) {
            node = resolve_hkcr(NULL, 1);
        } else {
            node = resolve_hkey(hKey);
        }
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (!entry || entry->type != HANDLE_TYPE_REGISTRY_KEY) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_INVALID_HANDLE;
        }
        reg_key_data_t *kd = (reg_key_data_t *)entry->data;
        node = kd ? kd->node : NULL;
    }

    if (!node) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_INVALID_HANDLE;
    }

    if (!node_upsert_value(node, name, type, data, size)) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_OUTOFMEMORY;
    }
    fs_write_value(node, name, type, data, size);

    pthread_rwlock_unlock(&g_reg_rwlock);
    return ERROR_SUCCESS;
}

LONG registry_get_value(HKEY hKey, const char *subkey, const char *name,
                        DWORD *type, void *data, DWORD *size)
{
    if (registry_validate_name(name) < 0) return ERROR_INVALID_PARAMETER;
    ensure_init();

    /* Hot path: read lock + RO resolve */
    pthread_rwlock_rdlock(&g_reg_rwlock);
    reg_node_t *node = hkey_to_node_ro(hKey, subkey);

    if (!node) {
        /* Cold path: need write lock to lazy-load tree segments from disk. */
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_wrlock(&g_reg_rwlock);
        node = hkey_to_node_locked(hKey, subkey, 0);
        if (!node) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_FILE_NOT_FOUND;
        }
        /* Downgrade: drop write, reacquire read. */
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_rdlock(&g_reg_rwlock);
        /* Re-verify node is still reachable (paranoid: another writer
         * could have removed it between unlock and reacquire). */
        node = hkey_to_node_ro(hKey, subkey);
        if (!node) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_FILE_NOT_FOUND;
        }
    }

    const char *vname = (name && name[0]) ? name : "";
    uint64_t h = fnv1a_ci(vname);
    reg_value_t *v = node_find_value(node, vname, h);

    /* HKCR fallback - if we resolved on HKCU side but value is only on
     * HKLM (merge semantics).  Only applies when hKey==HKCR root. */
    if (!v && is_predefined_hkey(hKey) && hkey_low32(hKey) == 0x80000000u) {
        char classes_sub[PATH_BUF_MAX];
        if (subkey && *subkey)
            snprintf(classes_sub, sizeof(classes_sub),
                     "SOFTWARE\\Classes\\%s", subkey);
        else
            snprintf(classes_sub, sizeof(classes_sub), "SOFTWARE\\Classes");
        reg_node_t *hklm_node = resolve_path_ro(g_hive_hklm, classes_sub);
        if (!hklm_node) {
            /* Upgrade to load HKLM side */
            pthread_rwlock_unlock(&g_reg_rwlock);
            pthread_rwlock_wrlock(&g_reg_rwlock);
            hklm_node = resolve_path(g_hive_hklm, classes_sub, 0);
            pthread_rwlock_unlock(&g_reg_rwlock);
            pthread_rwlock_rdlock(&g_reg_rwlock);
            hklm_node = resolve_path_ro(g_hive_hklm, classes_sub);
        }
        if (hklm_node) v = node_find_value(hklm_node, vname, h);
    }

    if (!v) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_FILE_NOT_FOUND;
    }

    if (type) *type = v->type;

    DWORD vsize = v->size;
    if (!data || !size) {
        if (size) *size = vsize;
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_SUCCESS;
    }

    if (*size == 0) {
        *size = vsize;
        pthread_rwlock_unlock(&g_reg_rwlock);
        return vsize > 0 ? ERROR_MORE_DATA : ERROR_SUCCESS;
    }

    if (*size < vsize) {
        *size = vsize;
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_MORE_DATA;
    }

    if (vsize > 0 && v->data) memcpy(data, v->data, vsize);
    *size = vsize;
    pthread_rwlock_unlock(&g_reg_rwlock);
    return ERROR_SUCCESS;
}

LONG registry_delete_value(HKEY hKey, const char *name)
{
    ensure_init();
    pthread_rwlock_wrlock(&g_reg_rwlock);
    reg_node_t *node = NULL;
    if (is_predefined_hkey(hKey)) {
        if (hkey_low32(hKey) == 0x80000000u) node = resolve_hkcr(NULL, 1);
        else node = resolve_hkey(hKey);
    } else {
        handle_entry_t *entry = handle_lookup(hKey);
        if (entry && entry->type == HANDLE_TYPE_REGISTRY_KEY) {
            reg_key_data_t *kd = (reg_key_data_t *)entry->data;
            node = kd ? kd->node : NULL;
        }
    }
    if (!node) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_INVALID_HANDLE;
    }
    /* Ensure loaded so we can reliably report not-found. */
    if (!node->loaded) node_ensure_loaded(node);
    int rc = node_remove_value(node, name);
    if (rc == 0) fs_unlink_value(node, name);
    pthread_rwlock_unlock(&g_reg_rwlock);
    return rc == 0 ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
}

LONG registry_delete_key(HKEY hKey, const char *subkey)
{
    if (registry_validate_name(subkey) < 0) return ERROR_INVALID_PARAMETER;
    ensure_init();

    pthread_rwlock_wrlock(&g_reg_rwlock);
    /* Resolve parent of target */
    reg_node_t *parent = NULL;
    char last[KEY_NAME_MAX] = {0};
    if (subkey && *subkey) {
        const char *last_sep = strrchr(subkey, '\\');
        const char *alt_sep  = strrchr(subkey, '/');
        if (alt_sep > last_sep) last_sep = alt_sep;
        if (last_sep) {
            size_t plen = (size_t)(last_sep - subkey);
            char parent_path[PATH_BUF_MAX];
            if (plen >= sizeof(parent_path)) plen = sizeof(parent_path) - 1;
            memcpy(parent_path, subkey, plen);
            parent_path[plen] = '\0';
            size_t llen = strlen(last_sep + 1);
            if (llen >= sizeof(last)) llen = sizeof(last) - 1;
            memcpy(last, last_sep + 1, llen);
            last[llen] = '\0';
            parent = hkey_to_node_locked(hKey, parent_path, 0);
        } else {
            size_t llen = strlen(subkey);
            if (llen >= sizeof(last)) llen = sizeof(last) - 1;
            memcpy(last, subkey, llen);
            last[llen] = '\0';
            parent = hkey_to_node_locked(hKey, NULL, 0);
        }
    }

    if (!parent || !last[0]) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_FILE_NOT_FOUND;
    }

    /* Resolve target for on-disk deletion. */
    uint64_t h = fnv1a_ci(last);
    reg_node_t *target = node_find_child(parent, last, h);
    if (!target) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_FILE_NOT_FOUND;
    }

    char target_fs[PATH_BUF_MAX] = {0};
    if (target->fs_path) {
        strncpy(target_fs, target->fs_path, sizeof(target_fs) - 1);
    }

    int rc = node_remove_child(parent, last);
    if (rc == -2) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_ACCESS_DENIED;
    }
    if (rc != 0) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_FILE_NOT_FOUND;
    }

    if (target_fs[0]) {
        /* Windows RegDeleteKey requires empty; we already enforced that. */
        if (rmdir(target_fs) < 0) {
            /* rmdir failure is non-fatal -- we've already removed from memory.
             * Common cause: .values subdir still present.  Try to clean it. */
            char vdir[PATH_BUF_MAX];
            snprintf(vdir, sizeof(vdir), "%s/.values", target_fs);
            rmdir(vdir);
            rmdir(target_fs);
        }
    }

    /* Invalidate path cache (we just removed a node; any cached
     * pointer to it or its descendants is dangling). */
    path_cache_invalidate_all();

    pthread_rwlock_unlock(&g_reg_rwlock);
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------------- */
/* Enumeration                                                            */
/* ---------------------------------------------------------------------- */

/* Helper: collect child names from hash table into a flat array.
 * Caller provides out[] with capacity out_cap; returns count filled.
 * dedup against entries already in out[] (case-insensitive) to support
 * HKCR merge enumeration. */
static DWORD collect_children_mem(reg_node_t *n,
                                  char (*out)[KEY_NAME_MAX],
                                  DWORD out_count, DWORD out_cap)
{
    if (!n) return out_count;
    if (!n->loaded) node_ensure_loaded(n);
    for (uint32_t i = 0; i < n->child_cap && out_count < out_cap; i++) {
        reg_node_t *c = n->children[i];
        if (!c || !c->name) continue;
        int dup = 0;
        for (DWORD k = 0; k < out_count; k++) {
            if (ci_streq(out[k], c->name)) { dup = 1; break; }
        }
        if (dup) continue;
        size_t nl = strlen(c->name);
        if (nl >= KEY_NAME_MAX) nl = KEY_NAME_MAX - 1;
        memcpy(out[out_count], c->name, nl);
        out[out_count][nl] = '\0';
        out_count++;
    }
    return out_count;
}

LONG registry_enum_key(HKEY hKey, DWORD index, char *name, DWORD *name_size)
{
    ensure_init();
    pthread_rwlock_rdlock(&g_reg_rwlock);

    /* HKCR merge enumeration */
    if (is_predefined_hkey(hKey) && hkey_low32(hKey) == 0x80000000u) {
        enum { MAX_HKCR_ENTRIES = 4096 };
        static char merged[MAX_HKCR_ENTRIES][KEY_NAME_MAX];
        DWORD count = 0;
        /* Need write lock for lazy-load; upgrade path. */
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_wrlock(&g_reg_rwlock);
        reg_node_t *hkcu_cl = resolve_path(g_hive_hkcu, "SOFTWARE\\Classes", 0);
        reg_node_t *hklm_cl = resolve_path(g_hive_hklm, "SOFTWARE\\Classes", 0);
        reg_node_t *legacy  = g_hive_hkcr;
        count = collect_children_mem(hkcu_cl, merged, count, MAX_HKCR_ENTRIES);
        count = collect_children_mem(hklm_cl, merged, count, MAX_HKCR_ENTRIES);
        count = collect_children_mem(legacy,  merged, count, MAX_HKCR_ENTRIES);
        pthread_rwlock_unlock(&g_reg_rwlock);

        if (index >= count) return ERROR_NO_MORE_ITEMS;
        DWORD len = (DWORD)strlen(merged[index]);
        if (!name || !name_size || *name_size <= len) {
            if (name_size) *name_size = len + 1;
            return ERROR_MORE_DATA;
        }
        memcpy(name, merged[index], len);
        name[len] = '\0';
        *name_size = len;
        return ERROR_SUCCESS;
    }

    reg_node_t *node = hkey_to_node_locked(hKey, NULL, 0);
    if (!node) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_FILE_NOT_FOUND;
    }

    if (!node->loaded) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_wrlock(&g_reg_rwlock);
        if (!node->loaded) node_ensure_loaded(node);
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_rdlock(&g_reg_rwlock);
        node = hkey_to_node_locked(hKey, NULL, 0);
        if (!node) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_FILE_NOT_FOUND;
        }
    }

    /* Walk hash table collecting up to (index+1)'th non-null child.
     * Table order is stable as long as no insert/delete between calls
     * (typical enumeration pattern). */
    DWORD current = 0;
    for (uint32_t i = 0; i < node->child_cap; i++) {
        reg_node_t *c = node->children[i];
        if (!c || !c->name) continue;
        if (current == index) {
            DWORD len = (DWORD)strlen(c->name);
            if (!name || !name_size || *name_size <= len) {
                if (name_size) *name_size = len + 1;
                pthread_rwlock_unlock(&g_reg_rwlock);
                return ERROR_MORE_DATA;
            }
            memcpy(name, c->name, len);
            name[len] = '\0';
            *name_size = len;
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_SUCCESS;
        }
        current++;
    }

    pthread_rwlock_unlock(&g_reg_rwlock);
    return ERROR_NO_MORE_ITEMS;
}

LONG registry_enum_value(HKEY hKey, DWORD index, char *name, DWORD *name_size,
                         DWORD *type, void *data, DWORD *data_size)
{
    ensure_init();
    pthread_rwlock_rdlock(&g_reg_rwlock);

    reg_node_t *node = hkey_to_node_locked(hKey, NULL, 0);
    if (!node) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return ERROR_NO_MORE_ITEMS;
    }
    if (!node->loaded) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_wrlock(&g_reg_rwlock);
        if (!node->loaded) node_ensure_loaded(node);
        pthread_rwlock_unlock(&g_reg_rwlock);
        pthread_rwlock_rdlock(&g_reg_rwlock);
        node = hkey_to_node_locked(hKey, NULL, 0);
        if (!node) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_NO_MORE_ITEMS;
        }
    }

    DWORD current = 0;
    for (uint32_t i = 0; i < node->value_cap; i++) {
        reg_value_t *v = node->values[i];
        if (!v) continue;
        if (current == index) {
            DWORD nlen = (DWORD)strlen(v->name);
            if (!name || !name_size || *name_size <= nlen) {
                if (name_size) *name_size = nlen + 1;
                pthread_rwlock_unlock(&g_reg_rwlock);
                return ERROR_MORE_DATA;
            }
            memcpy(name, v->name, nlen);
            name[nlen] = '\0';
            *name_size = nlen;
            if (type) *type = v->type;
            if (data_size) {
                DWORD vs = v->size;
                if (data && *data_size >= vs) {
                    if (vs > 0 && v->data) memcpy(data, v->data, vs);
                    *data_size = vs;
                } else {
                    *data_size = vs;
                    if (data) {
                        pthread_rwlock_unlock(&g_reg_rwlock);
                        return ERROR_MORE_DATA;
                    }
                    /* data==NULL: query-only, SUCCESS with size filled */
                }
            }
            pthread_rwlock_unlock(&g_reg_rwlock);
            return ERROR_SUCCESS;
        }
        current++;
    }

    pthread_rwlock_unlock(&g_reg_rwlock);
    return ERROR_NO_MORE_ITEMS;
}

/* ---------------------------------------------------------------------- */
/* Bulk fast-path for registry_defaults.c                                 */
/*                                                                        */
/* The original defaults populator did 6 locked registry ops per value    */
/* (open/get/close to check existence, then create/set/close to write).   */
/* This helper collapses that into a single locked critical section with  */
/* no handle allocation, no filesystem probing, and a single hash lookup  */
/* for idempotency. ~200 defaults values -> ~200 locks instead of ~1200. */
/* ---------------------------------------------------------------------- */

static int set_default_inner(HKEY root, const char *subkey,
                             const char *name, DWORD type,
                             const void *data, DWORD size,
                             int force)
{
    if (registry_validate_name(subkey) < 0) return 0;
    if (registry_validate_name(name) < 0) return 0;
    ensure_init();

    pthread_rwlock_wrlock(&g_reg_rwlock);

    reg_node_t *node = NULL;
    if (is_predefined_hkey(root)) {
        if ((uintptr_t)root == 0x80000000) {
            node = resolve_hkcr(subkey, 1);
        } else {
            reg_node_t *hr = resolve_hkey(root);
            if (hr) {
                if (!subkey || !*subkey) {
                    if (!hr->loaded) node_ensure_loaded(hr);
                    node = hr;
                } else {
                    node = resolve_path(hr, subkey, 1);
                }
            }
        }
    }
    if (!node) {
        pthread_rwlock_unlock(&g_reg_rwlock);
        return 0;
    }
    if (node->fs_path) mkdir_recursive(node->fs_path);

    /* Idempotent guard: if not forcing and value already present, skip. */
    if (!force) {
        const char *vname = (name && name[0]) ? name : "";
        uint64_t h = fnv1a_ci(vname);
        if (node_find_value(node, vname, h)) {
            pthread_rwlock_unlock(&g_reg_rwlock);
            return 0;
        }
    }

    reg_value_t *v = node_upsert_value(node, name, type, data, size);
    if (v) fs_write_value(node, name, type, data, size);

    /* Seed path cache for this key path (future lookups are O(1)). */
    if (is_predefined_hkey(root)) {
        const char *hs = hkey_to_prefix(root);
        if (hs) {
            char canon[PATH_BUF_MAX];
            build_canon_path(hs, subkey ? subkey : "", canon, sizeof(canon));
            path_cache_put(canon, fnv1a_ci_path(canon), node);
        }
    }

    pthread_rwlock_unlock(&g_reg_rwlock);
    return v ? 1 : 0;
}

int registry_set_default(HKEY root, const char *subkey,
                         const char *name, DWORD type,
                         const void *data, DWORD size)
{
    return set_default_inner(root, subkey, name, type, data, size, 0);
}

int registry_set_force(HKEY root, const char *subkey,
                       const char *name, DWORD type,
                       const void *data, DWORD size)
{
    return set_default_inner(root, subkey, name, type, data, size, 1);
}
