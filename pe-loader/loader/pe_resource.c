/*
 * pe_resource.c - PE_DIR_RESOURCE walker, manifest extractor, activation
 * context state.
 *
 * See pe_resource.h for the public surface.  Conventions:
 *   - We never modify the image; data pointers handed to the callback live
 *     inside the mapped image and are valid for the lifetime of the load.
 *   - The XML "parser" here is intentionally tiny — it only recognises the
 *     handful of elements/attributes we care about for SxS/manifest binding.
 *     It does not validate XML, does not chase entities, and silently
 *     ignores everything it does not understand.
 *   - We do NOT call any DLL stubs; this file is part of the loader binary
 *     and runs before user32/comctl32 are touched.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <ctype.h>

#include "pe/pe_types.h"
#include "pe/pe_resource.h"

/* ----------------------------------------------------------------
 * On-disk resource directory structures
 * ---------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
} pe_rsrc_dir_t;

typedef struct {
    /* Either NameOffset|NameIsString (named entry) or Id (numeric) */
    uint32_t NameOrId;
    /* High bit: DataIsDirectory.  Low 31 bits: offset within rsrc */
    uint32_t OffsetToData;
} pe_rsrc_entry_t;

typedef struct {
    uint32_t OffsetToData;   /* RVA within image */
    uint32_t Size;
    uint32_t CodePage;
    uint32_t Reserved;
} pe_rsrc_data_t;

#pragma pack(pop)

#define RSRC_NAME_IS_STRING  0x80000000u
#define RSRC_OFFSET_MASK     0x7FFFFFFFu
#define RSRC_DATA_IS_DIR     0x80000000u

/* ----------------------------------------------------------------
 * Activation context state (shared with kernel32 stubs)
 * ---------------------------------------------------------------- */
struct pe_activation_context g_actx = {
    .common_controls_version   = PE_COMCTL_V5,
    .requested_execution_level = PE_EXEC_LEVEL_ASINVOKER,
    .dpi_aware                 = PE_DPI_UNAWARE,
    .ui_access                 = 0,
    .dependencies              = NULL,
    .dependency_count          = 0,
    .have_manifest             = 0,
};

int g_common_controls_v6 = 0;

/* ----------------------------------------------------------------
 * Per-thread activation-context stack (S65 A9 deferred item)
 *
 * Each frame carries a back-pointer to the pe_activation_context the
 * caller wants to bind, plus a cookie that must be presented to pop.
 * Cookies are derived from the frame address so they are unique within
 * a thread's lifetime and cheap to validate.  The stack is small and
 * bounded — Windows applications rarely nest deeper than a handful.
 * ---------------------------------------------------------------- */
typedef struct {
    struct pe_activation_context *ctx;
    unsigned long                 cookie;
} pe_actx_frame_t;

typedef struct {
    pe_actx_frame_t frames[PE_ACTX_STACK_MAX];
    int             depth;
} pe_actx_tls_t;

static __thread pe_actx_tls_t tls_actx_stack;

unsigned long pe_actx_push(struct pe_activation_context *ctx)
{
    if (tls_actx_stack.depth >= PE_ACTX_STACK_MAX)
        return 0;
    int idx = tls_actx_stack.depth++;
    pe_actx_frame_t *f = &tls_actx_stack.frames[idx];
    f->ctx    = ctx ? ctx : &g_actx;
    /* Frame-address cookie: unique per push, never zero. */
    f->cookie = (unsigned long)(uintptr_t)f ^ (0xA5A5A5A5UL + (unsigned long)idx);
    if (f->cookie == 0) f->cookie = 1;
    return f->cookie;
}

int pe_actx_pop(unsigned long cookie)
{
    if (tls_actx_stack.depth <= 0)
        return 0;
    pe_actx_frame_t *top = &tls_actx_stack.frames[tls_actx_stack.depth - 1];
    if (top->cookie != cookie)
        return 0;       /* mismatched deactivate */
    top->ctx    = NULL;
    top->cookie = 0;
    tls_actx_stack.depth--;
    return 1;
}

struct pe_activation_context *pe_actx_current(void)
{
    if (tls_actx_stack.depth > 0) {
        struct pe_activation_context *c =
            tls_actx_stack.frames[tls_actx_stack.depth - 1].ctx;
        if (c) return c;
    }
    return &g_actx;
}

void pe_actx_thread_reset(void)
{
    for (int i = 0; i < PE_ACTX_STACK_MAX; i++) {
        tls_actx_stack.frames[i].ctx    = NULL;
        tls_actx_stack.frames[i].cookie = 0;
    }
    tls_actx_stack.depth = 0;
}

void pe_actx_reset(void)
{
    if (g_actx.dependencies) {
        for (size_t i = 0; i < g_actx.dependency_count; i++)
            free(g_actx.dependencies[i]);
        free(g_actx.dependencies);
    }
    g_actx.common_controls_version   = PE_COMCTL_V5;
    g_actx.requested_execution_level = PE_EXEC_LEVEL_ASINVOKER;
    g_actx.dpi_aware                 = PE_DPI_UNAWARE;
    g_actx.ui_access                 = 0;
    g_actx.dependencies              = NULL;
    g_actx.dependency_count          = 0;
    g_actx.have_manifest             = 0;
    g_common_controls_v6             = 0;
}

/* ----------------------------------------------------------------
 * PE header poke — find PE_DIR_RESOURCE without depending on
 * pe_image_t (we may be invoked from a stub DLL via env_get_peb).
 *
 * Returns 0 on success, -1 if the image has no resource directory.
 * ---------------------------------------------------------------- */
static int locate_rsrc_dir(void *image_base, void **rsrc_base_out,
                           uint32_t *rsrc_size_out)
{
    if (!image_base) return -1;
    const unsigned char *p = (const unsigned char *)image_base;

    if (p[0] != 'M' || p[1] != 'Z') return -1;

    int32_t e_lfanew;
    memcpy(&e_lfanew, p + 0x3C, sizeof(e_lfanew));
    if (e_lfanew < 0 || e_lfanew > 0x10000) return -1;

    const unsigned char *pe = p + e_lfanew;
    if (pe[0] != 'P' || pe[1] != 'E' || pe[2] || pe[3]) return -1;

    const unsigned char *coff = pe + 4;
    uint16_t opt_size;
    memcpy(&opt_size, coff + 16, sizeof(opt_size));

    const unsigned char *opt = coff + 20;
    uint16_t magic;
    memcpy(&magic, opt, sizeof(magic));

    uint32_t dd_off;
    if (magic == 0x020B) {
        dd_off = 112;       /* PE32+ data directory base */
    } else if (magic == 0x010B) {
        dd_off = 96;        /* PE32 */
    } else {
        return -1;
    }

    /* PE_DIR_RESOURCE is index 2 -> offset dd_off + 2*8 */
    if (opt_size < dd_off + (PE_DIR_RESOURCE + 1) * 8) return -1;

    uint32_t rva, size;
    memcpy(&rva,  opt + dd_off + PE_DIR_RESOURCE * 8,     sizeof(rva));
    memcpy(&size, opt + dd_off + PE_DIR_RESOURCE * 8 + 4, sizeof(size));
    if (!rva || !size) return -1;

    *rsrc_base_out = (void *)(p + rva);
    *rsrc_size_out = size;
    return 0;
}

/* ----------------------------------------------------------------
 * Recursive walker
 * ---------------------------------------------------------------- */

typedef struct {
    void *image_base;
    void *rsrc_base;
    uint32_t rsrc_size;
    pe_resource_callback_t cb;
    void *user;
    /* Path-tracking through the 3 levels */
    uint32_t cur_type;
    uint32_t cur_name_id;
    char    *cur_name_str;
} walk_ctx_t;

/* Decode a name/string entry: returns malloc'd ASCII string (UTF-16
 * downcast).  Caller frees.  Returns NULL on failure. */
static char *decode_name_string(const walk_ctx_t *w, uint32_t name_or_id)
{
    if (!(name_or_id & RSRC_NAME_IS_STRING)) return NULL;
    uint32_t off = name_or_id & RSRC_OFFSET_MASK;
    if (off + 2 > w->rsrc_size) return NULL;

    const unsigned char *p = (const unsigned char *)w->rsrc_base + off;
    uint16_t len;
    memcpy(&len, p, sizeof(len));
    if (off + 2 + (size_t)len * 2 > w->rsrc_size) return NULL;

    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    const uint16_t *src = (const uint16_t *)(p + 2);
    for (uint16_t i = 0; i < len; i++) {
        uint16_t c;
        memcpy(&c, &src[i], sizeof(c));
        /* Lossy: keep low byte; sufficient for type/name comparison. */
        out[i] = (char)(c & 0x7F);
    }
    out[len] = '\0';
    return out;
}

static int walk_dir(walk_ctx_t *w, uint32_t dir_offset, int level);

static int visit_leaf(walk_ctx_t *w, uint32_t leaf_offset)
{
    if (leaf_offset + sizeof(pe_rsrc_data_t) > w->rsrc_size) return 0;
    const pe_rsrc_data_t *de = (const pe_rsrc_data_t *)
        ((const unsigned char *)w->rsrc_base + leaf_offset);

    pe_resource_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.type      = w->cur_type;
    entry.name_id   = w->cur_name_id;
    entry.name_str  = w->cur_name_str;
    entry.lang      = 0;            /* set by caller before invoking us */
    entry.data_rva  = de->OffsetToData;
    entry.size      = de->Size;
    entry.code_page = de->CodePage;
    entry.data      = (unsigned char *)w->image_base + de->OffsetToData;

    return w->cb(&entry, w->user);
}

static int walk_dir(walk_ctx_t *w, uint32_t dir_offset, int level)
{
    if (dir_offset + sizeof(pe_rsrc_dir_t) > w->rsrc_size) return 0;
    const pe_rsrc_dir_t *dir = (const pe_rsrc_dir_t *)
        ((const unsigned char *)w->rsrc_base + dir_offset);

    uint32_t total = (uint32_t)dir->NumberOfNamedEntries +
                     (uint32_t)dir->NumberOfIdEntries;
    uint32_t entries_off = dir_offset + (uint32_t)sizeof(pe_rsrc_dir_t);
    if (entries_off + (uint64_t)total * sizeof(pe_rsrc_entry_t) > w->rsrc_size)
        return 0;

    const pe_rsrc_entry_t *ent = (const pe_rsrc_entry_t *)
        ((const unsigned char *)w->rsrc_base + entries_off);

    for (uint32_t i = 0; i < total; i++) {
        uint32_t name = ent[i].NameOrId;
        uint32_t off  = ent[i].OffsetToData;
        int is_dir    = (off & RSRC_DATA_IS_DIR) != 0;
        uint32_t roff = off & RSRC_OFFSET_MASK;

        /* Save level-specific path state */
        char    *prev_name_str = w->cur_name_str;
        uint32_t prev_type     = w->cur_type;
        uint32_t prev_name_id  = w->cur_name_id;

        if (level == 0) {
            /* Type level */
            if (name & RSRC_NAME_IS_STRING) {
                free(w->cur_name_str);
                w->cur_name_str = decode_name_string(w, name);
                w->cur_type = 0;
            } else {
                w->cur_type = name & 0xFFFF;
            }
        } else if (level == 1) {
            /* Name level */
            if (name & RSRC_NAME_IS_STRING) {
                free(w->cur_name_str);
                w->cur_name_str = decode_name_string(w, name);
                w->cur_name_id = 0;
            } else {
                w->cur_name_id = name & 0xFFFF;
            }
        }

        int rc = 0;
        if (is_dir) {
            rc = walk_dir(w, roff, level + 1);
        } else if (level == 2) {
            /* leaf at language level — stash lang into entry via cur_* trick */
            uint32_t lang_id = (name & RSRC_NAME_IS_STRING) ? 0 : (name & 0xFFFF);
            /* visit_leaf reads cur_* + we override lang via local */
            /* easiest: temporarily smuggle lang via a stack copy */
            walk_ctx_t saved = *w;
            (void)saved;
            /* Manually do the leaf with the right lang */
            if (roff + sizeof(pe_rsrc_data_t) <= w->rsrc_size) {
                const pe_rsrc_data_t *de = (const pe_rsrc_data_t *)
                    ((const unsigned char *)w->rsrc_base + roff);
                pe_resource_entry_t entry = {0};
                entry.type      = w->cur_type;
                entry.name_id   = w->cur_name_id;
                entry.name_str  = w->cur_name_str;
                entry.lang      = lang_id;
                entry.data_rva  = de->OffsetToData;
                entry.size      = de->Size;
                entry.code_page = de->CodePage;
                entry.data      = (unsigned char *)w->image_base + de->OffsetToData;
                rc = w->cb(&entry, w->user);
            }
        } else {
            /* Unexpected leaf above lang level — treat as no-op */
            rc = visit_leaf(w, roff);
        }

        /* Restore name_str etc. (visit_leaf may have been called with
         * a borrowed pointer; restore prev state). */
        if (w->cur_name_str != prev_name_str) {
            free(w->cur_name_str);
            w->cur_name_str = prev_name_str;
        }
        w->cur_type    = prev_type;
        w->cur_name_id = prev_name_id;

        if (rc != 0) return rc;
    }
    return 0;
}

int pe_walk_resources(void *image_base, pe_resource_callback_t cb, void *user)
{
    if (!image_base || !cb) return -1;
    void   *rsrc_base = NULL;
    uint32_t rsrc_size = 0;
    if (locate_rsrc_dir(image_base, &rsrc_base, &rsrc_size) < 0)
        return 0;       /* no resource dir is not an error */

    walk_ctx_t w = {
        .image_base   = image_base,
        .rsrc_base    = rsrc_base,
        .rsrc_size    = rsrc_size,
        .cb           = cb,
        .user         = user,
        .cur_type     = 0,
        .cur_name_id  = 0,
        .cur_name_str = NULL,
    };
    int rc = walk_dir(&w, 0, 0);
    free(w.cur_name_str);
    return rc;
}

/* ----------------------------------------------------------------
 * pe_find_resource — convenience for (type, numeric name)
 * ---------------------------------------------------------------- */

typedef struct {
    uint32_t want_type;
    uint32_t want_id;
    void    *out_data;
    size_t   out_size;
} find_ctx_t;

static int find_cb(const pe_resource_entry_t *e, void *u)
{
    find_ctx_t *fc = (find_ctx_t *)u;
    if (e->type == fc->want_type && e->name_id == fc->want_id) {
        fc->out_data = e->data;
        fc->out_size = e->size;
        return 1;       /* found — abort walk */
    }
    return 0;
}

void *pe_find_resource(void *image_base, uint32_t type, uint32_t name_id,
                       size_t *size_out)
{
    find_ctx_t fc = { .want_type = type, .want_id = name_id,
                      .out_data = NULL, .out_size = 0 };
    pe_walk_resources(image_base, find_cb, &fc);
    if (size_out) *size_out = fc.out_size;
    return fc.out_data;
}

/* ----------------------------------------------------------------
 * Minimal manifest XML parser
 *
 * The manifest is well-formed XML produced by the SxS toolchain.  We
 * only need a small set of values, so rather than pulling in libxml2
 * we hand-roll a tag/attribute scanner.  We skip whitespace and
 * comments; inside element start-tags we extract attribute pairs as
 * name/value strings.
 *
 * Elements we react to:
 *   <assemblyIdentity name=".." version=".."/>     (top-level OR inside
 *                                                   dependentAssembly)
 *   <requestedExecutionLevel level=".." uiAccess=".."/>
 *   <dpiAware>...</dpiAware>
 *   <dpiAwareness>...</dpiAwareness>
 *
 * Top-level <assemblyIdentity> describes the app itself.  When the
 * app's assemblyIdentity OR a <dependentAssembly>/<assemblyIdentity>
 * names "Microsoft.Windows.Common-Controls" with version ">=6", we
 * flip the comctl v6 flag.
 * ---------------------------------------------------------------- */

static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/* Consume <!-- ... --> and <?...?> */
static const char *skip_comments(const char *p, const char *end)
{
    while (p < end - 1) {
        p = skip_ws(p, end);
        if (p + 4 <= end && memcmp(p, "<!--", 4) == 0) {
            const char *e = (const char *)memmem(p + 4, end - (p + 4), "-->", 3);
            if (!e) return end;
            p = e + 3;
            continue;
        }
        if (p + 2 <= end && memcmp(p, "<?", 2) == 0) {
            const char *e = (const char *)memmem(p + 2, end - (p + 2), "?>", 2);
            if (!e) return end;
            p = e + 2;
            continue;
        }
        if (p + 9 <= end && memcmp(p, "<!DOCTYPE", 9) == 0) {
            const char *e = (const char *)memchr(p, '>', end - p);
            if (!e) return end;
            p = e + 1;
            continue;
        }
        break;
    }
    return p;
}

/* Case-insensitive prefix match */
static int starts_with_i(const char *s, const char *e, const char *kw)
{
    size_t n = strlen(kw);
    if ((size_t)(e - s) < n) return 0;
    return strncasecmp(s, kw, n) == 0;
}

/* Extract attribute named `attr` from a tag body.  Returns a malloc'd
 * value string (caller frees) or NULL if not found. */
static char *get_attr(const char *body, size_t body_len, const char *attr)
{
    const char *p = body;
    const char *end = body + body_len;
    size_t alen = strlen(attr);

    while (p < end) {
        /* find attr name */
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '/'))
            p++;
        if (p >= end) break;
        const char *name_start = p;
        while (p < end && *p != '=' && *p != ' ' && *p != '\t' && *p != '/')
            p++;
        size_t nlen = p - name_start;
        /* skip ws + '=' */
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end || *p != '=') {
            /* no '=' — attribute without value; skip */
            continue;
        }
        p++;
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p >= end) break;
        char quote = *p;
        if (quote != '"' && quote != '\'') break;
        p++;
        const char *val_start = p;
        while (p < end && *p != quote) p++;
        if (p >= end) break;
        size_t vlen = p - val_start;
        p++;        /* past closing quote */

        if (nlen == alen && strncasecmp(name_start, attr, alen) == 0) {
            char *out = (char *)malloc(vlen + 1);
            if (!out) return NULL;
            memcpy(out, val_start, vlen);
            out[vlen] = '\0';
            return out;
        }
    }
    return NULL;
}

/* Returns 1 if `version` (e.g. "6.0.0.0") has major >= 6 */
static int version_ge_6(const char *version)
{
    if (!version) return 0;
    /* Skip leading whitespace */
    while (*version == ' ') version++;
    long maj = strtol(version, NULL, 10);
    return maj >= 6;
}

static void add_dependency(const char *name, const char *version)
{
    if (!name) return;
    size_t nl = strlen(name);
    size_t vl = version ? strlen(version) : 0;
    char *combo = (char *)malloc(nl + vl + 2);
    if (!combo) return;
    memcpy(combo, name, nl);
    combo[nl] = ' ';
    if (vl) memcpy(combo + nl + 1, version, vl);
    combo[nl + 1 + vl] = '\0';

    char **np = (char **)realloc(g_actx.dependencies,
                                 (g_actx.dependency_count + 1) * sizeof(char *));
    if (!np) { free(combo); return; }
    g_actx.dependencies = np;
    g_actx.dependencies[g_actx.dependency_count++] = combo;
}

/* Map dpiAware / dpiAwareness text value to PE_DPI_* */
static int parse_dpi_value(const char *s)
{
    if (!s) return PE_DPI_UNAWARE;
    /* dpiAwareness can be a comma/space list — pick the first */
    char tmp[64] = {0};
    size_t i = 0;
    while (s[i] && i < sizeof(tmp) - 1 &&
           s[i] != ',' && s[i] != ' ' && s[i] != '\t' &&
           s[i] != '\n' && s[i] != '\r') {
        tmp[i] = (char)tolower((unsigned char)s[i]);
        i++;
    }
    if (strstr(tmp, "permonitorv2")) return PE_DPI_PERMONITOR_V2;
    if (strstr(tmp, "permonitor"))   return PE_DPI_PERMONITOR;
    if (strstr(tmp, "system"))       return PE_DPI_SYSTEM;
    if (strstr(tmp, "true"))         return PE_DPI_SYSTEM;
    if (strstr(tmp, "unaware"))      return PE_DPI_UNAWARE;
    if (strstr(tmp, "false"))        return PE_DPI_UNAWARE;
    return PE_DPI_UNAWARE;
}

static int parse_exec_level(const char *s)
{
    if (!s) return PE_EXEC_LEVEL_ASINVOKER;
    if (strcasecmp(s, "asInvoker") == 0)         return PE_EXEC_LEVEL_ASINVOKER;
    if (strcasecmp(s, "requireAdministrator") == 0) return PE_EXEC_LEVEL_REQUIREADMIN;
    if (strcasecmp(s, "highestAvailable") == 0)  return PE_EXEC_LEVEL_HIGHESTAVAILABLE;
    return PE_EXEC_LEVEL_ASINVOKER;
}

int pe_parse_manifest(const char *xml, size_t xml_len,
                      struct pe_activation_context *out)
{
    if (!xml || !xml_len) return -1;

    struct pe_activation_context *ctx = out ? out : &g_actx;
    int in_dependent = 0;

    /* Skip a UTF-8 BOM if present */
    if (xml_len >= 3 &&
        (unsigned char)xml[0] == 0xEF &&
        (unsigned char)xml[1] == 0xBB &&
        (unsigned char)xml[2] == 0xBF) {
        xml += 3;
        xml_len -= 3;
    }

    const char *p = xml;
    const char *end = xml + xml_len;

    while (p < end) {
        p = skip_comments(p, end);
        if (p >= end) break;
        if (*p != '<') { p++; continue; }

        /* Closing tag? */
        if (p + 1 < end && p[1] == '/') {
            const char *close = (const char *)memchr(p, '>', end - p);
            if (!close) break;
            const char *name = p + 2;
            size_t nlen = close - name;
            if (nlen == strlen("dependentAssembly") &&
                strncasecmp(name, "dependentAssembly", nlen) == 0) {
                in_dependent = 0;
            } else if (nlen == strlen("dependency") &&
                       strncasecmp(name, "dependency", nlen) == 0) {
                in_dependent = 0;
            }
            p = close + 1;
            continue;
        }

        /* Opening or self-closing tag */
        const char *close = (const char *)memchr(p, '>', end - p);
        if (!close) break;
        int self_closing = (close > p && close[-1] == '/');
        const char *body_start = p + 1;     /* past '<' */
        const char *body_end = self_closing ? close - 1 : close;

        /* Tag name */
        const char *nm_end = body_start;
        while (nm_end < body_end && *nm_end != ' ' && *nm_end != '\t' &&
               *nm_end != '\n' && *nm_end != '\r' && *nm_end != '/')
            nm_end++;
        size_t nlen = nm_end - body_start;
        const char *attrs = nm_end;
        size_t alen = body_end - nm_end;

        if (nlen == strlen("dependency") &&
            strncasecmp(body_start, "dependency", nlen) == 0 && !self_closing) {
            in_dependent = 1;
        } else if (nlen == strlen("dependentAssembly") &&
                   strncasecmp(body_start, "dependentAssembly", nlen) == 0 &&
                   !self_closing) {
            in_dependent = 1;
        } else if (nlen == strlen("assemblyIdentity") &&
                   strncasecmp(body_start, "assemblyIdentity", nlen) == 0) {
            char *aname    = get_attr(attrs, alen, "name");
            char *aversion = get_attr(attrs, alen, "version");
            if (aname && aversion) {
                if (in_dependent) add_dependency(aname, aversion);
                if (strcasecmp(aname, "Microsoft.Windows.Common-Controls") == 0 &&
                    version_ge_6(aversion)) {
                    ctx->common_controls_version = PE_COMCTL_V6;
                    if (ctx == &g_actx) g_common_controls_v6 = 1;
                }
            }
            free(aname);
            free(aversion);
        } else if (nlen == strlen("requestedExecutionLevel") &&
                   strncasecmp(body_start, "requestedExecutionLevel", nlen) == 0) {
            char *level    = get_attr(attrs, alen, "level");
            char *uiAccess = get_attr(attrs, alen, "uiAccess");
            ctx->requested_execution_level = parse_exec_level(level);
            if (uiAccess && (strcasecmp(uiAccess, "true") == 0)) {
                ctx->ui_access = 1;
            }
            free(level);
            free(uiAccess);
        } else if ((nlen == strlen("dpiAware") &&
                    strncasecmp(body_start, "dpiAware", nlen) == 0) ||
                   (nlen == strlen("dpiAwareness") &&
                    strncasecmp(body_start, "dpiAwareness", nlen) == 0)) {
            /* Element with text body: <dpiAware>true</dpiAware> */
            if (!self_closing) {
                const char *text_start = close + 1;
                const char *text_end = (const char *)memchr(text_start, '<',
                                                            end - text_start);
                if (text_end) {
                    char tmp[128] = {0};
                    size_t tl = (size_t)(text_end - text_start);
                    if (tl >= sizeof(tmp)) tl = sizeof(tmp) - 1;
                    memcpy(tmp, text_start, tl);
                    tmp[tl] = '\0';
                    /* trim leading ws */
                    char *t = tmp;
                    while (*t == ' ' || *t == '\t' || *t == '\n' || *t == '\r') t++;
                    int dpi = parse_dpi_value(t);
                    /* keep the strongest setting we've seen */
                    if (dpi > ctx->dpi_aware) ctx->dpi_aware = dpi;
                }
            }
        }
        /* Suppress unused warning */
        (void)starts_with_i;

        p = close + 1;
    }

    ctx->have_manifest = 1;
    return 0;
}

/* ----------------------------------------------------------------
 * Top-level: extract embedded RT_MANIFEST and apply it
 * ---------------------------------------------------------------- */
int pe_process_manifest_from_image(void *image_base)
{
    if (!image_base) return -1;

    size_t mft_size = 0;
    void *mft = pe_find_resource(image_base, RT_MANIFEST, 1, &mft_size);
    if (!mft) {
        mft = pe_find_resource(image_base, RT_MANIFEST, 2, &mft_size);
    }
    if (!mft || !mft_size) return 0;

    /* Sanity-clamp: manifests are tiny (<64 KiB in practice).  Refuse
     * absurd sizes that would indicate a corrupt resource entry. */
    if (mft_size > 1024 * 1024) {
        fprintf(stderr, "[pe_resource] RT_MANIFEST size %zu too large; ignoring\n",
                mft_size);
        return -1;
    }

    int rc = pe_parse_manifest((const char *)mft, mft_size, &g_actx);
    if (rc < 0) return rc;

    if (g_actx.common_controls_version == PE_COMCTL_V6) {
        fprintf(stderr,
            "[pe_resource] manifest: comctl32 v6 (visual styles enabled)\n");
    }
    if (g_actx.requested_execution_level != PE_EXEC_LEVEL_ASINVOKER) {
        fprintf(stderr,
            "[pe_resource] manifest: execution level = %s\n",
            g_actx.requested_execution_level == PE_EXEC_LEVEL_REQUIREADMIN
                ? "requireAdministrator" : "highestAvailable");
    }
    if (g_actx.dpi_aware != PE_DPI_UNAWARE) {
        const char *names[] = {"unaware", "system", "permonitor", "permonitorv2"};
        int idx = g_actx.dpi_aware;
        if (idx < 0 || idx > 3) idx = 0;
        fprintf(stderr, "[pe_resource] manifest: DPI awareness = %s\n", names[idx]);
    }
    if (g_actx.dependency_count) {
        fprintf(stderr,
            "[pe_resource] manifest: %zu dependent assemblies\n",
            g_actx.dependency_count);
    }
    return 1;
}
