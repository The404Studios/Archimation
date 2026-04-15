/*
 * winhttp_session.c - WinHTTP and WinINet via libcurl
 *
 * Real HTTP/HTTPS implementation using libcurl backend.
 * Covers winhttp.dll and wininet.dll exports.
 * Falls back to stub behavior if libcurl is not available.
 *
 * ALL exported functions use WINAPI_EXPORT (__attribute__((ms_abi, visibility("default"))))
 * WCHAR is uint16_t (NOT wchar_t). LPCWSTR is const uint16_t *.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* strcasecmp */
#include <dlfcn.h>
#include <pthread.h>
#include <ctype.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* External wchar_util.c functions */
extern size_t wcslen16(const uint16_t *s);
extern int    wcscmp16(const uint16_t *a, const uint16_t *b);
extern int    utf16_to_utf8(const WCHAR *src, int src_len, char *dst, int dst_size);
extern int    utf8_to_utf16(const char *src, int src_len, WCHAR *dst, int dst_size);

/* ================================================================== */
/*  WinHTTP constants                                                  */
/* ================================================================== */

#define WINHTTP_FLAG_SECURE                 0x00800000
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_ACCESS_TYPE_NO_PROXY        1
#define WINHTTP_ACCESS_TYPE_NAMED_PROXY     3

#define WINHTTP_QUERY_MIME_VERSION          0
#define WINHTTP_QUERY_CONTENT_TYPE          1
#define WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING 2
#define WINHTTP_QUERY_CONTENT_LENGTH        5
#define WINHTTP_QUERY_STATUS_CODE           19
#define WINHTTP_QUERY_STATUS_TEXT           20
#define WINHTTP_QUERY_RAW_HEADERS           21
#define WINHTTP_QUERY_RAW_HEADERS_CRLF      22
#define WINHTTP_QUERY_FLAG_NUMBER           0x20000000
#define WINHTTP_QUERY_FLAG_SYSTEMTIME       0x40000000

#define WINHTTP_OPTION_SECURITY_FLAGS       31
#define WINHTTP_OPTION_CONNECT_TIMEOUT      3
#define WINHTTP_OPTION_SEND_TIMEOUT         5
#define WINHTTP_OPTION_RECEIVE_TIMEOUT      6

#define WINHTTP_AUTH_TARGET_SERVER           0
#define WINHTTP_AUTH_TARGET_PROXY            1

#define WINHTTP_AUTH_SCHEME_BASIC            0x00000001
#define WINHTTP_AUTH_SCHEME_NTLM            0x00000002
#define WINHTTP_AUTH_SCHEME_NEGOTIATE        0x00000010

/* WinINet equivalents */
#define INTERNET_SERVICE_HTTP               3
#define INTERNET_FLAG_SECURE                0x00800000
#define INTERNET_CONNECTION_LAN             0x02

/* URL_COMPONENTS scheme IDs */
#define INTERNET_SCHEME_HTTP                1
#define INTERNET_SCHEME_HTTPS               2

/* Error codes */
#define ERROR_SUCCESS                       0
#define ERROR_INVALID_HANDLE                6
#define ERROR_INSUFFICIENT_BUFFER           122
#define ERROR_INTERNET_NAME_NOT_RESOLVED    12007
#define ERROR_INTERNET_CANNOT_CONNECT       12029
#define ERROR_WINHTTP_AUTODETECTION_FAILED  12180

/* ================================================================== */
/*  libcurl function pointer types (loaded at runtime)                 */
/* ================================================================== */

typedef void CURL;
typedef int CURLcode;

/* Forward-declare curl_slist so we can use pointers to it */
struct curl_slist {
    char *data;
    struct curl_slist *next;
};

/* curl_easy_* */
typedef CURL *(*curl_easy_init_fn)(void);
typedef void (*curl_easy_cleanup_fn)(CURL *);
typedef CURLcode (*curl_easy_setopt_fn)(CURL *, int, ...);
typedef CURLcode (*curl_easy_perform_fn)(CURL *);
typedef CURLcode (*curl_easy_getinfo_fn)(CURL *, int, ...);
typedef const char *(*curl_easy_strerror_fn)(CURLcode);
/* curl_slist */
typedef struct curl_slist *(*curl_slist_append_fn)(struct curl_slist *, const char *);
typedef void (*curl_slist_free_all_fn)(struct curl_slist *);
/* curl_global */
typedef CURLcode (*curl_global_init_fn)(long);
typedef void (*curl_global_cleanup_fn)(void);

/* CURLOPT constants (from curl headers, stable ABI) */
#define CURLOPT_URL             10002
#define CURLOPT_PORT            3
#define CURLOPT_HTTPHEADER      10023
#define CURLOPT_POST            47
#define CURLOPT_POSTFIELDS      10015
#define CURLOPT_POSTFIELDSIZE   60
#define CURLOPT_COPYPOSTFIELDS  10165
#define CURLOPT_WRITEFUNCTION   20011
#define CURLOPT_WRITEDATA       10001
#define CURLOPT_HEADERFUNCTION  20079
#define CURLOPT_HEADERDATA      10029
#define CURLOPT_USERAGENT       10018
#define CURLOPT_TIMEOUT         13
#define CURLOPT_CONNECTTIMEOUT  78
#define CURLOPT_FOLLOWLOCATION  52
#define CURLOPT_SSL_VERIFYPEER  64
#define CURLOPT_SSL_VERIFYHOST  81
#define CURLOPT_CUSTOMREQUEST   10036
#define CURLOPT_NOBODY          44
#define CURLOPT_HTTPGET         80
#define CURLOPT_USERNAME        10173
#define CURLOPT_PASSWORD        10174
#define CURLOPT_PUT             54

/* CURLINFO constants */
#define CURLINFO_RESPONSE_CODE  0x200002
#define CURLINFO_CONTENT_LENGTH 0x300015
#define CURLINFO_CONTENT_TYPE   0x100012

#define CURL_GLOBAL_DEFAULT     3
#define CURLE_OK                0

/* ================================================================== */
/*  libcurl dynamic loader                                             */
/* ================================================================== */

static void *g_curl_lib = NULL;
/* Session 30: curl_load() previously used a plain int guard which let
 * two concurrent WinHttpSendRequest calls each race to dlopen + re-assign
 * g_curl_lib and leak one copy. pthread_once ensures a single initialization
 * even under hot-startup contention. */
static pthread_once_t g_curl_load_once = PTHREAD_ONCE_INIT;

static curl_easy_init_fn      p_easy_init;
static curl_easy_cleanup_fn   p_easy_cleanup;
static curl_easy_setopt_fn    p_easy_setopt;
static curl_easy_perform_fn   p_easy_perform;
static curl_easy_getinfo_fn   p_easy_getinfo;
static curl_easy_strerror_fn  p_easy_strerror;
static curl_slist_append_fn   p_slist_append;
static curl_slist_free_all_fn p_slist_free_all;
static curl_global_init_fn    p_global_init;
static curl_global_cleanup_fn p_global_cleanup;

static void curl_load_once_cb(void)
{
    const char *libs[] = {
        "libcurl.so.4", "libcurl.so", "libcurl-gnutls.so.4", NULL
    };
    for (int i = 0; libs[i]; i++) {
        g_curl_lib = dlopen(libs[i], RTLD_NOW | RTLD_GLOBAL);
        if (g_curl_lib) break;
    }
    if (!g_curl_lib) {
        fprintf(stderr, "[winhttp] libcurl not found - HTTP requests will fail\n");
        return;
    }

    p_easy_init      = (curl_easy_init_fn)dlsym(g_curl_lib, "curl_easy_init");
    p_easy_cleanup   = (curl_easy_cleanup_fn)dlsym(g_curl_lib, "curl_easy_cleanup");
    p_easy_setopt    = (curl_easy_setopt_fn)dlsym(g_curl_lib, "curl_easy_setopt");
    p_easy_perform   = (curl_easy_perform_fn)dlsym(g_curl_lib, "curl_easy_perform");
    p_easy_getinfo   = (curl_easy_getinfo_fn)dlsym(g_curl_lib, "curl_easy_getinfo");
    p_easy_strerror  = (curl_easy_strerror_fn)dlsym(g_curl_lib, "curl_easy_strerror");
    p_slist_append   = (curl_slist_append_fn)dlsym(g_curl_lib, "curl_slist_append");
    p_slist_free_all = (curl_slist_free_all_fn)dlsym(g_curl_lib, "curl_slist_free_all");
    p_global_init    = (curl_global_init_fn)dlsym(g_curl_lib, "curl_global_init");
    p_global_cleanup = (curl_global_cleanup_fn)dlsym(g_curl_lib, "curl_global_cleanup");

    if (!p_easy_init || !p_easy_setopt || !p_easy_perform || !p_easy_getinfo) {
        fprintf(stderr, "[winhttp] libcurl loaded but missing critical functions\n");
        dlclose(g_curl_lib);
        g_curl_lib = NULL;
        return;
    }

    if (p_global_init) p_global_init(CURL_GLOBAL_DEFAULT);
    fprintf(stderr, "[winhttp] libcurl loaded successfully\n");
}

static int curl_load(void)
{
    pthread_once(&g_curl_load_once, curl_load_once_cb);
    return g_curl_lib ? 0 : -1;
}

/* ================================================================== */
/*  Internal handle structures                                         */
/* ================================================================== */

#define WH_TYPE_SESSION    1
#define WH_TYPE_CONNECTION 2
#define WH_TYPE_REQUEST    3

typedef struct winhttp_session {
    int  type;
    char user_agent[256];
    DWORD access_type;
    DWORD flags;
} winhttp_session_t;

typedef struct winhttp_connection {
    int  type;
    winhttp_session_t *session;
    char server[512];
    WORD port;
    int  is_secure;         /* derived from flags or port */
} winhttp_connection_t;

/* Growable buffer for response body / headers */
typedef struct {
    char  *data;
    size_t size;
    size_t capacity;
} response_buf_t;

typedef struct winhttp_request {
    int  type;
    winhttp_connection_t *conn;
    int  owns_conn;             /* 1 if this request owns (and must free) conn */
    char verb[32];
    char path[2048];
    char url[4096];
    DWORD flags;
    CURL *curl;

    /* Request headers (curl_slist chain) */
    struct curl_slist *req_headers;

    /* POST/PUT body (accumulated via WinHttpWriteData or SendRequest optional) */
    char  *post_data;
    DWORD  post_len;
    DWORD  post_capacity;

    /* Credentials */
    char username[256];
    char password[256];

    /* Timeouts (milliseconds, 0 = default) */
    int connect_timeout_ms;
    int send_timeout_ms;
    int receive_timeout_ms;

    /* Response state */
    int  performed;         /* 1 after curl_easy_perform succeeds */
    long status_code;
    response_buf_t resp_headers;
    response_buf_t resp_body;
    size_t read_offset;     /* how far WinHttpReadData has consumed */
} winhttp_request_t;

/* ================================================================== */
/*  curl write callbacks (sysv_abi - called by libcurl)                */
/* ================================================================== */

static size_t write_body_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    response_buf_t *buf = (response_buf_t *)userdata;
    if (!buf) return 0;
    size_t total = size * nmemb;

    if (buf->size + total >= buf->capacity) {
        size_t new_cap = (buf->capacity + total) * 2;
        if (new_cap < 8192) new_cap = 8192;
        char *tmp = realloc(buf->data, new_cap);
        if (!tmp) return 0;  /* signal write error to curl */
        buf->data = tmp;
        buf->capacity = new_cap;
    }
    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    return total;
}

static size_t write_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    return write_body_cb(ptr, size, nmemb, userdata);
}

/* ================================================================== */
/*  Wide string <-> UTF-8 helpers                                      */
/* ================================================================== */

/*
 * Convert LPCWSTR (uint16_t*) to a UTF-8 char buffer.
 * Uses the proper utf16_to_utf8 from wchar_util.c when available,
 * but also has a fast-path for pure-ASCII strings.
 */
static void wstr_to_utf8(const WCHAR *wstr, char *out, size_t out_size)
{
    if (!wstr || out_size == 0) {
        if (out && out_size > 0) out[0] = '\0';
        return;
    }
    /* Use proper conversion from wchar_util.c */
    int needed = utf16_to_utf8(wstr, -1, out, (int)out_size);
    /* Ensure null-termination */
    if (needed <= 0) {
        out[0] = '\0';
    } else if ((size_t)needed >= out_size) {
        out[out_size - 1] = '\0';
    }
}

/*
 * Convert a UTF-8 string to a WCHAR (uint16_t) buffer.
 * Caller must ensure dst has enough room.
 * Returns number of WCHARs written (including null).
 */
static int utf8_to_wstr(const char *src, WCHAR *dst, int dst_wchars)
    __attribute__((unused));
static int utf8_to_wstr(const char *src, WCHAR *dst, int dst_wchars)
{
    if (!src || !dst || dst_wchars <= 0) return 0;
    return utf8_to_utf16(src, -1, dst, dst_wchars);
}

/* ================================================================== */
/*  Internal: configure curl handle and perform the request            */
/* ================================================================== */

static void req_free_response(winhttp_request_t *req)
{
    free(req->resp_body.data);
    req->resp_body.data = NULL;
    req->resp_body.size = 0;
    req->resp_body.capacity = 0;
    free(req->resp_headers.data);
    req->resp_headers.data = NULL;
    req->resp_headers.size = 0;
    req->resp_headers.capacity = 0;
    req->read_offset = 0;
    req->performed = 0;
    req->status_code = 0;
}

static int req_perform(winhttp_request_t *req)
{
    if (!req || !req->curl) return -1;

    /* URL */
    p_easy_setopt(req->curl, CURLOPT_URL, req->url);

    /* User-agent */
    if (req->conn && req->conn->session) {
        p_easy_setopt(req->curl, CURLOPT_USERAGENT, req->conn->session->user_agent);
    }

    /* Follow redirects */
    p_easy_setopt(req->curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* Write callbacks */
    p_easy_setopt(req->curl, CURLOPT_WRITEFUNCTION, write_body_cb);
    p_easy_setopt(req->curl, CURLOPT_WRITEDATA, &req->resp_body);
    p_easy_setopt(req->curl, CURLOPT_HEADERFUNCTION, write_header_cb);
    p_easy_setopt(req->curl, CURLOPT_HEADERDATA, &req->resp_headers);

    /* Timeouts */
    long ct = (req->connect_timeout_ms > 0) ? (long)(req->connect_timeout_ms / 1000) : 30L;
    long rt = (req->receive_timeout_ms > 0) ? (long)(req->receive_timeout_ms / 1000) : 300L;
    if (ct < 1) ct = 1;
    if (rt < 1) rt = 1;
    p_easy_setopt(req->curl, CURLOPT_CONNECTTIMEOUT, ct);
    p_easy_setopt(req->curl, CURLOPT_TIMEOUT, rt);

    /* SSL: if WINHTTP_FLAG_SECURE was used, ensure SSL verification is on */
    if (req->flags & WINHTTP_FLAG_SECURE) {
        p_easy_setopt(req->curl, CURLOPT_SSL_VERIFYPEER, 1L);
        p_easy_setopt(req->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    /* Method */
    if (strcasecmp(req->verb, "POST") == 0) {
        p_easy_setopt(req->curl, CURLOPT_POST, 1L);
        if (req->post_data && req->post_len > 0) {
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDS, req->post_data);
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, (long)req->post_len);
        } else {
            /* Empty POST body */
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, 0L);
        }
    } else if (strcasecmp(req->verb, "PUT") == 0) {
        p_easy_setopt(req->curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (req->post_data && req->post_len > 0) {
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDS, req->post_data);
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, (long)req->post_len);
        }
    } else if (strcasecmp(req->verb, "HEAD") == 0) {
        p_easy_setopt(req->curl, CURLOPT_NOBODY, 1L);
    } else if (strcasecmp(req->verb, "DELETE") == 0 ||
               strcasecmp(req->verb, "PATCH") == 0 ||
               strcasecmp(req->verb, "OPTIONS") == 0) {
        p_easy_setopt(req->curl, CURLOPT_CUSTOMREQUEST, req->verb);
        if (req->post_data && req->post_len > 0) {
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDS, req->post_data);
            p_easy_setopt(req->curl, CURLOPT_POSTFIELDSIZE, (long)req->post_len);
        }
    } else {
        /* GET or anything else default */
        p_easy_setopt(req->curl, CURLOPT_HTTPGET, 1L);
    }

    /* Request headers */
    if (req->req_headers) {
        p_easy_setopt(req->curl, CURLOPT_HTTPHEADER, req->req_headers);
    }

    /* Credentials */
    if (req->username[0]) {
        p_easy_setopt(req->curl, CURLOPT_USERNAME, req->username);
    }
    if (req->password[0]) {
        p_easy_setopt(req->curl, CURLOPT_PASSWORD, req->password);
    }

    /* Perform */
    fprintf(stderr, "[winhttp] performing %s %s\n", req->verb, req->url);
    CURLcode res = p_easy_perform(req->curl);
    if (res != CURLE_OK) {
        const char *err = p_easy_strerror ? p_easy_strerror(res) : "unknown";
        fprintf(stderr, "[winhttp] curl_easy_perform failed: %s (code %d)\n", err, res);
        return -1;
    }

    if (p_easy_getinfo) {
        p_easy_getinfo(req->curl, CURLINFO_RESPONSE_CODE, &req->status_code);
    }
    req->performed = 1;
    req->read_offset = 0;

    fprintf(stderr, "[winhttp] HTTP %ld, body=%zu bytes, headers=%zu bytes\n",
            req->status_code, req->resp_body.size, req->resp_headers.size);
    return 0;
}

/*
 * Build the full URL from connection info + request path + flags.
 */
static void req_build_url(winhttp_request_t *req)
{
    if (!req || !req->conn) return;
    winhttp_connection_t *conn = req->conn;

    const char *scheme;
    if (req->flags & WINHTTP_FLAG_SECURE) {
        scheme = "https";
    } else if (conn->is_secure) {
        scheme = "https";
    } else {
        scheme = "http";
    }

    const char *path = req->path;
    if (!path[0]) path = "/";

    if (conn->port == 0 ||
        (strcmp(scheme, "http") == 0 && conn->port == 80) ||
        (strcmp(scheme, "https") == 0 && conn->port == 443)) {
        snprintf(req->url, sizeof(req->url), "%s://%s%s%s",
                 scheme, conn->server,
                 (path[0] == '/') ? "" : "/",
                 path);
    } else {
        snprintf(req->url, sizeof(req->url), "%s://%s:%u%s%s",
                 scheme, conn->server, conn->port,
                 (path[0] == '/') ? "" : "/",
                 path);
    }
}

/*
 * Parse header lines to find a specific header value.
 * header_data is the raw response headers buffer (HTTP lines separated by \r\n).
 * header_name is the header to search for (case-insensitive, without the colon).
 * Returns a pointer into header_data at the value, or NULL.
 */
static const char *find_header_value(const response_buf_t *hdrs, const char *header_name)
{
    if (!hdrs || !hdrs->data || !header_name) return NULL;

    size_t name_len = strlen(header_name);
    const char *p = hdrs->data;
    const char *end = hdrs->data + hdrs->size;

    while (p < end) {
        /* Find end of this line */
        const char *eol = p;
        while (eol < end && *eol != '\r' && *eol != '\n') eol++;

        size_t line_len = (size_t)(eol - p);
        /* Check if line starts with header_name: */
        if (line_len > name_len + 1 &&
            strncasecmp(p, header_name, name_len) == 0 &&
            p[name_len] == ':') {
            const char *val = p + name_len + 1;
            while (val < eol && (*val == ' ' || *val == '\t')) val++;
            return val;
        }

        /* Skip past \r\n */
        p = eol;
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;
    }
    return NULL;
}

/*
 * Add request headers from a wide string (headers separated by \r\n).
 */
static void req_add_headers_wide(winhttp_request_t *req, LPCWSTR headers, DWORD headersLen)
{
    if (!req || !headers || !p_slist_append) return;

    /* Determine length */
    size_t wlen;
    if (headersLen == (DWORD)-1) {
        wlen = wcslen16(headers);
    } else {
        wlen = headersLen;
    }
    if (wlen == 0) return;

    /* Convert to UTF-8 */
    size_t buf_size = wlen * 4 + 1;
    char *hdr_buf = malloc(buf_size);
    if (!hdr_buf) return;

    /* Manually convert the specific length */
    int written = utf16_to_utf8(headers, (int)wlen, hdr_buf, (int)buf_size);
    if (written <= 0) { free(hdr_buf); return; }
    hdr_buf[buf_size - 1] = '\0';

    /* Split by \r\n and add each non-empty line */
    char *saveptr = NULL;
    char *line = strtok_r(hdr_buf, "\r\n", &saveptr);
    while (line) {
        if (line[0] != '\0') {
            req->req_headers = p_slist_append(req->req_headers, line);
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    free(hdr_buf);
}

/*
 * Add request headers from a narrow (ANSI) string.
 */
static void req_add_headers_narrow(winhttp_request_t *req, LPCSTR headers, DWORD headersLen)
{
    if (!req || !headers || !p_slist_append) return;

    size_t len = (headersLen == (DWORD)-1) ? strlen(headers) : (size_t)headersLen;
    if (len == 0) return;

    char *hdr_copy = malloc(len + 1);
    if (!hdr_copy) return;
    memcpy(hdr_copy, headers, len);
    hdr_copy[len] = '\0';

    char *saveptr = NULL;
    char *line = strtok_r(hdr_copy, "\r\n", &saveptr);
    while (line) {
        if (line[0] != '\0') {
            req->req_headers = p_slist_append(req->req_headers, line);
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    free(hdr_copy);
}

/* ================================================================== */
/*  Cleanup helper (shared by WinHttpCloseHandle and InternetClose)    */
/* ================================================================== */

static void req_cleanup(winhttp_request_t *req)
{
    if (!req) return;
    if (req->curl && p_easy_cleanup)
        p_easy_cleanup(req->curl);
    req->curl = NULL;
    if (req->req_headers && p_slist_free_all)
        p_slist_free_all(req->req_headers);
    req->req_headers = NULL;
    free(req->post_data);
    req->post_data = NULL;
    free(req->resp_body.data);
    req->resp_body.data = NULL;
    free(req->resp_headers.data);
    req->resp_headers.data = NULL;
    /* Free owned connection (e.g. from InternetOpenUrlA) */
    if (req->owns_conn && req->conn) {
        free(req->conn);
        req->conn = NULL;
    }
}

/* ================================================================== */
/*  WinHTTP functions (winhttp.dll)                                    */
/* ================================================================== */

WINAPI_EXPORT HANDLE WinHttpOpen(LPCWSTR agent, DWORD access,
                                  LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
{
    (void)proxy; (void)bypass;
    curl_load();

    winhttp_session_t *sess = calloc(1, sizeof(winhttp_session_t));
    if (!sess) return NULL;
    sess->type = WH_TYPE_SESSION;
    sess->access_type = access;
    sess->flags = flags;

    if (agent) {
        wstr_to_utf8(agent, sess->user_agent, sizeof(sess->user_agent));
    } else {
        snprintf(sess->user_agent, sizeof(sess->user_agent), "PELoader/1.0");
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_SESSION, -1, sess);
    fprintf(stderr, "[winhttp] WinHttpOpen(\"%s\") -> %p\n", sess->user_agent, h);
    return h;
}

WINAPI_EXPORT HANDLE WinHttpConnect(HANDLE session, LPCWSTR server,
                                     WORD port, DWORD reserved)
{
    TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "WinHttpConnect", NULL);
    (void)reserved;
    handle_entry_t *se = handle_lookup(session);
    if (!se || !se->data) return NULL;

    winhttp_connection_t *conn = calloc(1, sizeof(winhttp_connection_t));
    if (!conn) return NULL;
    conn->type = WH_TYPE_CONNECTION;
    conn->session = (winhttp_session_t *)se->data;
    conn->port = port;
    conn->is_secure = (port == 443) ? 1 : 0;
    if (server) wstr_to_utf8(server, conn->server, sizeof(conn->server));

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_CONNECTION, -1, conn);
    fprintf(stderr, "[winhttp] WinHttpConnect(\"%s\":%u) -> %p\n",
            conn->server, (unsigned)port, h);
    return h;
}

WINAPI_EXPORT HANDLE WinHttpOpenRequest(HANDLE hConnect, LPCWSTR verb,
                                         LPCWSTR path, LPCWSTR version,
                                         LPCWSTR referrer, LPCWSTR *types,
                                         DWORD flags)
{
    (void)version; (void)referrer; (void)types;
    handle_entry_t *ce = handle_lookup(hConnect);
    if (!ce || !ce->data) return NULL;
    winhttp_connection_t *conn = (winhttp_connection_t *)ce->data;

    winhttp_request_t *req = calloc(1, sizeof(winhttp_request_t));
    if (!req) return NULL;
    req->type = WH_TYPE_REQUEST;
    req->conn = conn;
    req->flags = flags;

    if (verb) {
        wstr_to_utf8(verb, req->verb, sizeof(req->verb));
    } else {
        snprintf(req->verb, sizeof(req->verb), "GET");
    }

    if (path) {
        wstr_to_utf8(path, req->path, sizeof(req->path));
    } else {
        snprintf(req->path, sizeof(req->path), "/");
    }

    /* Build full URL */
    req_build_url(req);

    /* Init curl handle */
    if (g_curl_lib && p_easy_init) {
        req->curl = p_easy_init();
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_REQUEST, -1, req);
    fprintf(stderr, "[winhttp] WinHttpOpenRequest(%s %s) -> %p\n",
            req->verb, req->url, h);
    return h;
}

WINAPI_EXPORT BOOL WinHttpAddRequestHeaders(HANDLE request, LPCWSTR headers,
                                              DWORD headersLen, DWORD modifiers)
{
    (void)modifiers;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    req_add_headers_wide(req, headers, headersLen);
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpSendRequest(HANDLE request, LPCWSTR headers,
                                       DWORD headersLen, LPVOID optional,
                                       DWORD optionalLen, DWORD totalLen,
                                       DWORD_PTR context)
{
    TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "WinHttpSendRequest", FALSE);
    (void)context;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    if (!req->curl) {
        fprintf(stderr, "[winhttp] WinHttpSendRequest: no curl handle (libcurl not loaded)\n");
        set_last_error(ERROR_INTERNET_NAME_NOT_RESOLVED);
        return FALSE;
    }

    /* Add any additional headers passed with this call */
    if (headers && headersLen != 0) {
        req_add_headers_wide(req, headers, headersLen);
    }

    /* Optional data (inline POST body) */
    if (optional && optionalLen > 0) {
        free(req->post_data);
        req->post_data = malloc(optionalLen);
        if (req->post_data) {
            memcpy(req->post_data, optional, optionalLen);
            req->post_len = optionalLen;
            req->post_capacity = optionalLen;
        } else {
            req->post_len = 0;
            req->post_capacity = 0;
        }
    }

    /* If totalLen is specified but no data yet, we may be expecting WriteData calls.
     * However, since we perform synchronously, we perform now with whatever data we have.
     * If the app calls WriteData before SendRequest, the data is already in post_data. */
    (void)totalLen;

    /* Clear any previous response */
    req_free_response(req);

    /* Perform */
    if (req_perform(req) != 0) {
        set_last_error(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpReceiveResponse(HANDLE request, void *reserved)
{
    (void)reserved;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;
    /* Already performed in SendRequest */
    return req->performed ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL WinHttpQueryDataAvailable(HANDLE request, LPDWORD bytesAvailable)
{
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) {
        if (bytesAvailable) *bytesAvailable = 0;
        return FALSE;
    }
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    DWORD avail = 0;
    if (req->performed && req->resp_body.data && req->read_offset < req->resp_body.size) {
        avail = (DWORD)(req->resp_body.size - req->read_offset);
    }
    if (bytesAvailable) *bytesAvailable = avail;
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpReadData(HANDLE request, LPVOID buffer,
                                    DWORD toRead, LPDWORD bytesRead)
{
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) {
        if (bytesRead) *bytesRead = 0;
        return FALSE;
    }
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    if (!req->performed || !req->resp_body.data) {
        if (bytesRead) *bytesRead = 0;
        return TRUE;  /* EOF - no error, just 0 bytes */
    }

    size_t avail = req->resp_body.size - req->read_offset;
    size_t copy = (toRead < avail) ? toRead : avail;
    if (copy > 0 && buffer) {
        memcpy(buffer, req->resp_body.data + req->read_offset, copy);
        req->read_offset += copy;
    }
    if (bytesRead) *bytesRead = (DWORD)copy;
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpWriteData(HANDLE request, LPCVOID buffer,
                                      DWORD toWrite, LPDWORD bytesWritten)
{
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) {
        if (bytesWritten) *bytesWritten = 0;
        return FALSE;
    }
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    if (!buffer || toWrite == 0) {
        if (bytesWritten) *bytesWritten = 0;
        return TRUE;
    }

    /* Grow post_data buffer */
    DWORD needed = req->post_len + toWrite;
    if (needed > req->post_capacity) {
        DWORD new_cap = needed * 2;
        if (new_cap < 4096) new_cap = 4096;
        char *new_data = realloc(req->post_data, new_cap);
        if (!new_data) {
            if (bytesWritten) *bytesWritten = 0;
            return FALSE;
        }
        req->post_data = new_data;
        req->post_capacity = new_cap;
    }
    memcpy(req->post_data + req->post_len, buffer, toWrite);
    req->post_len += toWrite;

    if (bytesWritten) *bytesWritten = toWrite;
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpQueryHeaders(HANDLE request, DWORD infoLevel,
                                        LPCWSTR name, LPVOID buffer,
                                        LPDWORD bufLen, LPDWORD index)
{
    (void)name; (void)index;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    DWORD query_id = infoLevel & 0xFFFF;
    int flag_number = (infoLevel & WINHTTP_QUERY_FLAG_NUMBER) != 0;

    /* --- Status code (19) --- */
    if (query_id == WINHTTP_QUERY_STATUS_CODE) {
        if (flag_number) {
            if (buffer && bufLen && *bufLen >= sizeof(DWORD)) {
                *(DWORD *)buffer = (DWORD)req->status_code;
                *bufLen = sizeof(DWORD);
                return TRUE;
            }
            if (bufLen) *bufLen = sizeof(DWORD);
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        } else {
            /* Return as wide string */
            char code_str[16];
            snprintf(code_str, sizeof(code_str), "%ld", req->status_code);
            DWORD needed = (DWORD)(strlen(code_str) + 1) * sizeof(WCHAR);
            if (buffer && bufLen && *bufLen >= needed) {
                WCHAR *wbuf = (WCHAR *)buffer;
                for (size_t i = 0; code_str[i]; i++) wbuf[i] = (WCHAR)code_str[i];
                wbuf[strlen(code_str)] = 0;
                *bufLen = needed - sizeof(WCHAR);  /* excludes null */
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }

    /* --- Status text (20) --- */
    if (query_id == WINHTTP_QUERY_STATUS_TEXT) {
        /* Extract from first response header line: "HTTP/1.1 200 OK\r\n" */
        const char *status_text = "OK";
        if (req->resp_headers.data && req->resp_headers.size > 0) {
            const char *p = req->resp_headers.data;
            /* Skip "HTTP/x.x NNN " */
            const char *space1 = strchr(p, ' ');
            if (space1) {
                const char *space2 = strchr(space1 + 1, ' ');
                if (space2) {
                    status_text = space2 + 1;
                }
            }
        }
        /* Find end of status text (until \r or \n) */
        size_t st_len = 0;
        while (status_text[st_len] && status_text[st_len] != '\r' && status_text[st_len] != '\n')
            st_len++;

        DWORD needed = (DWORD)(st_len + 1) * sizeof(WCHAR);
        if (buffer && bufLen && *bufLen >= needed) {
            WCHAR *wbuf = (WCHAR *)buffer;
            for (size_t i = 0; i < st_len; i++) wbuf[i] = (WCHAR)(unsigned char)status_text[i];
            wbuf[st_len] = 0;
            *bufLen = needed - sizeof(WCHAR);
            return TRUE;
        }
        if (bufLen) *bufLen = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* --- Raw headers with CRLF (22) --- */
    if (query_id == WINHTTP_QUERY_RAW_HEADERS_CRLF) {
        if (req->resp_headers.data && req->resp_headers.size > 0) {
            DWORD needed = (DWORD)(req->resp_headers.size + 1) * sizeof(WCHAR);
            if (buffer && bufLen && *bufLen >= needed) {
                WCHAR *wbuf = (WCHAR *)buffer;
                for (size_t i = 0; i < req->resp_headers.size; i++)
                    wbuf[i] = (WCHAR)(unsigned char)req->resp_headers.data[i];
                wbuf[req->resp_headers.size] = 0;
                *bufLen = needed - sizeof(WCHAR);
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }

    /* --- Raw headers null-separated (21) --- */
    if (query_id == WINHTTP_QUERY_RAW_HEADERS) {
        if (req->resp_headers.data && req->resp_headers.size > 0) {
            /* Convert \r\n to \0 separators, double-null terminated */
            DWORD needed = (DWORD)(req->resp_headers.size + 2) * sizeof(WCHAR);
            if (buffer && bufLen && *bufLen >= needed) {
                WCHAR *wbuf = (WCHAR *)buffer;
                size_t j = 0;
                for (size_t i = 0; i < req->resp_headers.size; i++) {
                    char c = req->resp_headers.data[i];
                    if (c == '\r') continue;
                    if (c == '\n') {
                        wbuf[j++] = 0;  /* null separator */
                    } else {
                        wbuf[j++] = (WCHAR)(unsigned char)c;
                    }
                }
                wbuf[j++] = 0;  /* final null */
                wbuf[j] = 0;    /* double null */
                *bufLen = (DWORD)(j * sizeof(WCHAR));
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }

    /* --- Content-Length (5) --- */
    if (query_id == WINHTTP_QUERY_CONTENT_LENGTH) {
        if (flag_number) {
            if (buffer && bufLen && *bufLen >= sizeof(DWORD)) {
                *(DWORD *)buffer = (DWORD)req->resp_body.size;
                *bufLen = sizeof(DWORD);
                return TRUE;
            }
            if (bufLen) *bufLen = sizeof(DWORD);
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        } else {
            char len_str[32];
            snprintf(len_str, sizeof(len_str), "%zu", req->resp_body.size);
            DWORD needed = (DWORD)(strlen(len_str) + 1) * sizeof(WCHAR);
            if (buffer && bufLen && *bufLen >= needed) {
                WCHAR *wbuf = (WCHAR *)buffer;
                for (size_t i = 0; len_str[i]; i++) wbuf[i] = (WCHAR)len_str[i];
                wbuf[strlen(len_str)] = 0;
                *bufLen = needed - sizeof(WCHAR);
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }

    /* --- Content-Type (1) --- */
    if (query_id == WINHTTP_QUERY_CONTENT_TYPE) {
        const char *ct = find_header_value(&req->resp_headers, "Content-Type");
        if (!ct) return FALSE;
        /* Find end of value */
        size_t vlen = 0;
        while (ct[vlen] && ct[vlen] != '\r' && ct[vlen] != '\n') vlen++;

        DWORD needed = (DWORD)(vlen + 1) * sizeof(WCHAR);
        if (buffer && bufLen && *bufLen >= needed) {
            WCHAR *wbuf = (WCHAR *)buffer;
            for (size_t i = 0; i < vlen; i++) wbuf[i] = (WCHAR)(unsigned char)ct[i];
            wbuf[vlen] = 0;
            *bufLen = needed - sizeof(WCHAR);
            return TRUE;
        }
        if (bufLen) *bufLen = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* Unknown query */
    return FALSE;
}

WINAPI_EXPORT BOOL WinHttpSetCredentials(HANDLE request, DWORD target,
                                           DWORD scheme, LPCWSTR user,
                                           LPCWSTR pass, void *pAuthParams)
{
    (void)target; (void)scheme; (void)pAuthParams;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    if (user) wstr_to_utf8(user, req->username, sizeof(req->username));
    if (pass) wstr_to_utf8(pass, req->password, sizeof(req->password));
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpSetTimeouts(HANDLE h, int resolve, int connect,
                                        int send_timeout, int receive)
{
    (void)resolve;
    handle_entry_t *re = handle_lookup(h);
    if (!re || !re->data) return TRUE;

    /* Could be a session or request handle; only apply to requests */
    winhttp_request_t *req = (winhttp_request_t *)re->data;
    if (req->type != WH_TYPE_REQUEST) return TRUE;

    if (connect > 0) req->connect_timeout_ms = connect;
    if (send_timeout > 0) req->send_timeout_ms = send_timeout;
    if (receive > 0) req->receive_timeout_ms = receive;
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpSetOption(HANDLE h, DWORD option, LPVOID buffer, DWORD bufLen)
{
    (void)h; (void)buffer; (void)bufLen;

    handle_entry_t *entry = handle_lookup(h);
    if (!entry || !entry->data) return TRUE;  /* silently succeed for unknown handles */

    /* Apply recognized options to request handles */
    if (entry->type == HANDLE_TYPE_WINHTTP_REQUEST) {
        winhttp_request_t *req = (winhttp_request_t *)entry->data;
        if (req->type == WH_TYPE_REQUEST && req->curl) {
            switch (option) {
            case WINHTTP_OPTION_CONNECT_TIMEOUT:
                if (buffer && bufLen >= sizeof(DWORD)) {
                    req->connect_timeout_ms = (int)(*(DWORD *)buffer);
                }
                break;
            case WINHTTP_OPTION_RECEIVE_TIMEOUT:
                if (buffer && bufLen >= sizeof(DWORD)) {
                    req->receive_timeout_ms = (int)(*(DWORD *)buffer);
                }
                break;
            case WINHTTP_OPTION_SECURITY_FLAGS:
                /* Could tweak SSL verification here */
                break;
            default:
                break;
            }
        }
    }
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpQueryOption(HANDLE h, DWORD option, LPVOID buffer, LPDWORD bufLen)
{
    (void)h; (void)option; (void)buffer; (void)bufLen;
    return FALSE;
}

WINAPI_EXPORT BOOL WinHttpCloseHandle(HANDLE h)
{
    handle_entry_t *entry = handle_lookup(h);
    if (!entry) return TRUE;

    if (entry->data) {
        /* Check handle type to determine cleanup */
        if (entry->type == HANDLE_TYPE_WINHTTP_REQUEST) {
            winhttp_request_t *req = (winhttp_request_t *)entry->data;
            if (req->type == WH_TYPE_REQUEST) {
                req_cleanup(req);
            }
        }
        /* For session and connection, no special cleanup needed beyond free */
        free(entry->data);
        entry->data = NULL;
    }
    handle_close(h);
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpGetProxyForUrl(HANDLE session, LPCWSTR url,
                                           void *pAutoProxyOptions, void *pProxyInfo)
{
    (void)session; (void)url; (void)pAutoProxyOptions; (void)pProxyInfo;
    set_last_error(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

WINAPI_EXPORT BOOL WinHttpGetDefaultProxyConfiguration(void *pProxyInfo)
{
    if (pProxyInfo) memset(pProxyInfo, 0, 24);
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpGetIEProxyConfigForCurrentUser(void *pProxyConfig)
{
    if (pProxyConfig) memset(pProxyConfig, 0, 32);
    return TRUE;
}

/* ================================================================== */
/*  WinHttpCrackUrl - parse URL into components                        */
/* ================================================================== */

/*
 * URL_COMPONENTS layout (from winhttp.h):
 *   DWORD dwStructSize;
 *   LPWSTR lpszScheme;      DWORD dwSchemeLength;
 *   int    nScheme;
 *   LPWSTR lpszHostName;    DWORD dwHostNameLength;
 *   WORD   nPort;           (2 bytes padding)
 *   LPWSTR lpszUserName;    DWORD dwUserNameLength;
 *   LPWSTR lpszPassword;    DWORD dwPasswordLength;
 *   LPWSTR lpszUrlPath;     DWORD dwUrlPathLength;
 *   LPWSTR lpszExtraInfo;   DWORD dwExtraInfoLength;
 *
 * We work with a packed struct matching the Windows x64 layout.
 */
#pragma pack(push, 8)
typedef struct {
    DWORD   dwStructSize;
    LPWSTR  lpszScheme;
    DWORD   dwSchemeLength;
    int     nScheme;
    LPWSTR  lpszHostName;
    DWORD   dwHostNameLength;
    WORD    nPort;
    WORD    _pad1;
    DWORD   _pad2;
    LPWSTR  lpszUserName;
    DWORD   dwUserNameLength;
    DWORD   _pad3;
    LPWSTR  lpszPassword;
    DWORD   dwPasswordLength;
    DWORD   _pad4;
    LPWSTR  lpszUrlPath;
    DWORD   dwUrlPathLength;
    DWORD   _pad5;
    LPWSTR  lpszExtraInfo;
    DWORD   dwExtraInfoLength;
} URL_COMPONENTS_W;
#pragma pack(pop)

/*
 * Helper: copy a narrow string into a WCHAR buffer in URL_COMPONENTS.
 * If the pointer field is non-NULL and length > 0, we copy into the provided buffer.
 * If the pointer field is NULL and length == 0, we point it into the original URL wide string.
 */
static void crack_copy_component(LPWSTR *field_ptr, DWORD *field_len,
                                  const char *value, size_t value_len,
                                  const WCHAR *url_base, size_t url_offset)
{
    if (!field_ptr || !field_len) return;

    if (*field_ptr != NULL && *field_len > 0) {
        /* Caller provided a buffer - copy into it */
        DWORD max_copy = *field_len;
        DWORD copy_len = (DWORD)value_len;
        if (copy_len >= max_copy) copy_len = max_copy - 1;
        for (DWORD i = 0; i < copy_len; i++) {
            (*field_ptr)[i] = (WCHAR)(unsigned char)value[i];
        }
        (*field_ptr)[copy_len] = 0;
        *field_len = copy_len;
    } else if (*field_len == 0 && *field_ptr == NULL) {
        /* Point into the original URL string */
        *field_ptr = (LPWSTR)(url_base + url_offset);
        *field_len = (DWORD)value_len;
    }
}

WINAPI_EXPORT BOOL WinHttpCrackUrl(LPCWSTR pwszUrl, DWORD dwUrlLength,
                                     DWORD dwFlags, void *lpUrlComponents)
{
    (void)dwFlags;
    if (!pwszUrl || !lpUrlComponents) return FALSE;

    URL_COMPONENTS_W *uc = (URL_COMPONENTS_W *)lpUrlComponents;

    /* Convert URL to UTF-8 for parsing */
    size_t url_wlen = (dwUrlLength > 0) ? dwUrlLength : wcslen16(pwszUrl);
    size_t buf_size = url_wlen * 4 + 1;
    char *url_utf8 = malloc(buf_size);
    if (!url_utf8) return FALSE;

    int written = utf16_to_utf8(pwszUrl, (int)url_wlen, url_utf8, (int)buf_size);
    if (written <= 0) { free(url_utf8); return FALSE; }
    url_utf8[buf_size - 1] = '\0';

    /* Parse: scheme://[user:pass@]host[:port][/path][?query][#fragment] */
    const char *p = url_utf8;
    /* Find scheme */
    const char *colon = strstr(p, "://");
    if (!colon) { free(url_utf8); return FALSE; }

    size_t scheme_len = (size_t)(colon - p);
    char scheme_buf[32] = {0};
    if (scheme_len < sizeof(scheme_buf)) {
        memcpy(scheme_buf, p, scheme_len);
    }

    int nScheme = 0;
    WORD default_port = 80;
    if (strcasecmp(scheme_buf, "https") == 0) {
        nScheme = INTERNET_SCHEME_HTTPS;
        default_port = 443;
    } else if (strcasecmp(scheme_buf, "http") == 0) {
        nScheme = INTERNET_SCHEME_HTTP;
        default_port = 80;
    }

    /* Calculate offsets into the wide URL string */
    size_t scheme_offset = 0;  /* scheme starts at position 0 */

    p = colon + 3;  /* skip "://" */
    size_t after_scheme_offset = scheme_len + 3;

    /* Check for user:pass@ */
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    const char *user_start = NULL;
    size_t user_len = 0;
    const char *pass_start = NULL;
    size_t pass_len = 0;
    size_t user_offset = 0, pass_offset = 0;

    if (at && (!slash || at < slash)) {
        /* There is userinfo */
        user_start = p;
        const char *user_colon = strchr(p, ':');
        if (user_colon && user_colon < at) {
            user_len = (size_t)(user_colon - p);
            pass_start = user_colon + 1;
            pass_len = (size_t)(at - pass_start);
            user_offset = after_scheme_offset;
            pass_offset = after_scheme_offset + user_len + 1;
        } else {
            user_len = (size_t)(at - p);
            user_offset = after_scheme_offset;
        }
        p = at + 1;
        after_scheme_offset = (size_t)(p - url_utf8);
    }

    /* Host (and optional port) */
    const char *host_start = p;
    size_t host_offset = (size_t)(p - url_utf8);

    /* Find end of host */
    const char *host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/' &&
           *host_end != '?' && *host_end != '#') {
        host_end++;
    }
    size_t host_len = (size_t)(host_end - host_start);

    /* Port */
    WORD port = default_port;
    if (*host_end == ':') {
        port = (WORD)atoi(host_end + 1);
        /* Skip past port digits */
        p = host_end + 1;
        while (*p >= '0' && *p <= '9') p++;
    } else {
        p = host_end;
    }

    /* Path */
    const char *path_start = p;
    size_t path_offset = (size_t)(p - url_utf8);
    const char *path_end = p;
    while (*path_end && *path_end != '?' && *path_end != '#') path_end++;
    size_t path_len = (size_t)(path_end - path_start);

    /* Extra info (query string + fragment) */
    const char *extra_start = path_end;
    size_t extra_offset = (size_t)(path_end - url_utf8);
    size_t extra_len = strlen(extra_start);

    /* Fill in URL_COMPONENTS */
    uc->nScheme = nScheme;
    uc->nPort = port;

    crack_copy_component(&uc->lpszScheme, &uc->dwSchemeLength,
                          scheme_buf, scheme_len, pwszUrl, scheme_offset);

    char host_buf[512] = {0};
    if (host_len < sizeof(host_buf)) memcpy(host_buf, host_start, host_len);
    crack_copy_component(&uc->lpszHostName, &uc->dwHostNameLength,
                          host_buf, host_len, pwszUrl, host_offset);

    if (user_start) {
        char user_buf[256] = {0};
        if (user_len < sizeof(user_buf)) memcpy(user_buf, user_start, user_len);
        crack_copy_component(&uc->lpszUserName, &uc->dwUserNameLength,
                              user_buf, user_len, pwszUrl, user_offset);
    }
    if (pass_start) {
        char pass_buf[256] = {0};
        if (pass_len < sizeof(pass_buf)) memcpy(pass_buf, pass_start, pass_len);
        crack_copy_component(&uc->lpszPassword, &uc->dwPasswordLength,
                              pass_buf, pass_len, pwszUrl, pass_offset);
    }

    char path_buf[2048] = {0};
    if (path_len < sizeof(path_buf)) memcpy(path_buf, path_start, path_len);
    crack_copy_component(&uc->lpszUrlPath, &uc->dwUrlPathLength,
                          path_buf, path_len, pwszUrl, path_offset);

    char extra_buf[2048] = {0};
    if (extra_len < sizeof(extra_buf)) memcpy(extra_buf, extra_start, extra_len);
    crack_copy_component(&uc->lpszExtraInfo, &uc->dwExtraInfoLength,
                          extra_buf, extra_len, pwszUrl, extra_offset);

    free(url_utf8);
    return TRUE;
}

WINAPI_EXPORT BOOL WinHttpCreateUrl(void *lpUrlComponents, DWORD dwFlags,
                                      LPWSTR pwszUrl, LPDWORD pdwUrlLength)
{
    (void)dwFlags;

    if (!lpUrlComponents || !pdwUrlLength)
        return FALSE;

    URL_COMPONENTS_W *uc = (URL_COMPONENTS_W *)lpUrlComponents;

    /* --- Build the URL in UTF-8 first, then convert to UTF-16 --- */

    /* Determine scheme string */
    char scheme_buf[32] = {0};
    if (uc->lpszScheme && uc->dwSchemeLength > 0) {
        /* Convert wide scheme to narrow */
        DWORD slen = uc->dwSchemeLength;
        if (slen >= sizeof(scheme_buf)) slen = sizeof(scheme_buf) - 1;
        for (DWORD i = 0; i < slen; i++)
            scheme_buf[i] = (char)(uc->lpszScheme[i] & 0x7F);
    } else if (uc->nScheme == INTERNET_SCHEME_HTTPS) {
        strcpy(scheme_buf, "https");
    } else {
        strcpy(scheme_buf, "http");
    }

    /* Determine host */
    char host_buf[512] = {0};
    if (uc->lpszHostName && uc->dwHostNameLength > 0) {
        DWORD hlen = uc->dwHostNameLength;
        if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
        for (DWORD i = 0; i < hlen; i++)
            host_buf[i] = (char)(uc->lpszHostName[i] & 0x7F);
    }

    /* Determine port */
    WORD port = uc->nPort;
    WORD default_port = (uc->nScheme == INTERNET_SCHEME_HTTPS) ? 443 : 80;

    /* User / password */
    char user_buf[256] = {0};
    char pass_buf[256] = {0};
    if (uc->lpszUserName && uc->dwUserNameLength > 0) {
        DWORD ulen = uc->dwUserNameLength;
        if (ulen >= sizeof(user_buf)) ulen = sizeof(user_buf) - 1;
        for (DWORD i = 0; i < ulen; i++)
            user_buf[i] = (char)(uc->lpszUserName[i] & 0x7F);
    }
    if (uc->lpszPassword && uc->dwPasswordLength > 0) {
        DWORD plen = uc->dwPasswordLength;
        if (plen >= sizeof(pass_buf)) plen = sizeof(pass_buf) - 1;
        for (DWORD i = 0; i < plen; i++)
            pass_buf[i] = (char)(uc->lpszPassword[i] & 0x7F);
    }

    /* Path */
    char path_buf[2048] = {0};
    if (uc->lpszUrlPath && uc->dwUrlPathLength > 0) {
        DWORD pathlen = uc->dwUrlPathLength;
        if (pathlen >= sizeof(path_buf)) pathlen = sizeof(path_buf) - 1;
        for (DWORD i = 0; i < pathlen; i++)
            path_buf[i] = (char)(uc->lpszUrlPath[i] & 0x7F);
    }

    /* Extra info (query/fragment) */
    char extra_buf[2048] = {0};
    if (uc->lpszExtraInfo && uc->dwExtraInfoLength > 0) {
        DWORD elen = uc->dwExtraInfoLength;
        if (elen >= sizeof(extra_buf)) elen = sizeof(extra_buf) - 1;
        for (DWORD i = 0; i < elen; i++)
            extra_buf[i] = (char)(uc->lpszExtraInfo[i] & 0x7F);
    }

    /* Assemble URL into a narrow buffer:
     * scheme://[user[:pass]@]host[:port][/path][extrainfo] */
    char url_narrow[4096];
    size_t pos = 0;
    size_t cap = sizeof(url_narrow);

#define URL_APPEND(fmt, ...) do {                              \
        int _n = snprintf(url_narrow + pos, cap - pos,         \
                          fmt, ##__VA_ARGS__);                  \
        if (_n > 0) {                                          \
            pos += (size_t)_n;                                 \
            if (pos >= cap) pos = cap - 1;                     \
        }                                                       \
    } while (0)

    URL_APPEND("%s://", scheme_buf);

    if (user_buf[0]) {
        if (pass_buf[0])
            URL_APPEND("%s:%s@", user_buf, pass_buf);
        else
            URL_APPEND("%s@", user_buf);
    }

    URL_APPEND("%s", host_buf);

    if (port != 0 && port != default_port)
        URL_APPEND(":%u", (unsigned)port);

    if (path_buf[0])
        URL_APPEND("%s", path_buf);

    if (extra_buf[0])
        URL_APPEND("%s", extra_buf);

#undef URL_APPEND

    url_narrow[pos] = '\0';

    /* Convert narrow URL to UTF-16 */
    size_t narrow_len = strlen(url_narrow);
    DWORD required_wchars = (DWORD)(narrow_len + 1);  /* including NUL */

    if (!pwszUrl) {
        /* Query-only: return required size */
        *pdwUrlLength = required_wchars;
        return TRUE;
    }

    if (*pdwUrlLength < required_wchars) {
        *pdwUrlLength = required_wchars;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* Simple ASCII-to-UTF16 copy (handles the vast majority of URLs) */
    for (size_t i = 0; i < narrow_len; i++)
        pwszUrl[i] = (WCHAR)(unsigned char)url_narrow[i];
    pwszUrl[narrow_len] = 0;

    *pdwUrlLength = (DWORD)narrow_len;  /* excluding NUL, per MSDN */
    return TRUE;
}

/* ================================================================== */
/*  WinINet functions (wininet.dll) - delegate to same backend         */
/* ================================================================== */

WINAPI_EXPORT HANDLE InternetOpenA(LPCSTR agent, DWORD access,
                                    LPCSTR proxy, LPCSTR bypass, DWORD flags)
{
    (void)proxy; (void)bypass;
    curl_load();

    winhttp_session_t *sess = calloc(1, sizeof(winhttp_session_t));
    if (!sess) return NULL;
    sess->type = WH_TYPE_SESSION;
    sess->access_type = access;
    sess->flags = flags;
    if (agent)
        snprintf(sess->user_agent, sizeof(sess->user_agent), "%s", agent);
    else
        snprintf(sess->user_agent, sizeof(sess->user_agent), "PELoader/1.0");

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_SESSION, -1, sess);
    fprintf(stderr, "[wininet] InternetOpenA(\"%s\") -> %p\n", sess->user_agent, h);
    return h;
}

WINAPI_EXPORT HANDLE InternetOpenW(LPCWSTR agent, DWORD access,
                                    LPCWSTR proxy, LPCWSTR bypass, DWORD flags)
{
    (void)proxy; (void)bypass;
    char agent_utf8[256];
    if (agent)
        wstr_to_utf8(agent, agent_utf8, sizeof(agent_utf8));
    else
        snprintf(agent_utf8, sizeof(agent_utf8), "PELoader/1.0");
    return InternetOpenA(agent_utf8, access, NULL, NULL, flags);
}

WINAPI_EXPORT HANDLE InternetConnectA(HANDLE session, LPCSTR server,
                                       WORD port, LPCSTR user, LPCSTR pass,
                                       DWORD service, DWORD flags,
                                       DWORD_PTR context)
{
    (void)user; (void)pass; (void)service; (void)flags; (void)context;
    handle_entry_t *se = handle_lookup(session);
    if (!se || !se->data) return NULL;

    winhttp_connection_t *conn = calloc(1, sizeof(winhttp_connection_t));
    if (!conn) return NULL;
    conn->type = WH_TYPE_CONNECTION;
    conn->session = (winhttp_session_t *)se->data;
    conn->port = port;
    conn->is_secure = (port == 443) ? 1 : 0;
    if (server) snprintf(conn->server, sizeof(conn->server), "%s", server);

    /* If credentials were provided, store them for later requests */
    /* (we would need to propagate to request, done in HttpOpenRequestA) */

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_CONNECTION, -1, conn);
    fprintf(stderr, "[wininet] InternetConnectA(\"%s\":%u) -> %p\n",
            conn->server, (unsigned)port, h);
    return h;
}

WINAPI_EXPORT HANDLE InternetConnectW(HANDLE session, LPCWSTR server,
                                       WORD port, LPCWSTR user, LPCWSTR pass,
                                       DWORD service, DWORD flags,
                                       DWORD_PTR context)
{
    (void)user; (void)pass;
    char server_utf8[512] = {0};
    if (server) wstr_to_utf8(server, server_utf8, sizeof(server_utf8));
    return InternetConnectA(session, server_utf8, port, NULL, NULL, service, flags, context);
}

WINAPI_EXPORT HANDLE HttpOpenRequestA(HANDLE conn, LPCSTR verb, LPCSTR path,
                                       LPCSTR version, LPCSTR referrer,
                                       LPCSTR *types, DWORD flags,
                                       DWORD_PTR context)
{
    (void)version; (void)referrer; (void)types; (void)context;
    handle_entry_t *ce = handle_lookup(conn);
    if (!ce || !ce->data) return NULL;
    winhttp_connection_t *c = (winhttp_connection_t *)ce->data;

    winhttp_request_t *req = calloc(1, sizeof(winhttp_request_t));
    if (!req) return NULL;
    req->type = WH_TYPE_REQUEST;
    req->conn = c;
    req->flags = flags;

    snprintf(req->verb, sizeof(req->verb), "%s", verb ? verb : "GET");
    snprintf(req->path, sizeof(req->path), "%s", path ? path : "/");

    /* Build full URL */
    req_build_url(req);

    /* Init curl handle */
    if (g_curl_lib && p_easy_init) {
        req->curl = p_easy_init();
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_REQUEST, -1, req);
    fprintf(stderr, "[wininet] HttpOpenRequestA(%s %s) -> %p\n",
            req->verb, req->url, h);
    return h;
}

WINAPI_EXPORT HANDLE HttpOpenRequestW(HANDLE conn, LPCWSTR verb, LPCWSTR path,
                                       LPCWSTR version, LPCWSTR referrer,
                                       LPCWSTR *types, DWORD flags,
                                       DWORD_PTR context)
{
    (void)version; (void)referrer; (void)types;
    char v[32] = "GET", p_str[2048] = "/";
    if (verb) wstr_to_utf8(verb, v, sizeof(v));
    if (path) wstr_to_utf8(path, p_str, sizeof(p_str));
    return HttpOpenRequestA(conn, v, p_str, NULL, NULL, NULL, flags, context);
}

WINAPI_EXPORT BOOL HttpSendRequestA(HANDLE request, LPCSTR headers,
                                     DWORD headersLen, LPVOID optional,
                                     DWORD optionalLen)
{
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    if (!req->curl) {
        set_last_error(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }

    /* Add headers */
    if (headers && headersLen != 0) {
        req_add_headers_narrow(req, headers, headersLen);
    }

    /* Optional POST data */
    if (optional && optionalLen > 0) {
        free(req->post_data);
        req->post_data = malloc(optionalLen);
        if (req->post_data) {
            memcpy(req->post_data, optional, optionalLen);
            req->post_len = optionalLen;
            req->post_capacity = optionalLen;
        } else {
            req->post_len = 0;
            req->post_capacity = 0;
        }
    }

    /* Clear any previous response */
    req_free_response(req);

    /* Perform */
    if (req_perform(req) != 0) {
        set_last_error(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }
    return TRUE;
}

WINAPI_EXPORT BOOL HttpSendRequestW(HANDLE request, LPCWSTR headers,
                                     DWORD headersLen, LPVOID optional,
                                     DWORD optionalLen)
{
    char hdr_buf[8192] = {0};
    if (headers && headersLen != 0) {
        wstr_to_utf8(headers, hdr_buf, sizeof(hdr_buf));
    }
    return HttpSendRequestA(request,
                             hdr_buf[0] ? hdr_buf : NULL,
                             (DWORD)strlen(hdr_buf),
                             optional, optionalLen);
}

WINAPI_EXPORT BOOL InternetReadFile(HANDLE file, LPVOID buffer,
                                     DWORD toRead, LPDWORD bytesRead)
{
    return WinHttpReadData(file, buffer, toRead, bytesRead);
}

WINAPI_EXPORT BOOL InternetCloseHandle(HANDLE h)
{
    return WinHttpCloseHandle(h);
}

WINAPI_EXPORT BOOL InternetQueryDataAvailable(HANDLE file, LPDWORD bytesAvailable,
                                                DWORD flags, DWORD_PTR context)
{
    (void)flags; (void)context;
    return WinHttpQueryDataAvailable(file, bytesAvailable);
}

WINAPI_EXPORT BOOL InternetGetConnectedState(LPDWORD flags, DWORD reserved)
{
    (void)reserved;
    if (flags) *flags = INTERNET_CONNECTION_LAN;
    return TRUE;
}

WINAPI_EXPORT BOOL InternetGetConnectedStateExA(LPDWORD flags, LPSTR connName,
                                                  DWORD connNameLen, DWORD reserved)
{
    (void)reserved;
    if (flags) *flags = INTERNET_CONNECTION_LAN;
    if (connName && connNameLen > 0) connName[0] = '\0';
    return TRUE;
}

WINAPI_EXPORT BOOL InternetCheckConnectionA(LPCSTR url, DWORD flags, DWORD reserved)
{
    (void)url; (void)flags; (void)reserved;
    return TRUE;  /* Always report connected */
}

WINAPI_EXPORT BOOL InternetSetOptionA(HANDLE h, DWORD option, LPVOID buffer, DWORD bufLen)
{
    (void)h; (void)option; (void)buffer; (void)bufLen;
    return TRUE;
}

WINAPI_EXPORT BOOL InternetSetOptionW(HANDLE h, DWORD option, LPVOID buffer, DWORD bufLen)
{
    (void)h; (void)option; (void)buffer; (void)bufLen;
    return TRUE;
}

WINAPI_EXPORT BOOL InternetQueryOptionA(HANDLE h, DWORD option, LPVOID buffer, LPDWORD bufLen)
{
    (void)h; (void)option; (void)buffer; (void)bufLen;
    return FALSE;
}

WINAPI_EXPORT BOOL InternetQueryOptionW(HANDLE h, DWORD option, LPVOID buffer, LPDWORD bufLen)
{
    (void)h; (void)option; (void)buffer; (void)bufLen;
    return FALSE;
}

WINAPI_EXPORT BOOL HttpQueryInfoA(HANDLE request, DWORD infoLevel,
                                    LPVOID buffer, LPDWORD bufLen, LPDWORD index)
{
    (void)index;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;

    DWORD query_id = infoLevel & 0xFFFF;
    int flag_number = (infoLevel & WINHTTP_QUERY_FLAG_NUMBER) != 0;

    /* HTTP_QUERY_STATUS_CODE = 19 */
    if (query_id == 19) {
        if (flag_number) {
            if (buffer && bufLen && *bufLen >= sizeof(DWORD)) {
                *(DWORD *)buffer = (DWORD)req->status_code;
                *bufLen = sizeof(DWORD);
                return TRUE;
            }
            if (bufLen) *bufLen = sizeof(DWORD);
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        } else {
            /* Return as ANSI string */
            char code_str[16];
            snprintf(code_str, sizeof(code_str), "%ld", req->status_code);
            DWORD needed = (DWORD)(strlen(code_str) + 1);
            if (buffer && bufLen && *bufLen >= needed) {
                memcpy(buffer, code_str, needed);
                *bufLen = needed - 1;
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }

    /* HTTP_QUERY_STATUS_TEXT = 20 */
    if (query_id == 20) {
        const char *status_text = "OK";
        if (req->resp_headers.data && req->resp_headers.size > 0) {
            const char *sp1 = strchr(req->resp_headers.data, ' ');
            if (sp1) {
                const char *sp2 = strchr(sp1 + 1, ' ');
                if (sp2) status_text = sp2 + 1;
            }
        }
        size_t st_len = 0;
        while (status_text[st_len] && status_text[st_len] != '\r' &&
               status_text[st_len] != '\n') st_len++;
        DWORD needed = (DWORD)(st_len + 1);
        if (buffer && bufLen && *bufLen >= needed) {
            memcpy(buffer, status_text, st_len);
            ((char *)buffer)[st_len] = '\0';
            *bufLen = (DWORD)st_len;
            return TRUE;
        }
        if (bufLen) *bufLen = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* HTTP_QUERY_CONTENT_LENGTH = 5 */
    if (query_id == 5) {
        if (flag_number) {
            if (buffer && bufLen && *bufLen >= sizeof(DWORD)) {
                *(DWORD *)buffer = (DWORD)req->resp_body.size;
                *bufLen = sizeof(DWORD);
                return TRUE;
            }
            if (bufLen) *bufLen = sizeof(DWORD);
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        } else {
            char len_str[32];
            snprintf(len_str, sizeof(len_str), "%zu", req->resp_body.size);
            DWORD needed = (DWORD)(strlen(len_str) + 1);
            if (buffer && bufLen && *bufLen >= needed) {
                memcpy(buffer, len_str, needed);
                *bufLen = needed - 1;
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
    }

    /* HTTP_QUERY_CONTENT_TYPE = 1 */
    if (query_id == 1) {
        const char *ct = find_header_value(&req->resp_headers, "Content-Type");
        if (!ct) return FALSE;
        size_t vlen = 0;
        while (ct[vlen] && ct[vlen] != '\r' && ct[vlen] != '\n') vlen++;

        DWORD needed = (DWORD)(vlen + 1);
        if (buffer && bufLen && *bufLen >= needed) {
            memcpy(buffer, ct, vlen);
            ((char *)buffer)[vlen] = '\0';
            *bufLen = (DWORD)vlen;
            return TRUE;
        }
        if (bufLen) *bufLen = needed;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    /* HTTP_QUERY_RAW_HEADERS_CRLF = 22 */
    if (query_id == 22) {
        if (req->resp_headers.data && req->resp_headers.size > 0) {
            DWORD needed = (DWORD)(req->resp_headers.size + 1);
            if (buffer && bufLen && *bufLen >= needed) {
                memcpy(buffer, req->resp_headers.data, req->resp_headers.size);
                ((char *)buffer)[req->resp_headers.size] = '\0';
                *bufLen = (DWORD)req->resp_headers.size;
                return TRUE;
            }
            if (bufLen) *bufLen = needed;
            set_last_error(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }

    return FALSE;
}

WINAPI_EXPORT BOOL HttpQueryInfoW(HANDLE request, DWORD infoLevel,
                                    LPVOID buffer, LPDWORD bufLen, LPDWORD index)
{
    /* For wide version, delegate to WinHttpQueryHeaders which returns wide strings */
    return WinHttpQueryHeaders(request, infoLevel, NULL, buffer, bufLen, index);
}

WINAPI_EXPORT DWORD InternetAttemptConnect(DWORD reserved)
{
    (void)reserved;
    return ERROR_SUCCESS;
}

WINAPI_EXPORT HANDLE InternetOpenUrlA(HANDLE session, LPCSTR url,
                                        LPCSTR headers, DWORD headersLen,
                                        DWORD flags, DWORD_PTR context)
{
    (void)context;

    handle_entry_t *se = handle_lookup(session);
    if (!se || !se->data) return NULL;

    /* Create a temporary connection for this URL */
    winhttp_connection_t *conn = calloc(1, sizeof(winhttp_connection_t));
    if (!conn) return NULL;
    conn->type = WH_TYPE_CONNECTION;
    conn->session = (winhttp_session_t *)se->data;
    conn->port = 0;

    /* Parse host from URL */
    if (url) {
        const char *host = strstr(url, "://");
        if (host) host += 3; else host = url;

        /* Detect scheme for is_secure */
        if (strncasecmp(url, "https", 5) == 0) {
            conn->is_secure = 1;
        }

        const char *path = strchr(host, '/');
        const char *port_colon = strchr(host, ':');
        size_t hlen;

        if (port_colon && (!path || port_colon < path)) {
            hlen = (size_t)(port_colon - host);
            conn->port = (WORD)atoi(port_colon + 1);
        } else {
            hlen = path ? (size_t)(path - host) : strlen(host);
            conn->port = conn->is_secure ? 443 : 80;
        }
        if (hlen >= sizeof(conn->server)) hlen = sizeof(conn->server) - 1;
        memcpy(conn->server, host, hlen);
        conn->server[hlen] = '\0';
    }

    winhttp_request_t *req = calloc(1, sizeof(winhttp_request_t));
    if (!req) { free(conn); return NULL; }
    req->type = WH_TYPE_REQUEST;
    req->conn = conn;
    req->owns_conn = 1;  /* This request owns the connection; free it on cleanup */
    req->flags = flags;
    snprintf(req->verb, sizeof(req->verb), "GET");
    if (url) snprintf(req->url, sizeof(req->url), "%s", url);

    /* Add request headers if provided */
    if (headers && headersLen > 0) {
        req_add_headers_narrow(req, headers, headersLen);
    }

    /* Create curl handle and perform immediately */
    if (g_curl_lib && p_easy_init) {
        req->curl = p_easy_init();
        if (req->curl) {
            if (req_perform(req) != 0) {
                fprintf(stderr, "[wininet] InternetOpenUrlA: request failed for \"%s\"\n",
                        url ? url : "(null)");
            }
        }
    }

    HANDLE h = handle_alloc(HANDLE_TYPE_WINHTTP_REQUEST, -1, req);
    fprintf(stderr, "[wininet] InternetOpenUrlA(\"%s\") -> %p (HTTP %ld)\n",
            url ? url : "(null)", h, req->status_code);
    return h;
}

WINAPI_EXPORT HANDLE InternetOpenUrlW(HANDLE session, LPCWSTR url,
                                        LPCWSTR headers, DWORD headersLen,
                                        DWORD flags, DWORD_PTR context)
{
    char url_utf8[4096] = {0};
    if (url) wstr_to_utf8(url, url_utf8, sizeof(url_utf8));

    char hdr_utf8[8192] = {0};
    if (headers && headersLen > 0) {
        wstr_to_utf8(headers, hdr_utf8, sizeof(hdr_utf8));
    }

    return InternetOpenUrlA(session,
                             url_utf8[0] ? url_utf8 : NULL,
                             hdr_utf8[0] ? hdr_utf8 : NULL,
                             (DWORD)strlen(hdr_utf8),
                             flags, context);
}

/* ================================================================== */
/*  Additional WinINet stubs for compatibility                         */
/* ================================================================== */

WINAPI_EXPORT BOOL HttpAddRequestHeadersA(HANDLE request, LPCSTR headers,
                                            DWORD headersLen, DWORD modifiers)
{
    (void)modifiers;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;
    req_add_headers_narrow(req, headers, headersLen);
    return TRUE;
}

WINAPI_EXPORT BOOL HttpAddRequestHeadersW(HANDLE request, LPCWSTR headers,
                                            DWORD headersLen, DWORD modifiers)
{
    (void)modifiers;
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;
    req_add_headers_wide(req, headers, headersLen);
    return TRUE;
}

WINAPI_EXPORT BOOL InternetWriteFile(HANDLE file, LPCVOID buffer,
                                       DWORD toWrite, LPDWORD bytesWritten)
{
    return WinHttpWriteData(file, buffer, toWrite, bytesWritten);
}

WINAPI_EXPORT BOOL InternetGetCookieA(LPCSTR url, LPCSTR name,
                                        LPSTR data, LPDWORD size)
{
    (void)url; (void)name;
    if (data && size && *size > 0) data[0] = '\0';
    if (size) *size = 0;
    return FALSE;  /* No cookies stored */
}

WINAPI_EXPORT BOOL InternetSetCookieA(LPCSTR url, LPCSTR name, LPCSTR data)
{
    (void)url; (void)name; (void)data;
    return TRUE;  /* Pretend success */
}

WINAPI_EXPORT BOOL InternetGetLastResponseInfoA(LPDWORD error, LPSTR buffer, LPDWORD bufLen)
{
    if (error) *error = 0;
    if (buffer && bufLen && *bufLen > 0) buffer[0] = '\0';
    if (bufLen) *bufLen = 0;
    return TRUE;
}

WINAPI_EXPORT DWORD InternetErrorDlg(HANDLE hWnd, HANDLE hRequest,
                                       DWORD dwError, DWORD dwFlags, void **lppvData)
{
    (void)hWnd; (void)hRequest; (void)dwError; (void)dwFlags; (void)lppvData;
    return ERROR_SUCCESS;
}

WINAPI_EXPORT BOOL InternetCanonicalizeUrlA(LPCSTR url, LPSTR buffer,
                                              LPDWORD bufLen, DWORD flags)
{
    (void)flags;
    if (!url || !buffer || !bufLen) return FALSE;
    DWORD len = (DWORD)strlen(url);
    if (*bufLen <= len) {
        *bufLen = len + 1;
        set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memcpy(buffer, url, len + 1);
    *bufLen = len;
    return TRUE;
}

WINAPI_EXPORT BOOL InternetCrackUrlA(LPCSTR url, DWORD urlLen,
                                       DWORD flags, void *components)
{
    (void)flags;
    if (!url || !components) return FALSE;

    /* WinINet URL_COMPONENTS_A has same layout but with char* instead of WCHAR*
     * For simplicity, do a basic parse here */
    /* The struct layout is identical to URL_COMPONENTS_W but with LPSTR fields.
     * We will reuse similar logic. */

    typedef struct {
        DWORD dwStructSize;
        LPSTR lpszScheme;       DWORD dwSchemeLength;
        int   nScheme;
        LPSTR lpszHostName;     DWORD dwHostNameLength;
        WORD  nPort;            WORD _pad1; DWORD _pad2;
        LPSTR lpszUserName;     DWORD dwUserNameLength; DWORD _pad3;
        LPSTR lpszPassword;     DWORD dwPasswordLength; DWORD _pad4;
        LPSTR lpszUrlPath;      DWORD dwUrlPathLength;  DWORD _pad5;
        LPSTR lpszExtraInfo;    DWORD dwExtraInfoLength;
    } URL_COMPONENTS_A;

    URL_COMPONENTS_A *uc = (URL_COMPONENTS_A *)components;

    size_t url_len = (urlLen > 0) ? urlLen : strlen(url);
    char *url_copy = malloc(url_len + 1);
    if (!url_copy) return FALSE;
    memcpy(url_copy, url, url_len);
    url_copy[url_len] = '\0';

    const char *p = url_copy;
    const char *colon = strstr(p, "://");
    if (!colon) { free(url_copy); return FALSE; }

    size_t scheme_len = (size_t)(colon - p);
    int nScheme = 0;
    WORD default_port = 80;

    if (scheme_len == 5 && strncasecmp(p, "https", 5) == 0) {
        nScheme = INTERNET_SCHEME_HTTPS;
        default_port = 443;
    } else if (scheme_len == 4 && strncasecmp(p, "http", 4) == 0) {
        nScheme = INTERNET_SCHEME_HTTP;
        default_port = 80;
    }

    uc->nScheme = nScheme;

    p = colon + 3;

    /* Skip userinfo if present */
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at && (!slash || at < slash)) {
        p = at + 1;
    }

    /* Host */
    const char *host_start = p;
    const char *host_end = p;
    while (*host_end && *host_end != ':' && *host_end != '/' &&
           *host_end != '?' && *host_end != '#') host_end++;

    size_t host_len = (size_t)(host_end - host_start);
    WORD port = default_port;

    if (*host_end == ':') {
        port = (WORD)atoi(host_end + 1);
        p = host_end + 1;
        while (*p >= '0' && *p <= '9') p++;
    } else {
        p = host_end;
    }

    uc->nPort = port;

    /* Copy host */
    if (uc->lpszHostName && uc->dwHostNameLength > 0) {
        DWORD copy = (DWORD)host_len;
        if (copy >= uc->dwHostNameLength) copy = uc->dwHostNameLength - 1;
        memcpy(uc->lpszHostName, host_start, copy);
        uc->lpszHostName[copy] = '\0';
        uc->dwHostNameLength = copy;
    }

    /* Copy scheme */
    if (uc->lpszScheme && uc->dwSchemeLength > 0) {
        DWORD copy = (DWORD)scheme_len;
        if (copy >= uc->dwSchemeLength) copy = uc->dwSchemeLength - 1;
        memcpy(uc->lpszScheme, url_copy, copy);
        uc->lpszScheme[copy] = '\0';
        uc->dwSchemeLength = copy;
    }

    /* Path */
    const char *path_start = p;
    const char *path_end = p;
    while (*path_end && *path_end != '?' && *path_end != '#') path_end++;
    size_t path_len = (size_t)(path_end - path_start);

    if (uc->lpszUrlPath && uc->dwUrlPathLength > 0) {
        DWORD copy = (DWORD)path_len;
        if (copy >= uc->dwUrlPathLength) copy = uc->dwUrlPathLength - 1;
        memcpy(uc->lpszUrlPath, path_start, copy);
        uc->lpszUrlPath[copy] = '\0';
        uc->dwUrlPathLength = copy;
    }

    /* Extra info */
    const char *extra_start = path_end;
    size_t extra_len = strlen(extra_start);
    if (uc->lpszExtraInfo && uc->dwExtraInfoLength > 0) {
        DWORD copy = (DWORD)extra_len;
        if (copy >= uc->dwExtraInfoLength) copy = uc->dwExtraInfoLength - 1;
        memcpy(uc->lpszExtraInfo, extra_start, copy);
        uc->lpszExtraInfo[copy] = '\0';
        uc->dwExtraInfoLength = copy;
    }

    free(url_copy);
    return TRUE;
}

WINAPI_EXPORT BOOL HttpEndRequestA(HANDLE request, void *buffers_out,
                                     DWORD flags, DWORD_PTR context)
{
    (void)buffers_out; (void)flags; (void)context;
    /* Used with HttpSendRequestEx for chunked sends. We perform everything
     * in SendRequest, so this is a no-op that indicates completion. */
    handle_entry_t *re = handle_lookup(request);
    if (!re || !re->data) return FALSE;
    winhttp_request_t *req = (winhttp_request_t *)re->data;
    return req->performed ? TRUE : FALSE;
}

WINAPI_EXPORT BOOL HttpEndRequestW(HANDLE request, void *buffers_out,
                                     DWORD flags, DWORD_PTR context)
{
    return HttpEndRequestA(request, buffers_out, flags, context);
}
