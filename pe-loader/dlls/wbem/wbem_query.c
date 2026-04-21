/*
 * wbem_query.c - Minimal WQL parser
 *
 * Grammar accepted (whitespace-tolerant, case-insensitive on keywords):
 *
 *     SELECT  *  |  prop_list           (prop_list is parsed but
 *                                        currently equivalent to *)
 *     FROM    <ClassIdentifier>
 *     [ WHERE <Identifier> '=' <Literal> ]
 *
 * Literals: 'single-quoted string' (no escapes), or signed/unsigned
 * decimal integer.  No expression grammar -- AND/OR/comparison-ops other
 * than '=' set q->ok = 1 but produce WBEM_OP_NONE so the row is *not*
 * filtered (the dispatcher returns the full set; calling code can either
 * accept that or layer its own filter).  This is what real Windows does
 * with `ExecQuery` flags it doesn't understand.
 *
 * The parser is hand-rolled (no flex/bison dep) and tokenises in-place
 * over a UTF-16LE buffer.  Pure-ASCII is assumed for class/identifier
 * names and string literals (which is true for every WMI consumer in
 * the wild -- WQL identifiers are ASCII per the spec).
 */

#include "wbem_internal.h"
#include <ctype.h>

static int peek_char(const uint16_t *s, size_t i)
{
    uint16_t c = s[i];
    return (c < 0x80) ? (int)c : 0;
}

static void skip_ws(const uint16_t *s, size_t *pi)
{
    while (s[*pi] && peek_char(s, *pi) <= ' ') (*pi)++;
}

/* Case-insensitive prefix match against an ASCII literal at offset *pi.
 * On match, advances *pi past the literal AND past any required trailing
 * whitespace (kw must be a SQL keyword, so we insist on a separator). */
static int match_kw(const uint16_t *s, size_t *pi, const char *kw)
{
    size_t i = *pi;
    size_t k = 0;
    while (kw[k]) {
        int c = peek_char(s, i + k);
        if (!c) return 0;
        char lc = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
        char lk = (kw[k] >= 'A' && kw[k] <= 'Z') ? (char)(kw[k] + 32) : kw[k];
        if (lc != lk) return 0;
        k++;
    }
    /* Require a non-identifier char after the keyword. */
    int after = peek_char(s, i + k);
    if (after && (isalnum(after) || after == '_')) return 0;
    *pi = i + k;
    return 1;
}

/* Consume an ASCII identifier into out (NUL-terminated), capped to cap-1. */
static int parse_ident(const uint16_t *s, size_t *pi, char *out, size_t cap)
{
    size_t i = *pi;
    int c = peek_char(s, i);
    if (!c || !(isalpha(c) || c == '_')) return 0;
    size_t k = 0;
    while (k < cap - 1) {
        c = peek_char(s, i + k);
        if (!c || !(isalnum(c) || c == '_')) break;
        out[k++] = (char)c;
    }
    out[k] = '\0';
    *pi = i + k;
    return k > 0;
}

/* Consume a 'single-quoted' string literal into out.  Returns 1 on success. */
static int parse_string_lit(const uint16_t *s, size_t *pi, char *out, size_t cap)
{
    size_t i = *pi;
    if (peek_char(s, i) != '\'') return 0;
    i++;
    size_t k = 0;
    while (k < cap - 1) {
        int c = peek_char(s, i);
        if (!c) return 0;            /* unterminated */
        if (c == '\'') { i++; break; }
        out[k++] = (char)c;
        i++;
    }
    out[k] = '\0';
    *pi = i;
    return 1;
}

/* Consume a signed decimal integer.  Returns 1 on success. */
static int parse_int_lit(const uint16_t *s, size_t *pi, int64_t *out)
{
    size_t i = *pi;
    int sign = 1;
    int c = peek_char(s, i);
    if (c == '-') { sign = -1; i++; c = peek_char(s, i); }
    else if (c == '+') { i++; c = peek_char(s, i); }
    if (!isdigit(c)) return 0;
    int64_t v = 0;
    while (isdigit(peek_char(s, i))) {
        v = v * 10 + (peek_char(s, i) - '0');
        i++;
    }
    *out = sign * v;
    *pi = i;
    return 1;
}

/* Consume "prop_list" -- comma-separated identifiers.  We accept it but
 * effectively treat it as SELECT *.  Returns 1 even on a bare '*'. */
static int parse_select_list(const uint16_t *s, size_t *pi, int *select_star)
{
    skip_ws(s, pi);
    if (peek_char(s, *pi) == '*') { (*pi)++; *select_star = 1; return 1; }
    /* Identifiers list */
    char tmp[WBEM_QUERY_MAX_KEY];
    for (;;) {
        skip_ws(s, pi);
        if (!parse_ident(s, pi, tmp, sizeof(tmp))) return 0;
        skip_ws(s, pi);
        if (peek_char(s, *pi) != ',') break;
        (*pi)++;
    }
    *select_star = 0;        /* prop list given but we still emit all props */
    return 1;
}

void wbem_parse_query(const uint16_t *wql, wbem_query_t *q)
{
    memset(q, 0, sizeof(*q));
    if (!wql) return;

    size_t i = 0;
    skip_ws(wql, &i);
    if (!match_kw(wql, &i, "SELECT")) return;

    if (!parse_select_list(wql, &i, &q->select_star)) return;

    skip_ws(wql, &i);
    if (!match_kw(wql, &i, "FROM")) return;

    skip_ws(wql, &i);
    if (!parse_ident(wql, &i, q->from_class, sizeof(q->from_class))) return;

    skip_ws(wql, &i);
    if (wql[i] == 0) {
        q->where_op = WBEM_OP_NONE;
        q->ok = 1;
        return;
    }

    if (!match_kw(wql, &i, "WHERE")) {
        /* trailing junk -- be forgiving: still mark ok and ignore. */
        q->where_op = WBEM_OP_NONE;
        q->ok = 1;
        return;
    }

    skip_ws(wql, &i);
    if (!parse_ident(wql, &i, q->where_key, sizeof(q->where_key))) return;

    skip_ws(wql, &i);
    /* Operator: only '=' supported.  Anything else -> WBEM_OP_NONE
     * (we accept the query but don't filter). */
    if (peek_char(wql, i) != '=') {
        q->where_op = WBEM_OP_NONE;
        q->ok = 1;
        return;
    }
    i++;
    skip_ws(wql, &i);

    if (peek_char(wql, i) == '\'') {
        if (!parse_string_lit(wql, &i, q->where_str, sizeof(q->where_str))) return;
        q->where_op = WBEM_OP_EQ_STR;
    } else if (isdigit(peek_char(wql, i)) ||
               peek_char(wql, i) == '-' ||
               peek_char(wql, i) == '+') {
        int64_t v = 0;
        if (!parse_int_lit(wql, &i, &v)) return;
        q->where_int = v;
        q->where_op = WBEM_OP_EQ_INT;
    } else {
        /* Unknown literal shape -- accept the query, no filter. */
        q->where_op = WBEM_OP_NONE;
    }
    q->ok = 1;
}
