/*-
 * Copyright (c) 2013-2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013-2015 Otto Gmbh & Co KG
 * All rights reserved
 * Use only with permission
 *
 * Author: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>

#include "vapi/vsl.h"
#include "vas.h"
#include "miniobj.h"
#include "base64.h"
#include "vqueue.h"

#include "varnishevent.h"
#include "format.h"
#include "hdrtrie.h"
#include "strfTIM.h"

#ifdef PAGE_SIZE
#define OBUF_SIZE PAGE_SIZE
#else
#define OBUF_SIZE 4096
#endif

typedef struct compiled_fmt_t {
    char **str;
    formatter_f **formatter;
    arg_t *args;
    int *strlen;
    unsigned n;
} compiled_fmt_t;

static struct vsb *scratch;

static char *payload, *obuf;
static char empty[] = "";
static char hit[] = "hit";
static char miss[] = "miss";
static char pass[] = "pass";
static char pipe[] = "pipe";
static char error[] = "error";
static char dash[] = "-";
static char buf[BUFSIZ];
static char hdr_char[256] = { 0 };

static size_t obuf_sz = OBUF_SIZE;

typedef struct inc_t {
    char *hdr;
    VSTAILQ_ENTRY(inc_t) inclist;
    int dup;
} inc_t;

typedef VSTAILQ_HEAD(includehead_s, inc_t) includehead_t;

static compiled_fmt_t cformat, bformat, rformat;
static includehead_t cincl[MAX_VSL_TAG], bincl[MAX_VSL_TAG], rincl[MAX_VSL_TAG];

/*
 * Header field names are HTTP 'tokens': ASCII except for control chars
 * and the listed separators.
 * RFC 7230 section 3.2, RFC 2616 sections 2.2 and 4.2
 */
static void
init_hdr_char(void)
{
    for (int i = 0; i < 256; i++) {
        if (isascii(i))
            hdr_char[i] = 1;
        if (iscntrl(i))
            hdr_char[i] = 0;
    }
    hdr_char['('] = 0;
    hdr_char[')'] = 0;
    hdr_char['<'] = 0;
    hdr_char['>'] = 0;
    hdr_char['@'] = 0;
    hdr_char[','] = 0;
    hdr_char[';'] = 0;
    hdr_char[':'] = 0;
    hdr_char['\\'] = 0;
    hdr_char['"'] = 0;
    hdr_char['/'] = 0;
    hdr_char['['] = 0;
    hdr_char[']'] = 0;
    hdr_char['?'] = 0;
    hdr_char['='] = 0;
    hdr_char['{'] = 0;
    hdr_char['}'] = 0;
    hdr_char[' '] = 0;
    hdr_char['\t'] = 0;
}

static int
isheader(const char *h)
{
    while (*h)
        if (!hdr_char[(unsigned) *h++])
            return 0;
    return 1;
}

char *
get_payload(const rec_t *rec)
{
    CHECK_OBJ_NOTNULL(rec, RECORD_MAGIC);
    assert(OCCUPIED(rec));

    if (!rec->len)
        return empty;

    chunk_t *chunk = VSTAILQ_FIRST(&rec->chunks);
    CHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
    assert(OCCUPIED(chunk));
    if (rec->len <= config.chunk_size)
        return chunk->data;

    assert(rec->len <= config.max_reclen);
    int n = rec->len;
    char *p = payload;
    while (n > 0) {
        CHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
        int cp = n;
        if (cp > config.chunk_size)
            cp = config.chunk_size;
        memcpy(p, chunk->data, cp);
        p += cp;
        n -= cp;
        chunk = VSTAILQ_NEXT(chunk, chunklist);
    }
    return payload;
}

/*
 * Return the *first* record in tx that matches the tag, or NULL if none
 * match
 */
rec_t *
get_tag(const tx_t *tx, enum VSL_tag_e tag)
{
    int idx;
    rec_t *rec;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_FORMATTING);
    idx = tag2idx[tag];
    if (idx == -1)
        return NULL;
    assert(idx < max_idx);
    rec = tx->recs[idx]->rec;
    if (rec == NULL)
        return NULL;
    CHECK_OBJ(rec, RECORD_MAGIC);
    assert(OCCUPIED(rec));
    assert(rec->tag == tag);
    return rec;
}

/*
 * Return the header payload of the *first* record in tx that matches the
 * tag and the given header.
 */
char *
get_hdr(const tx_t *tx, enum VSL_tag_e tag, int hdr_idx)
{
    rec_t *rec;
    int idx;
    char *c;

    assert(hdr_idx >= 0);
    assert(hdr_idx <= hidx[tag]);
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_FORMATTING);
    idx = tag2idx[tag];
    if (idx == -1)
        return NULL;
    assert(idx < max_idx);
    CHECK_OBJ_NOTNULL(tx->recs[idx], REC_NODE_MAGIC);
    if (tx->recs[idx]->hdrs == NULL)
        return NULL;
    rec = tx->recs[idx]->hdrs[hdr_idx];
    if (rec == NULL)
        return NULL;
    CHECK_OBJ(rec, RECORD_MAGIC);
    assert(OCCUPIED(rec));
    assert(rec->tag == tag);
    c = get_payload(rec);
    while (*c && *c != ':')
        c++;
    c++;
    while (*c && isspace(*c))
        c++;
    return c;
}

/*
 * Get the nth whitespace-separated field from str, counting from 0.
 */
char *
get_fld(char *str, int n, size_t *len)
{
    char *b, *e;
    int i = 0;

    AN(str);
    e = str;
    do {
        b = e;
        while (*b && isspace(*b))
            b++;
        e = b;
        while (*e && !isspace(*e))
            e++;
    } while (i++ < n && *b);
    *len = e - b;
    
    return b;
}

char *
get_rec_fld(const rec_t *rec, int n, size_t *len)
{
    return get_fld(get_payload(rec), n, len);
}

static inline void
format_slt(const tx_t *tx, enum VSL_tag_e tag, int hdr_idx, int fld, char **s,
           size_t *len)
{
    rec_t *rec;

    if (hdr_idx < 0) {
        rec = get_tag(tx, tag);
        if (rec != NULL) {
            if (fld == -1) {
                *s = get_payload(rec);
                *len = rec->len - 1;
            }
            else
                *s = get_rec_fld(rec, fld, len);
        }
    }
    else {
        *s = get_hdr(tx, tag, hdr_idx);
        if (*s != NULL) {
            if (fld == -1)
                *len = strlen(*s);
            else
                *s = get_fld(*s, fld, len);
        }
    }
}

static inline void
format_b(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    rec_t *rec = get_tag(tx, tag);
    if (rec != NULL)
        *s = get_rec_fld(rec, 4, len);
}

void
format_b_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_b(tx, SLT_ReqAcct, s, len);
}

void
format_b_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_b(tx, SLT_BereqAcct, s, len);
}

static inline void
format_DT(const tx_t *tx, int ts_idx, int m, char **s, size_t *len)
{
    const char *t;
    double d;

    char *f = get_hdr(tx, SLT_Timestamp, ts_idx);
    if (f == NULL)
        return;
    t = get_fld(f, 1, len);
    errno = 0;
    d = strtod(t, NULL);
    if (errno == 0) {
        VSB_clear(scratch);
        VSB_printf(scratch, "%d", (int) (d * m));
        VSB_finish(scratch);
        *s = VSB_data(scratch);
        *len = VSB_len(scratch);
    }
}

void
format_D_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_DT(tx, args->hdr_idx, 1e6, s, len);
}

void
format_D_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_DT(tx, args->hdr_idx, 1e6, s, len);
}

void
format_H_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_ReqProtocol, -1, -1, s, len);
}

void
format_H_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BereqProtocol, -1, -1, s, len);
}

static inline void
format_h(const tx_t *tx, enum VSL_tag_e tag, int fld_nr, char **s, size_t *len)
{
    rec_t *rec = get_tag(tx, tag);
    if (rec != NULL)
        *s = get_rec_fld(rec, fld_nr, len);
}

void
format_h_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_h(tx, SLT_ReqStart, 0, s, len);
}

void
format_h_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_h(tx, SLT_Backend, 2, s, len);
}

static inline void
format_IO_client(const tx_t *tx, int req_fld, int pipe_fld, char **s,
                 size_t *len)
{
    int field;

    rec_t *rec = get_tag(tx, SLT_ReqAcct);
    if (rec != NULL)
        field = req_fld;
    else {
        rec = get_tag(tx, SLT_PipeAcct);
        field = pipe_fld;
    }
    if (rec != NULL)
        *s = get_rec_fld(rec, field, len);
}

static inline void
format_IO_backend(const tx_t *tx, int field, char **s, size_t *len)
{
    rec_t *rec = get_tag(tx, SLT_BereqAcct);
    if (rec != NULL)
        *s = get_rec_fld(rec, field, len);
}

void
format_I_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_IO_client(tx, 2, 2, s, len);
}

void
format_I_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_IO_backend(tx, 2, s, len);
}

void
format_m_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_ReqMethod, -1, -1, s, len);
}

void
format_m_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BereqMethod, -1, -1, s, len);
}

void
format_O_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_IO_client(tx, 5, 3, s, len);
}

void
format_O_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_IO_backend(tx, 5, s, len);
}

static inline void
format_q(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;
    rec_t *rec = get_tag(tx, tag);
    if (rec == NULL)
        return;
    char *p = get_payload(rec);
    if (p == NULL)
        return;
    qs = memchr(p, '?', rec->len);
    if (qs != NULL) {
        *s = qs + 1;
        *len = rec->len - 1 - (*s - p);
    }
}

void
format_q_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_q(tx, SLT_ReqURL, s, len);
}

void
format_q_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_q(tx, SLT_BereqURL, s, len);
}

static inline void
format_r(const tx_t *tx, int host_idx, enum VSL_tag_e mtag, enum VSL_tag_e htag,
         enum VSL_tag_e utag, enum VSL_tag_e ptag, char **s, size_t *len) 
{
    char *str;

    VSB_clear(scratch);
    rec_t *rec = get_tag(tx, mtag);
    if (rec != NULL)
        VSB_cat(scratch, get_payload(rec));
    else
        VSB_cat(scratch, "-");
    VSB_cat(scratch, " ");

    if ((str = get_hdr(tx, htag, host_idx)) != NULL) {
        if (strncmp(str, "http://", 7) != 0)
            VSB_cat(scratch, "http://");
        VSB_cat(scratch, str);
    }
    else
        VSB_cat(scratch, "http://localhost");

    rec = get_tag(tx, utag);
    if (rec != NULL && rec->len > 0)
        VSB_cat(scratch, get_payload(rec));
    else
        VSB_cat(scratch, "-");

    VSB_cat(scratch, " ");
    rec = get_tag(tx, ptag);
    if (rec != NULL && rec->len > 0)
        VSB_cat(scratch, get_payload(rec));
    else
        VSB_cat(scratch, "HTTP/1.0");

    VSB_finish(scratch);
    *s = VSB_data(scratch);
    *len = VSB_len(scratch);
}

void
format_r_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_r(tx, args->hdr_idx, SLT_ReqMethod, SLT_ReqHeader, SLT_ReqURL,
             SLT_ReqProtocol, s, len);
}

void
format_r_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_r(tx, args->hdr_idx, SLT_BereqMethod, SLT_BereqHeader, SLT_BereqURL,
             SLT_BereqProtocol, s, len);
}

void
format_s_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_RespStatus, -1, -1, s, len);
}

void
format_s_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BerespStatus, -1, -1, s, len);
}

static inline const char *
fmt_parse_unsigned(const char *t, unsigned *num)
{
    unsigned new;
    *num = 0;
    while (isdigit(*t)) {
        new = *num * 10 + (*t++ - '0');
        if (new < *num)
            return NULL;
        *num = new;
    }
    return t;
}

static inline int
fmt_parse_tim(const char *ts, unsigned *secs, unsigned *usecs)
{
    const char *t = fmt_parse_unsigned(ts, secs);
    if (t == NULL || *t != '.')
        return 0;
    t++;
    if (fmt_parse_unsigned(t, usecs) == NULL)
        return 0;
    return 1;
}

static inline void
format_tim(const tx_t *tx, int start_idx, const char *fmt, char **s,
           size_t *len)
{
    unsigned secs, usecs;
    char *data;
    const char *ts;
    time_t t;
    struct tm tm;

    if (tx->type != VSL_t_raw) {
        data = get_hdr(tx, SLT_Timestamp, start_idx);
        if (data == NULL)
            return;
        ts = get_fld(data, 0, len);
        if (ts == NULL)
            return;
        if (!fmt_parse_tim(ts, &secs, &usecs))
            return;
        assert(usecs < 1000000);
        t = (time_t) secs;
    }
    else {
        t = (time_t) tx->t;
        usecs = (tx->t - (double)t) * 1e6;
    }
    AN(localtime_r(&t, &tm));
    size_t n = strfTIM(buf, BUFSIZ, fmt, &tm, usecs);
    if (n != 0) {
        *s = buf;
        *len = strlen(buf);
    }
}

void
format_t(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_tim(tx, args->hdr_idx, "[%d/%b/%Y:%T %z]", s, len);
}

void
format_T_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_DT(tx, args->hdr_idx, 1, s, len);
}

void
format_T_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_DT(tx, args->hdr_idx, 1, s, len);
}

static inline void
format_U(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;

    rec_t *rec = get_tag(tx, tag);
    if (rec == NULL)
        return;
    *s = get_payload(rec);
    if (s == NULL)
        return;
    qs = memchr(*s, '?', rec->len);
    if (qs == NULL)
        *len = rec->len - 1;
    else
        *len = qs - *s;
}

void
format_U_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_U(tx, SLT_ReqURL, s, len);
}

void
format_U_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_U(tx, SLT_BereqURL, s, len);
}

static inline void
format_u(const tx_t *tx, int auth_idx, enum VSL_tag_e tag, char **s,
         size_t *len)
{
    char *hdr;

    if ((hdr = get_hdr(tx, tag, auth_idx)) != NULL
        && strncasecmp(get_fld(hdr, 0, len), "Basic", 5) == 0) {
        const char *c, *auth = get_fld(hdr, 1, len);
        VB64_init();
        VB64_decode(buf, BUFSIZ, auth, auth + *len);
        c = strchr(buf, ':');
        *s = buf;
        if (c != NULL)
            *len = c - buf;
        else
            *len = strlen(buf);
    }
    else {
        *s = dash;
        *len = 1;
    }
}

void
format_u_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_u(tx, args->hdr_idx, SLT_ReqHeader, s, len);
}

void
format_u_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_u(tx, args->hdr_idx, SLT_BereqHeader, s, len);
}

static inline void
format_Xio(const tx_t *tx, int hdr_idx, enum VSL_tag_e tag, char **s,
           size_t *len)
{
    *s = get_hdr(tx, tag, hdr_idx);
    if (*s)
        *len = strlen(*s);
}

void
format_Xi_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->hdr_idx, SLT_ReqHeader, s, len);
}

void
format_Xi_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->hdr_idx, SLT_BereqHeader, s, len);
}

void
format_Xo_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->hdr_idx, SLT_RespHeader, s, len);
}

void
format_Xo_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->hdr_idx, SLT_BerespHeader, s, len);
}

void
format_Xt(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_tim(tx, args->hdr_idx, (const char *) args->name, s, len);
}

static inline void
format_Xttfb(const tx_t *tx, int ts_idx, char **s, size_t *len)
{
    char *ts;

    ts = get_hdr(tx, SLT_Timestamp, ts_idx);
    if (ts == NULL)
        return;
    *s = get_fld(ts, 1, len);
}

void
format_Xttfb_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xttfb(tx, args->hdr_idx, s, len);
}

void
format_Xttfb_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xttfb(tx, args->hdr_idx, s, len);
}

void
format_VCL_disp(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    *s = dash;
    switch(tx->disp) {
    case DISP_NONE:
        break;
    case DISP_HIT:
        *s = hit;
        break;
    case DISP_MISS:
        *s = miss;
        break;
    case DISP_PASS:
        if (*args->name == 'm')
            *s = miss;
        else
            *s = pass;
        break;
    case DISP_PIPE:
        if (*args->name == 'm')
            *s = miss;
        else
            *s = pipe;
        break;
    case DISP_ERROR:
        if (*args->name == 'm')
            *s = miss;
        else
            *s = error;
        break;
    default:
        WRONG("Illegal tx disposition value");
    }
    *len = strlen(*s);
}

void
format_VCL_Log(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    char *l = get_hdr(tx, SLT_VCL_Log, args->hdr_idx);
    if (l == NULL)
        return;
    *s = l;
    *len = strlen(l);
}

/*
 * XXX: apparently none of VSL, varnishlog or varnishncsa use VSB_quote
 * for SLT_F_BINARY any more.
 */
void
format_SLT(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_slt(tx, args->tag, args->hdr_idx, args->fld, s, len);
    if (VSL_tagflags[args->tag] & SLT_F_BINARY && *s != NULL && *len > 0)
        for (int i = 0; i < *len; i++)
            if (!isprint(*(*s + i))) {
                VSB_clear(scratch);
                VSB_putc(scratch, '\"');
                VSB_quote(scratch, *s, (int) *len, 0);
                VSB_putc(scratch, '\"');
                VSB_finish(scratch);
                *s = VSB_data(scratch);
                *len = VSB_len(scratch);
                break;
            }
}

static inline void
format_xid(int32_t xid, char **s, size_t *len)
{
    VSB_clear(scratch);
    VSB_printf(scratch, "%d", xid);
    VSB_finish(scratch);
    *s = VSB_data(scratch);
    *len = VSB_len(scratch);
}

void
format_vxid(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_xid(tx->vxid, s, len);
}

void
format_pvxid(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_xid(tx->pvxid, s, len);
}

static void
add_fmt(const compiled_fmt_t *fmt, struct vsb *os, unsigned n,
        formatter_f formatter, const char *name, enum VSL_tag_e tag, int fld)
{
    if (VSB_len(os) > 0) {
        fmt->str[n] = (char *) malloc(VSB_len(os) + 1);
        AN(fmt->str[n]);
        VSB_finish(os);
        strcpy(fmt->str[n], VSB_data(os));
        fmt->strlen[n] = VSB_len(os);
    }
    else {
        fmt->str[n] = NULL;
        fmt->strlen[n] = 0;
    }
    VSB_clear(os);
    if (name == NULL)
        fmt->args[n].name = NULL;
    else {
        fmt->args[n].name = strdup(name);
        AN(fmt->args[n].name);
    }
    fmt->formatter[n] = formatter;
    fmt->args[n].tag = tag;
    fmt->args[n].fld = fld;
}

static void
add_formatter(const compiled_fmt_t *fmt, struct vsb *os, unsigned n,
              formatter_f formatter)
{
    add_fmt(fmt, os, n, formatter, NULL, SLT__Bogus, -1);
}

static void
add_fmt_name(const compiled_fmt_t *fmt, struct vsb *os, unsigned n,
             formatter_f formatter, const char *name)
{
    add_fmt(fmt, os, n, formatter, name, SLT__Bogus, -1);
}

static inline char *
strdup_add_colon(const char *s)
{
    int len;
    char *dst;

    AN(s);
    len = strlen(s);
    dst = (char *) malloc(len + 2);
    AN(dst);
    strcpy(dst, s);
    dst[len] = ':';
    dst[len + 1] = '\0';
    return dst;
}

static void
add_hdr(const compiled_fmt_t *fmt,  enum VSL_tag_e tag, const char *hdr,
        unsigned n)
{
    assert(isheader(hdr));
    char *hdr_colon = strdup_add_colon(hdr);
    if (HDR_FindIdx(hdr_trie[tag], hdr_colon) == -1) {
        hidx[tag]++;
        hdr_trie[tag] = HDR_InsertIdx(hdr_trie[tag], hdr, hidx[tag]);
    }
    fmt->args[n].hdr_idx = HDR_FindIdx(hdr_trie[tag], hdr_colon);
    free(hdr_colon);
}

static void
add_fmt_hdr(const compiled_fmt_t *fmt, struct vsb *os, unsigned n,
            formatter_f formatter, enum VSL_tag_e tag, const char *hdr)
{
    add_fmt(fmt, os, n, formatter, NULL, tag, -1);
    add_hdr(fmt, tag, hdr, n);
}

#define FMT(type, format_ltr)                           \
    (C(type) ? format_ltr##_client : format_ltr##_backend)

#define NAME(type, cname, bname) (C(type) ? (cname) : (bname))

#define TAG(type, ctag, btag) (C(type) ? (ctag) : (btag))

static void
add_tag(enum VSL_transaction_e type, enum VSL_tag_e tag, const char *hdr)
{
    includehead_t *inclhead;
    inc_t *incl;

    switch(type) {
    case VSL_t_req:
        inclhead = &cincl[tag];
        break;
    case VSL_t_bereq:
        inclhead = &bincl[tag];
        break;
    case VSL_t_raw:
        inclhead = &rincl[tag];
        break;
    default:
        WRONG("Illegal transaction type");
    }

    /* Don't add the same include more than once */
    VSTAILQ_FOREACH(incl, inclhead, inclist)
        if ((hdr == NULL && incl->hdr == NULL)
            || (hdr != NULL && incl->hdr != NULL
                && (strcmp(incl->hdr, hdr) == 0)))
            return;

    incl = calloc(1, sizeof(inc_t));
    AN(incl);
    if (hdr != NULL)
        incl->hdr = strdup(hdr);
    VSTAILQ_INSERT_TAIL(inclhead, incl, inclist);
}

static void
add_cb_tag(enum VSL_transaction_e type, enum VSL_tag_e ctag,
           enum VSL_tag_e btag, const char *hdr)
{
    enum VSL_tag_e tag;

    switch(type) {
    case VSL_t_req:
        tag = ctag;
        break;
    case VSL_t_bereq:
        tag = btag;
        break;
    default:
        WRONG("Illegal transaction type");
    }

    add_tag(type, tag, hdr);
}

static void
add_cb_tag_incl(enum VSL_transaction_e type, enum VSL_tag_e tag,
                const char *chdr, const char *bhdr)
{
    const char *hdr;

    switch(type) {
    case VSL_t_req:
        hdr = chdr;
        break;
    case VSL_t_bereq:
        hdr = bhdr;
        break;
    default:
        WRONG("Illegal transaction type");
    }

    add_tag(type, tag, hdr);
}

static int
compile_fmt(char * const format, compiled_fmt_t * const fmt,
            enum VSL_transaction_e type, char *err)
{
    const char *p;
    unsigned n = 1;
    struct vsb *os;

    assert(type == VSL_t_req || type == VSL_t_bereq || type == VSL_t_raw);

    for (p = format; *p != '\0'; p++)
        if (*p == '%')
            n++;

    fmt->n = n;
    fmt->str = (char **) calloc(n, sizeof(char *));
    if (fmt->str == NULL) {
        strcpy(err, strerror(errno));
        return 0;
    }
    fmt->formatter = (formatter_f **) calloc(n, sizeof(formatter_f *));
    if (fmt->formatter == NULL) {
        strcpy(err, strerror(errno));
        return 0;
    }
    fmt->args = (arg_t *) calloc(n, sizeof(arg_t));
    if (fmt->args == NULL) {
        strcpy(err, strerror(errno));
        return 0;
    }
    fmt->strlen = (int *) calloc(n, sizeof(int));
    if (fmt->strlen == NULL) {
        strcpy(err, strerror(errno));
        return 0;
    }
    for (int i = 0; i < n; i++)
        fmt->args[i].hdr_idx = -1;

    nonrecs_wanted[type] = 0;
    tag_no_hdr[type] = vbit_new(MAX_VSL_TAG);

    n = 0;
    os = VSB_new_auto();
    
    for (p = format; *p != '\0'; p++) {

        /* allow the most essential escape sequences in format. */
        if (*p == '\\') {
            p++;
            if (*p == 't') VSB_putc(os, '\t');
            if (*p == 'n') VSB_putc(os, '\n');
            continue;
        }

        if (*p != '%') {
            VSB_putc(os, *p);
            continue;
        }
        
        p++;

        /* Only the SLT, vxid or time formatters permitted for the "raw"
           format (neither client nor backend) */
        if (R(type)
            && sscanf(p, "{tag:%s}x", buf) != 1
            && sscanf(p, "{VSL:%s}x", buf) != 1
            && sscanf(p, "{vxid}x") != 1
            && *p != 't'
            && sscanf(p, "{%s}t", buf) != 1) {
            sprintf(err, "Unknown format starting at: %s", --p);
            return 1;
        }
        
        switch (*p) {

        case 'b':
            add_formatter(fmt, os, n, FMT(type, format_b));
            add_cb_tag(type, SLT_ReqAcct, SLT_BereqAcct, NULL);
            n++;
            break;

        case 'd':
            VSB_putc(os, C(type) ? 'c' : 'b');
            nonrecs_wanted[type] = 1;
            break;
            
        case 'D':
            add_fmt_hdr(fmt, os, n, FMT(type, format_D), SLT_Timestamp,
                        NAME(type, "Resp", "BerespBody"));
            add_cb_tag_incl(type, SLT_Timestamp, "Resp", "BerespBody");
            n++;
            break;
            
        case 'H':
            add_formatter(fmt, os, n, FMT(type, format_H));
            add_cb_tag(type, SLT_ReqProtocol, SLT_BereqProtocol, NULL);
            n++;
            break;
            
        case 'h':
            add_formatter(fmt, os, n, FMT(type, format_h));
            add_cb_tag(type, SLT_ReqStart, SLT_Backend, NULL);
            n++;
            break;
            
        case 'I':
            add_formatter(fmt, os, n, FMT(type, format_I));
            if (C(type)) {
                add_tag(type, SLT_ReqAcct, NULL);
                add_tag(type, SLT_PipeAcct, NULL);
            }
            else
                add_tag(type, SLT_BereqAcct, NULL);
            n++;
            break;
            
        case 'l':
            VSB_putc(os, '-');
            break;

        case 'm':
            add_formatter(fmt, os, n, FMT(type, format_m));
            add_cb_tag(type, SLT_ReqMethod, SLT_BereqMethod, NULL);
            n++;
            break;

        case 'O':
            add_formatter(fmt, os, n, FMT(type, format_O));
            if (C(type)) {
                add_tag(type, SLT_ReqAcct, NULL);
                add_tag(type, SLT_PipeAcct, NULL);
            }
            else
                add_tag(type, SLT_BereqAcct, NULL);
            n++;
            break;
            
        case 'q':
            add_formatter(fmt, os, n, FMT(type, format_q));
            add_cb_tag(type, SLT_ReqURL, SLT_BereqURL, NULL);
            n++;
            break;

        case 'r':
            add_fmt_hdr(fmt, os, n, FMT(type, format_r),
                        TAG(type, SLT_ReqHeader, SLT_BereqHeader), "Host");
            add_cb_tag(type, SLT_ReqMethod, SLT_BereqMethod, NULL);
            add_cb_tag(type, SLT_ReqHeader, SLT_BereqHeader, "Host");
            add_cb_tag(type, SLT_ReqURL, SLT_BereqURL, NULL);
            add_cb_tag(type, SLT_ReqProtocol, SLT_BereqProtocol, NULL);
            n++;
            break;

        case 's':
            add_formatter(fmt, os, n, FMT(type, format_s));
            add_cb_tag(type, SLT_RespStatus, SLT_BerespStatus, NULL);
            n++;
            break;

        case 't':
            if (type != VSL_t_raw) {
                add_fmt_hdr(fmt, os, n, format_t, SLT_Timestamp, "Start");
                add_tag(type, SLT_Timestamp, "Start");
            }
            else
                add_formatter(fmt, os, n, format_t);
            n++;
            break;

        case 'T':
            add_fmt_hdr(fmt, os, n, FMT(type, format_T), SLT_Timestamp,
                        "Start");
            add_tag(type, SLT_Timestamp, "Start");
            n++;
            break;
            
        case 'U':
            add_formatter(fmt, os, n, FMT(type, format_U));
            add_cb_tag(type, SLT_ReqURL, SLT_BereqURL, NULL);
            n++;
            break;

        case 'u':
            add_fmt_hdr(fmt, os, n, FMT(type, format_u),
                        TAG(type, SLT_ReqHeader, SLT_BereqHeader),
                        "Authorization");
            add_cb_tag(type, SLT_ReqHeader, SLT_BereqHeader, "Authorization");
            n++;
            break;

        case '{': {
            const char *tmp;
            char *fname = NULL, ltr;
            tmp = p;
            ltr = '\0';
            while (*tmp != '\0' && *tmp != '}')
                tmp++;
            if (*tmp == '}') {
                tmp++;
                ltr = *tmp;
                fname = strndup(p+1, tmp-p-2);
                AN(fname);
            }

            switch (ltr) {
            case 'i':
                if (!isheader(fname)) {
                    sprintf(err, "illegal header name: '%s'", fname);
                    return 1;
                }
                add_fmt_hdr(fmt, os, n, FMT(type, format_Xi),
                            TAG(type, SLT_ReqHeader, SLT_BereqHeader), fname);
                add_cb_tag(type, SLT_ReqHeader, SLT_BereqHeader, fname);
                n++;
                p = tmp;
                break;
            case 'o':
                if (!isheader(fname)) {
                    sprintf(err, "illegal header name: '%s'", fname);
                    return 1;
                }
                add_fmt_hdr(fmt, os, n, FMT(type, format_Xo),
                            TAG(type, SLT_RespHeader, SLT_BerespHeader),
                            fname);
                add_cb_tag(type, SLT_RespHeader, SLT_BerespHeader, fname);
                n++;
                p = tmp;
                break;
            case 't':
                add_fmt_name(fmt, os, n, format_Xt, fname);
                if (type != VSL_t_raw) {
                    add_hdr(fmt, SLT_Timestamp, "Start", n);
                    fmt->args[n].tag = SLT_Timestamp;
                    add_tag(type, SLT_Timestamp, "Start");
                }
                n++;
                p = tmp;
                break;
            case 'x':
                if (strcmp(fname, "Varnish:time_firstbyte") == 0) {
                    add_fmt_hdr(fmt, os, n, FMT(type, format_Xttfb),
                                SLT_Timestamp, NAME(type, "Process", "Beresp"));
                    add_cb_tag_incl(type, SLT_Timestamp, "Process", "Beresp");
                }
                else if (strcmp(fname, "Varnish:hitmiss") == 0) {
                    if (C(type)) {
                        add_fmt_name(fmt, os, n, format_VCL_disp, "m");
                        add_tag(type, SLT_VCL_call, NULL);
                        add_tag(type, SLT_VCL_return, NULL);
                    }
                    else {
                        sprintf(err,
                           "Varnish:hitmiss only permitted for client formats");
                        return 1;
                    }
                }
                else if (strcmp(fname, "Varnish:handling") == 0) {
                    if (C(type)) {
                        add_fmt_name(fmt, os, n, format_VCL_disp, "n");
                        add_tag(type, SLT_VCL_call, NULL);
                        add_tag(type, SLT_VCL_return, NULL);
                    }
                    else {
                        sprintf(err,
                          "Varnish:handling only permitted for client formats");
                        return 1;
                    }
                }
                else if (strncmp(fname, "VCL_Log:", 8) == 0) {
                    // support pulling entries logged with std.log() into
                    // output.
                    // Format: %{VCL_Log:keyname}x
                    // Logging: std.log("keyname:value")
                    if (!isheader(fname + 8)) {
                        sprintf(err, "illegal header name: '%s'", fname + 8);
                        return 1;
                    }
                    add_fmt_hdr(fmt, os, n, format_VCL_Log, SLT_VCL_Log,
                                fname+8);
                    add_tag(type, SLT_VCL_Log, fname+8);
                }
                else if (strncmp(fname, "tag:", 4) == 0
                         || strncmp(fname, "VSL:", 4) == 0) {
                    /* retrieve the tag contents from the log */
                    char *c, *tagname = fname+4, *hdr = NULL, *fld = NULL;
                    int t = 0, fld_nr = -1;

                    c = tagname + 1;
                    while (*c != ':' && *c != '[' && *c != '\0')
                        c++;
                    if ((t = VSL_Name2Tag(tagname, c - tagname)) < 0) {
                        sprintf(err, "Unknown or non-unique tag %*s",
                                (int) (c - tagname), tagname);
                        return 1;
                    }
                    if (*c == ':') {
                        hdr = c + 1;
                        while (*c != '[' && *c != '\0')
                            c++;
                    }
                    if (*c == '[') {
                        *c = '\0';
                        c++;
                        fld = c;
                        while (isdigit(*c))
                            c++;
                        if (*c != ']') {
                            sprintf(err, "Unterminated field specifier "
                                    "starting at %s", --p);
                            return 1;
                        }
                        *c = '\0';
                        fld_nr = atoi(fld);
                    }
                    add_fmt(fmt, os, n, format_SLT, NULL, t, fld_nr);
                    if (hdr != NULL) {
                        if (!isheader(hdr)) {
                            sprintf(err, "illegal header name: '%s'", hdr);
                            return 1;
                        }
                        add_hdr(fmt, t, hdr, n);
                    }
                    else
                        vbit_set(tag_no_hdr[type], t);
                    add_tag(type, t, hdr);
                }
                else if (strncmp(fname, "vxid", 4) == 0
                         || strncmp(fname, "Varnish:vxid", 12) == 0) {
                    add_formatter(fmt, os, n, format_vxid);
                    nonrecs_wanted[type] = 1;
                }
                else if (strncmp(fname, "pvxid", 5) == 0) {
                    add_formatter(fmt, os, n, format_pvxid);
                    nonrecs_wanted[type] = 1;
                }
                else if (strncmp(fname, "Varnish:side", 12) == 0) {
                    /* same as %d */
                    VSB_putc(os, C(type) ? 'c' : 'b');
                    nonrecs_wanted[type] = 1;
                }
                else {
                    sprintf(err, "Unknown format starting at: %s", fname);
                    return 1;
                }
                n++;
                p = tmp;
                free(fname);
                break;
                
            default:
                sprintf(err, "Unknown format starting at: %s", --p);
                return 1;
            }
        }
            break;

            /* Fall through if we haven't handled something */
            /* FALLTHROUGH*/
        default:
            sprintf(err, "Unknown format starting at: %s", --p);
            return 1;
        }
    }

    /* Add any remaining string after the last formatter,
     * and the terminating newline
     */
    VSB_putc(os, '\n');
    add_formatter(fmt, os, n, NULL);
    VSB_destroy(&os);
    return 0;
}

static void
fmt_compute_indices(const includehead_t *inclhead, int *idx)
{
    for (int i = 0; i < MAX_VSL_TAG; i++) {
        if (VSTAILQ_EMPTY(&inclhead[i]))
            continue;
        if (tag2idx[i] < 0)
            tag2idx[i] = (*idx)++;
    }
    if (*idx > max_idx)
        max_idx = *idx;
}

int
FMT_Init(char *err)
{
    int idx = 0;

    obuf = calloc(OBUF_SIZE, sizeof(char));
    if (obuf == NULL)
        return ENOMEM;
    payload = malloc(config.max_reclen);
    if (payload == NULL)
        return ENOMEM;
    scratch = VSB_new_auto();
    AN(scratch);

    memset(tag2idx, -1, sizeof(tag2idx));
    max_idx = 0;

    init_hdr_char();
    for (int i = 0; i < MAX_VSL_TAG; i++) {
        hdr_trie[i] = NULL;
        hidx[i] = -1;
    }

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        VSTAILQ_INIT(&cincl[i]);
        VSTAILQ_INIT(&bincl[i]);
        VSTAILQ_INIT(&rincl[i]);
    }
    for (int i = 0; i < VSL_t__MAX; i++)
        tag_no_hdr[i] = NULL;

    if (!VSB_EMPTY(config.cformat)) {
        if (compile_fmt(VSB_data(config.cformat), &cformat, VSL_t_req, err)
            != 0)
            return EINVAL;
        fmt_compute_indices(cincl, &idx);
    }

    if (!VSB_EMPTY(config.bformat)) {
        if (compile_fmt(VSB_data(config.bformat), &bformat, VSL_t_bereq, err)
            != 0)
            return EINVAL;
        fmt_compute_indices(bincl, &idx);
    }

    if (!VSB_EMPTY(config.rformat)) {
        if (compile_fmt(VSB_data(config.rformat), &rformat, VSL_t_raw, err)
            != 0)
            return EINVAL;
        fmt_compute_indices(rincl, &idx);
    }

    return 0;
}

int
FMT_GetMaxIdx(void)
{
    return max_idx;
}

int
FMT_Estimate_RecsPerTx(void)
{
    int recs_per_tx = 0, recs_per_ctx = 0, recs_per_btx = 0;
    inc_t *incl;

    if (max_idx == 0)
        return 0;

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        if (!VSTAILQ_EMPTY(&rincl[i])) {
            recs_per_tx = 1;
            break;
        }
    }

    for (int i = 0; i < MAX_VSL_TAG; i++)
        if (i != SLT_VCL_call && i != SLT_VCL_return)
            VSTAILQ_FOREACH(incl, &cincl[i], inclist)
                recs_per_ctx++;
    if (recs_per_ctx > recs_per_tx)
        recs_per_tx = recs_per_ctx;

    for (int i = 0; i < MAX_VSL_TAG; i++)
        VSTAILQ_FOREACH(incl, &bincl[i], inclist)
            recs_per_btx++;
    if (recs_per_btx > recs_per_tx)
        recs_per_tx = recs_per_btx;

    return recs_per_tx;
}

static inline void
fmt_resize(size_t length)
{
    /* Add 1 since we'll be appending a NUL byte */
    if (length + 1 > obuf_sz) {
        do { obuf_sz <<= 1; } while (length + 1 > obuf_sz);
        obuf = realloc(obuf, obuf_sz);
        AN(obuf);
    }
}

char *
FMT_Format(tx_t *tx, size_t *length)
{
    compiled_fmt_t fmt;
    size_t curlen = 0;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_SUBMITTED);

    switch(tx->type) {
    case VSL_t_req:
        fmt = cformat;
        break;
    case VSL_t_bereq:
        fmt = bformat;
        break;
    case VSL_t_raw:
        fmt = rformat;
        break;
    default:
        WRONG("Illegal transaction type");
    }

    tx->state = TX_FORMATTING;

    *obuf = '\0';
    for (int i = 0; i < fmt.n; i++) {
        char *s = NULL;
        size_t len = 0;

        if (fmt.str[i] != NULL) {
            fmt_resize(curlen + fmt.strlen[i]);
            memcpy(obuf + curlen, fmt.str[i], fmt.strlen[i]);
            curlen += fmt.strlen[i];
        }
        if (fmt.formatter[i] != NULL) {
            (fmt.formatter[i])(tx, &fmt.args[i], &s, &len);
            if (s != NULL && len != 0) {
                fmt_resize(curlen + len);
                memcpy(obuf + curlen, s, len);
                curlen += len;
            }
        }
    }
    obuf[curlen] = '\0';
    *length = curlen;

    assert(tx->state == TX_FORMATTING);
    tx->state = TX_WRITTEN;

    return obuf;
}

static void
free_format(compiled_fmt_t *fmt)
{
    for (int i = 0; i < fmt->n; i++) {
        free(fmt->str[i]);
        if (fmt->args[i].name != NULL)
            free(fmt->args[i].name);
    }
    free(fmt->str);
    free(fmt->strlen);
    free(fmt->formatter);
    free(fmt->args);
}

static void
free_incl(includehead_t inclhead[])
{
    inc_t *incl;

    for (int i = 0; i < MAX_VSL_TAG; i++)
        VSTAILQ_FOREACH(incl, &inclhead[i], inclist) {
            if (incl->hdr != NULL)
                free(incl->hdr);
            free(incl);
        }
}

void
FMT_Fini(void)
{
    free(obuf);
    VSB_destroy(&scratch);
    free(payload);

    free_incl(cincl);
    free_incl(bincl);
    free_incl(rincl);

    for (int i = 0; i < MAX_VSL_TAG; i++)
        if (hdr_trie[i] != NULL) {
            HDR_Fini(hdr_trie[i]);
            hdr_trie[i] = NULL;
        }

    for (int i = 0; i < VSL_t__MAX; i++)
        if (tag_no_hdr[i] != NULL)
            vbit_destroy(tag_no_hdr[i]);

    if (!VSB_EMPTY(config.cformat))
        free_format(&cformat);
    if (!VSB_EMPTY(config.bformat))
        free_format(&bformat);
    if (!VSB_EMPTY(config.rformat))
        free_format(&rformat);
}
