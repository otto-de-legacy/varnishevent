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

#include "vapi/vsl.h"
#include "vas.h"
#include "miniobj.h"
#include "base64.h"
#include "vqueue.h"

#include "varnishevent.h"
#include "format.h"
#include "strfTIM.h"

typedef struct compiled_fmt_t {
    char **str;
    formatter_f **formatter;
    arg_t *args;
    unsigned n;
} compiled_fmt_t;

static struct vsb *payload;
static struct vsb *bintag;
static char *scratch = NULL;

static char empty[] = "";
static char hit[] = "hit";
static char miss[] = "miss";
static char pass[] = "pass";
static char pipe[] = "pipe";
static char error[] = "error";
static char dash[] = "-";

typedef struct include_t {
    char *hdr;
    VSTAILQ_ENTRY(include_t) inclist;
} include_t;

typedef VSTAILQ_HEAD(includehead_s, include_t) includehead_t;

static compiled_fmt_t cformat, bformat, rformat;
static includehead_t cincl[MAX_VSL_TAG], bincl[MAX_VSL_TAG], rincl[MAX_VSL_TAG];
static unsigned includes;
static char **incl_arg = NULL;

char *
get_payload(const logline_t *rec)
{
    CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
    assert(OCCUPIED(rec));

    if (!rec->len)
        return empty;

    chunk_t *chunk = VSTAILQ_FIRST(&rec->chunks);
    CHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
    assert(OCCUPIED(chunk));
    if (rec->len <= config.chunk_size)
        return chunk->data;

    VSB_clear(payload);
    int n = rec->len;
    while (n > 0) {
        CHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
        int cp = n;
        if (cp > config.chunk_size)
            cp = config.chunk_size;
        VSB_bcat(payload, chunk->data, cp);
        n -= cp;
        chunk = VSTAILQ_NEXT(chunk, chunklist);
    }
    assert(VSB_len(payload) == rec->len);
    VSB_finish(payload);
    return VSB_data(payload);
}

/*
 * Return the *last* record in tx that matches the tag
 */
logline_t *
get_tag(const tx_t *tx, enum VSL_tag_e tag)
{
    logline_t *rec, *tagrec = NULL;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
        assert(OCCUPIED(rec));
        if (rec->tag == tag)
            tagrec = rec;
    }
    return tagrec;
}

/*
 * Return the header payload of the *last* record in tx that matches the
 * tag and the header name.
 */
char *
get_hdr(const tx_t *tx, enum VSL_tag_e tag, const char *hdr)
{
    logline_t *rec;
    char *hdr_payload = NULL;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        char *c;

        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
        assert(OCCUPIED(rec));
        if (rec->tag != tag)
            continue;
        c = get_payload(rec);
        while (isspace(*c))
            c++;
        if (strncasecmp(c, hdr, strlen(hdr)) != 0)
            continue;
        c += strlen(hdr);
        while (isspace(*c))
            c++;
        if (*c++ != ':')
            continue;
        while (isspace(*c))
            c++;
        hdr_payload = c;
    }
    return hdr_payload;
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
get_rec_fld(const logline_t *rec, int n, size_t *len)
{
    return get_fld(get_payload(rec), n, len);
}

static inline void
format_slt(const tx_t *tx, enum VSL_tag_e tag, char *hdr, int fld, char **s,
           size_t *len)
{
    logline_t *rec;

    if (hdr == NULL) {
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
        *s = get_hdr(tx, tag, hdr);
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
    logline_t *rec = get_tag(tx, tag);
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
format_DT(const tx_t *tx, const char *ts, int m, char **s, size_t *len)
{
    const char *t;
    double d;

    char *f = get_hdr(tx, SLT_Timestamp, ts);
    if (f == NULL)
        return;
    t = get_fld(f, 1, len);
    errno = 0;
    d = strtod(t, NULL);
    if (errno != 0)
        scratch[0] = '\0';
    else
        sprintf(scratch, "%d", (int) (d * m));
    *s = scratch;
    *len = strlen(scratch);
}

void
format_D_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_DT(tx, "Resp", 1e6, s, len);
}

void
format_D_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_DT(tx, "BerespBody", 1e6, s, len);
}

void
format_H_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_ReqProtocol, NULL, -1, s, len);
}

void
format_H_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BereqProtocol, NULL, -1, s, len);
}

static inline void
format_h(const tx_t *tx, enum VSL_tag_e tag, int fld_nr, char **s, size_t *len)
{
    logline_t *rec = get_tag(tx, tag);
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

    logline_t *rec = get_tag(tx, SLT_ReqAcct);
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
    logline_t *rec = get_tag(tx, SLT_BereqAcct);
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
    format_IO_backend(tx, 5, s, len);
}

void
format_m_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_ReqMethod, NULL, -1, s, len);
}

void
format_m_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BereqMethod, NULL, -1, s, len);
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
    format_IO_backend(tx, 2, s, len);
}

static inline void
format_q(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;
    logline_t *rec = get_tag(tx, tag);
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
format_r(const tx_t *tx, enum VSL_tag_e mtag, enum VSL_tag_e htag,
         enum VSL_tag_e utag, enum VSL_tag_e ptag, char **s, size_t *len) 
{
    char *str;

    logline_t *rec = get_tag(tx, mtag);
    if (rec != NULL)
        sprintf(scratch, get_payload(rec));
    else
        strcpy(scratch, "-");
    strcat(scratch, " ");

    if ((str = get_hdr(tx, htag, "Host")) != NULL) {
        if (strncmp(str, "http://", 7) != 0)
            strcat(scratch, "http://");
        strcat(scratch, str);
    }
    else
        strcat(scratch, "http://localhost");

    rec = get_tag(tx, utag);
    if (rec != NULL && rec->len > 0)
        strcat(scratch, get_payload(rec));
    else
        strcat(scratch, "-");

    strcat(scratch, " ");
    rec = get_tag(tx, ptag);
    if (rec != NULL && rec->len > 0)
        strcat(scratch, get_payload(rec));
    else
        strcat(scratch, "HTTP/1.0");

    *s = scratch;
    *len = strlen(scratch);
}

void
format_r_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_r(tx, SLT_ReqMethod, SLT_ReqHeader, SLT_ReqURL, SLT_ReqProtocol, s,
             len);
}

void
format_r_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_r(tx, SLT_BereqMethod, SLT_BereqHeader, SLT_BereqURL,
             SLT_BereqProtocol, s, len);
}

void
format_s_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_RespStatus, NULL, -1, s, len);
}

void
format_s_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_slt(tx, SLT_BerespStatus, NULL, -1, s, len);
}

static inline void
format_tim(const tx_t *tx, const char *fmt, char **s, size_t *len)
{
    unsigned secs, usecs;
    char *data;
    const char *ts;
    time_t t;
    struct tm tm;

    if (tx->type != VSL_t_raw) {
        data = get_hdr(tx, SLT_Timestamp, "Start");
        if (data == NULL)
            return;
        ts = get_fld(data, 0, len);
        if (ts == NULL)
            return;
        if (sscanf(ts, "%d.%u", &secs, &usecs) != 2)
            return;
        assert(usecs < 1000000);
        t = (time_t) secs;
    }
    else {
        t = (time_t) tx->t;
        usecs = (tx->t - (double)t) * 1e6;
    }
    AN(localtime_r(&t, &tm));
    AN(scratch);
    size_t n = strfTIM(scratch, config.max_reclen, fmt, &tm, usecs);
    if (n != 0) {
        *s = scratch;
        *len = strlen(scratch);
    }
}

void
format_t(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_tim(tx, "[%d/%b/%Y:%T %z]", s, len);
}

void
format_T_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_DT(tx, "Resp", 1, s, len);
}

void
format_T_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_DT(tx, "BerespBody", 1, s, len);
}

static inline void
format_U(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;

    logline_t *rec = get_tag(tx, tag);
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
format_u(const tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *hdr;

    if ((hdr = get_hdr(tx, tag, "Authorization")) != NULL
        && strncasecmp(get_fld(hdr, 0, len), "Basic", 5) == 0) {
        const char *c, *auth = get_fld(hdr, 1, len);
        VB64_init();
        VB64_decode(scratch, config.max_reclen, auth, auth + *len);
        c = strchr(scratch, ':');
        *s = scratch;
        if (c != NULL)
            *len = c - scratch;
        else
            *len = strlen(scratch);
    }
    else {
        *s = dash;
        *len = 1;
    }
}

void
format_u_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_u(tx, SLT_ReqHeader, s, len);
}

void
format_u_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_u(tx, SLT_BereqHeader, s, len);
}

static inline void
format_Xio(const tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
           size_t *len)
{
    *s = get_hdr(tx, tag, name);
    if (*s)
        *len = strlen(*s);
}

void
format_Xi_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->name, SLT_ReqHeader, s, len);
}

void
format_Xi_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->name, SLT_BereqHeader, s, len);
}

void
format_Xo_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->name, SLT_RespHeader, s, len);
}

void
format_Xo_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_Xio(tx, args->name, SLT_BerespHeader, s, len);
}

void
format_Xt(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_tim(tx, (const char *) args->name, s, len);
}

static inline void
format_Xttfb(const tx_t *tx, const char *tname, char **s, size_t *len)
{
    char *ts;

    ts = get_hdr(tx, SLT_Timestamp, tname);
    if (ts == NULL)
        return;
    *s = get_fld(ts, 1, len);
}

void
format_Xttfb_client(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_Xttfb(tx, "Process", s, len);
}

void
format_Xttfb_backend(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    (void) args;
    format_Xttfb(tx, "Beresp", s, len);
}

void
format_VCL_disp(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    logline_t *rec;

    *s = dash;
    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
        if (rec->tag != SLT_VCL_call && rec->tag != SLT_VCL_return)
            continue;
        char *data = get_payload(rec);
        if (rec->tag == SLT_VCL_call) {
            if (strcasecmp(data, "hit") == 0)
                *s = hit;
            else if (strcasecmp(data, "miss") == 0)
                *s = miss;
            else if (strcasecmp(data, "pass") == 0) {
                if (*args->name == 'm')
                    *s = miss;
                else
                    *s = pass;
            }
            else if (strcasecmp(data, "error") == 0) {
                if (*args->name == 'm')
                    *s = miss;
                else
                    *s = error;
            }
        }
        else if (strcasecmp(data, "pipe") == 0) {
            if (*args->name == 'm')
                *s = miss;
            else
                *s = pipe;
        }
    }
    *len = strlen(*s);
}

void
format_VCL_Log(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    char *l = get_hdr(tx, SLT_VCL_Log, args->name);
    if (l == NULL)
        return;
    *s = l;
    *len = strlen(l);
}

void
format_SLT(const tx_t *tx, const arg_t *args, char **s, size_t *len)
{
    format_slt(tx, args->tag, args->name, args->fld, s, len);
    if (VSL_tagflags[args->tag] & SLT_F_BINARY) {
        VSB_clear(bintag);
        VSB_quote(bintag, *s, (int) *len, 0);
        VSB_finish(bintag);
        *s = VSB_data(bintag);
        *len = VSB_len(bintag);
    }
}

static void
add_fmt(const compiled_fmt_t *fmt, struct vsb *os, unsigned n,
        formatter_f formatter, const char *name, enum VSL_tag_e tag, int fld)
{
    fmt->str[n] = (char *) malloc(VSB_len(os) + 1);
    AN(fmt->str[n]);
    if (name == NULL)
        fmt->args[n].name = NULL;
    else {
        fmt->args[n].name = (char *) malloc(strlen(name) + 1);
        AN(fmt->args[n].name);
        strcpy(fmt->args[n].name, name);
    }
    VSB_finish(os);
    strcpy(fmt->str[n], VSB_data(os));
    VSB_clear(os);
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

#define FMT(type, format_ltr)                           \
    (C(type) ? format_ltr##_client : format_ltr##_backend)

static void
add_tag(enum VSL_transaction_e type, enum VSL_tag_e tag, const char *hdr)
{
    includehead_t *inclhead;
    include_t *incl;

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

    incl = calloc(1, sizeof(include_t));
    AN(incl);
    if (hdr != NULL)
        incl->hdr = strdup(hdr);
    VSTAILQ_INSERT_TAIL(inclhead, incl, inclist);
    includes++;
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

        /* Only the SLT or time formatters permitted for the "zero" format
           (neither client nor backend) */
        if (R(type)
            && sscanf(p, "{tag:%s}x", scratch) != 1
            && *p != 't'
            && sscanf(p, "{%s}t", scratch) != 1) {
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
            break;
            
        case 'D':
            add_formatter(fmt, os, n, FMT(type, format_D));
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
            add_formatter(fmt, os, n, FMT(type, format_r));
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
            add_formatter(fmt, os, n, format_t);
            if (type != VSL_t_raw)
                add_tag(type, SLT_Timestamp, "Start");
            n++;
            break;

        case 'T':
            add_formatter(fmt, os, n, FMT(type, format_T));
            add_tag(type, SLT_Timestamp, "Start");
            n++;
            break;
            
        case 'U':
            add_formatter(fmt, os, n, FMT(type, format_U));
            add_cb_tag(type, SLT_ReqURL, SLT_BereqURL, NULL);
            n++;
            break;

        case 'u':
            add_formatter(fmt, os, n, FMT(type, format_u));
            add_cb_tag(type, SLT_ReqHeader, SLT_BereqHeader, "Authorization");
            n++;
            break;

        case '{': {
            const char *tmp;
            char fname[100], ltr;
            tmp = p;
            ltr = '\0';
            while (*tmp != '\0' && *tmp != '}')
                tmp++;
            if (*tmp == '}') {
                tmp++;
                ltr = *tmp;
                memcpy(fname, p+1, tmp-p-2);
                fname[tmp-p-2] = 0;
            }

            switch (ltr) {
            case 'i':
                add_fmt_name(fmt, os, n, FMT(type, format_Xi), fname);
                add_cb_tag(type, SLT_ReqHeader, SLT_BereqHeader, fname);
                n++;
                p = tmp;
                break;
            case 'o':
                add_fmt_name(fmt, os, n, FMT(type, format_Xo), fname);
                add_cb_tag(type, SLT_RespHeader, SLT_BerespHeader, fname);
                n++;
                p = tmp;
                break;
            case 't':
                add_fmt_name(fmt, os, n, format_Xt, fname);
                if (type != VSL_t_raw)
                    add_tag(type, SLT_Timestamp, "Start");
                n++;
                p = tmp;
                break;
            case 'x':
                if (strcmp(fname, "Varnish:time_firstbyte") == 0) {
                    add_formatter(fmt, os, n, FMT(type, format_Xttfb));
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
                    add_fmt_name(fmt, os, n, format_VCL_Log, fname+8);
                    add_tag(type, SLT_VCL_Log, fname+8);
                }
                else if (strncmp(fname, "tag:", 4) == 0) {
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
                    add_fmt(fmt, os, n, format_SLT, hdr, t, fld_nr);
                    add_tag(type, t, hdr);
                }
                else {
                    sprintf(err, "Unknown format starting at: %s", fname);
                    return 1;
                }
                n++;
                p = tmp;
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
    VSB_delete(os);
    return 0;
}

static void
fmt_build_I_arg(const includehead_t *inclhead, int *incl_idx)
{
    AN(incl_arg);
    AN(includes);
    AN(scratch);

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        include_t *incl;

        VSTAILQ_FOREACH(incl, &inclhead[i], inclist) {
            assert(*incl_idx < includes);
            if (incl->hdr == NULL)
                sprintf(scratch, "%s:.", VSL_tags[i]);
            else
                sprintf(scratch, "%s:^\\s*%s\\s*:", VSL_tags[i], incl->hdr);
            incl_arg[*incl_idx] = strdup(scratch);
            *incl_idx += 1;
        }
    }
}

int
FMT_Init(char *err)
{
    scratch = (char *) malloc(config.max_reclen + 1);
    if (scratch == NULL)
        return errno;

    payload = VSB_new(NULL, NULL, config.max_reclen + 1, VSB_FIXEDLEN);
    if (payload == NULL)
        return ENOMEM;

    bintag = VSB_new(NULL, NULL, config.max_reclen + 1, VSB_FIXEDLEN);
    if (bintag == NULL)
        return ENOMEM;

    includes = 0;
    for (int i = 0; i < MAX_VSL_TAG; i++) {
        VSTAILQ_INIT(&cincl[i]);
        VSTAILQ_INIT(&bincl[i]);
        VSTAILQ_INIT(&rincl[i]);
    }

    if (!EMPTY(config.cformat))
        if (compile_fmt(config.cformat, &cformat, VSL_t_req, err) != 0)
            return EINVAL;

    if (!EMPTY(config.bformat))
        if (compile_fmt(config.bformat, &bformat, VSL_t_bereq, err) != 0)
            return EINVAL;

    if (!EMPTY(config.rformat))
        if (compile_fmt(config.rformat, &rformat, VSL_t_raw, err) != 0)
            return EINVAL;

    if (includes > 0) {
        incl_arg = calloc(includes + 1, sizeof(char *));
        if (incl_arg == NULL)
            return ENOMEM;
        int incl_idx = 0;

        fmt_build_I_arg(cincl, &incl_idx);
        fmt_build_I_arg(bincl, &incl_idx);
        fmt_build_I_arg(rincl, &incl_idx);
        assert(incl_idx == includes);
    }

    return 0;
}

char **
FMT_Get_I_Args(void)
{
    return incl_arg;
}

int
FMT_Estimate_RecsPerTx(void)
{
    int recs_per_tx = 0, recs_per_ctx = 0, recs_per_btx = 0;
    include_t *incl;

    if (includes == 0)
        return 0;

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        if (!VSTAILQ_EMPTY(&rincl[i])) {
            recs_per_tx = 1;
            break;
        }
    }

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        VSTAILQ_FOREACH(incl, &cincl[i], inclist)
            switch(i) {
            case SLT_VCL_call:
            case SLT_VCL_return:
                recs_per_ctx += config.max_vcl_call;
                break;
            case SLT_VCL_Log:
                recs_per_ctx += config.max_vcl_log;
                break;
            default:
                recs_per_ctx++;
            }
    }
    if (recs_per_ctx > recs_per_tx)
        recs_per_tx = recs_per_ctx;

    for (int i = 0; i < MAX_VSL_TAG; i++)
        VSTAILQ_FOREACH(incl, &bincl[i], inclist)
            if (i == SLT_VCL_Log)
                recs_per_btx += config.max_vcl_log;
            else
                recs_per_btx++;
    if (recs_per_btx > recs_per_tx)
        recs_per_tx = recs_per_btx;

    return recs_per_tx;
}

void
FMT_Format(tx_t *tx, struct vsb *os)
{
    compiled_fmt_t fmt;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(OCCUPIED(tx));

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

    for (int i = 0; i < fmt.n; i++) {
        char *s = NULL;
        size_t len = 0;

        if (fmt.str[i] != NULL)
            VSB_cat(os, fmt.str[i]);
        if (fmt.formatter[i] != NULL) {
            (fmt.formatter[i])(tx, &fmt.args[i], &s, &len);
            if (s != NULL && len != 0)
                VSB_bcat(os, s, len);
        }
    }
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
    free(fmt->formatter);
    free(fmt->args);
}

static void
free_incl(includehead_t inclhead[])
{
    include_t *incl;

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
    free(scratch);
    VSB_delete(payload);
    VSB_delete(bintag);

    if (includes > 0) {
        for (int i = 0; i <= includes; i++)
            if (incl_arg[i] != NULL)
                free((void *) incl_arg[i]);
        free(incl_arg);

        free_incl(cincl);
        free_incl(bincl);
        free_incl(rincl);
    }

    if (!EMPTY(config.cformat))
        free_format(&cformat);
    if (!EMPTY(config.bformat))
        free_format(&bformat);
    if (!EMPTY(config.rformat))
        free_format(&rformat);
}
