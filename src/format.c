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

#include "vas.h"
#include "miniobj.h"
#include "base64.h"
#include "vre.h"

#include "varnishevent.h"
#include "format.h"
#include "strfTIM.h"

typedef struct arg_t {
    char *name;
    enum VSL_tag_e tag;
} arg_t;

typedef struct compiled_fmt_t {
    unsigned n;
    char **str;
    formatter_f **formatter;
    arg_t *args;
    char tags[MAX_VSL_TAG];
} compiled_fmt_t;

/* XXX: When FMT_Init is implemented, malloc to config.max_reclen */
static char scratch[DEFAULT_MAX_RECLEN];

static char hit[] = "hit";
static char miss[] = "miss";
static char pass[] = "pass";
static char pipe[] = "pipe";
static char error[] = "error";
static char dash[] = "-";

#if 0

static compiled_fmt_t cformat, bformat, zformat;

static char i_arg[BUFSIZ] = "";

static int read_rx_hdr = 0, read_tx_hdr = 0, read_vcl_log = 0,
    read_vcl_call = 0, ntags = 0;

#endif

void
get_payload(logline_t *rec)
{
    CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);

    VSB_clear(payload);
    if (rec->len) {
        int n = rec->len;
        chunk_t *chunk = VSTAILQ_FIRST(&rec->chunks);
        while (n > 0 && chunk != NULL) {
            CHECK_OBJ(chunk, CHUNK_MAGIC);
            int cp = n;
            if (cp > config.chunk_size)
                cp = config.chunk_size;
            VSB_bcat(payload, chunk->data, cp);
            n -= cp;
            chunk = VSTAILQ_NEXT(chunk, chunklist);
        }
    }
    assert(VSB_len(payload) == rec->len);
    VSB_finish(payload);
}

/*
 * Return the *last* record in tx that matches the tag
 */
logline_t *
get_tag(tx_t *tx, enum VSL_tag_e tag)
{
    logline_t *rec, *tagrec = NULL;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
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
get_hdr(tx_t *tx, enum VSL_tag_e tag, const char *hdr)
{
    logline_t *rec;
    char *hdr_payload = NULL;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        char *c;

        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
        if (rec->tag != tag)
            continue;
        get_payload(rec);
        c = VSB_data(payload);
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
get_fld(const char *str, int n)
{
    char *fld = NULL, *s, cp[BUFSIZ];
    int i = 0;

    AN(str);
    strcpy(cp, str);
    s = cp;
    do {
        fld = strtok(s, " \t");
        s = NULL;
    } while (i++ < n && fld != NULL);
    
    return fld;
}

char *
get_rec_fld(logline_t *rec, int n)
{
    get_payload(rec);
    return get_fld(VSB_data(payload), n);
}

double
get_tm(tx_t *tx)
{
    char *ts, *epochstr;
    double epocht = 0;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);

    ts = get_hdr(tx, SLT_Timestamp, "Start");
    if (ts != NULL && (epochstr = get_fld(ts, 0)) != NULL) {
        char *p;
        epocht = strtod(epochstr, &p);
    }
    if (epocht == 0)
        epocht = tx->t;

    return epocht;
}

static inline void
format(tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    logline_t *rec = get_tag(tx, tag);
    if (rec != NULL) {
        get_payload(rec);
        *s = VSB_data(payload);
        *len = VSB_len(payload);
    }
}

static inline void
format_b(tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    logline_t *rec = get_tag(tx, tag);
    *s = get_rec_fld(rec, 4);
    *len = strlen(*s);
}

void
format_b_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_b(tx, SLT_ReqAcct, s, len);
}

void
format_b_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_b(tx, SLT_BereqAcct, s, len);
}

static inline void
format_DT(tx_t *tx, const char *ts, int m, char **s, size_t *len)
{
    char *t;
    double d;

    char *f = get_hdr(tx, SLT_Timestamp, ts);
    t = get_fld(f, 1);
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
format_D_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_DT(tx, "Resp", 1e6, s, len);
}

void
format_D_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_DT(tx, "BerespBody", 1e6, s, len);
}

void
format_H_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_ReqProtocol, s, len);
}

void
format_H_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_BereqProtocol, s, len);
}

static inline void
format_h(tx_t *tx, enum VSL_tag_e tag, int fld_nr, char **s, size_t *len)
{
    logline_t *rec = get_tag(tx, tag);
    *s = get_rec_fld(rec, fld_nr);
    *len = strlen(*s);
}

void
format_h_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_h(tx, SLT_ReqStart, 0, s, len);
}

void
format_h_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_h(tx, SLT_Backend, 2, s, len);
}

static inline void
format_IO_client(tx_t *tx, int req_fld, int pipe_fld, char **s, size_t *len)
{
    int field;

    logline_t *rec = get_tag(tx, SLT_ReqAcct);
    if (rec != NULL)
        field = req_fld;
    else {
        rec = get_tag(tx, SLT_PipeAcct);
        field = pipe_fld;
    }
    *s = get_rec_fld(rec, field);
    *len = strlen(*s);
}

static inline void
format_IO_backend(tx_t *tx, int field, char **s, size_t *len)
{
    logline_t *rec = get_tag(tx, SLT_BereqAcct);
    *s = get_rec_fld(rec, field);
    *len = strlen(*s);
}

void
format_I_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                size_t *len)
{
    (void) name;
    (void) tag;
    format_IO_client(tx, 2, 2, s, len);
}

void
format_I_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_IO_backend(tx, 5, s, len);
}

void
format_m_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_ReqMethod, s, len);
}

void
format_m_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_BereqMethod, s, len);
}

void
format_O_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                size_t *len)
{
    (void) name;
    (void) tag;
    format_IO_client(tx, 5, 3, s, len);
}

void
format_O_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_IO_backend(tx, 2, s, len);
}

static inline void
format_q(tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;
    logline_t *rec = get_tag(tx, tag);
    get_payload(rec);
    qs = memchr(VSB_data(payload), '?', rec->len);
    if (qs != NULL) {
        *s = qs + 1;
        *len = rec->len - (*s - VSB_data(payload));
    }
}

void
format_q_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_q(tx, SLT_ReqURL, s, len);
}

void
format_q_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_q(tx, SLT_BereqURL, s, len);
}

static inline void
format_r(tx_t *tx, enum VSL_tag_e mtag, enum VSL_tag_e htag,
         enum VSL_tag_e utag, enum VSL_tag_e ptag, char **s, size_t *len) 
{
    char *str;

    logline_t *rec = get_tag(tx, mtag);
    if (rec != NULL) {
        get_payload(rec);
        sprintf(scratch, VSB_data(payload));
    }
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
    if (rec->len) {
        get_payload(rec);
        strcat(scratch, VSB_data(payload));
    }
    else
        strcat(scratch, "-");

    strcat(scratch, " ");
    rec = get_tag(tx, ptag);
    if (rec->len) {
        get_payload(rec);
        strcat(scratch, VSB_data(payload));
    }
    else
        strcat(scratch, "HTTP/1.0");

    *s = scratch;
    *len = strlen(scratch);
}

void
format_r_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_r(tx, SLT_ReqMethod, SLT_ReqHeader, SLT_ReqURL, SLT_ReqProtocol, s,
             len);
}

void
format_r_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_r(tx, SLT_BereqMethod, SLT_BereqHeader, SLT_BereqURL,
             SLT_BereqProtocol, s, len);
}

void
format_s_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_RespStatus, s, len);
}

void
format_s_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format(tx, SLT_RespStatus, s, len);
}

static inline void
format_tim(tx_t *tx, const char *fmt, char **s, size_t *len)
{
    unsigned secs, usecs;
    char *data, *ts;
    time_t t;
    struct tm tm;

    data = get_hdr(tx, SLT_Timestamp, "Start");
    if (data == NULL)
        return;
    ts = get_fld(data, 0);
    if (ts == NULL)
        return;
    if (sscanf(ts, "%d.%u", &secs, &usecs) != 2)
        return;
    assert(usecs < 1000000);
    t = (time_t) secs;
    AN(localtime_r(&t, &tm));
    AN(scratch);
    size_t n = strfTIM(scratch, config.max_reclen, fmt, &tm, usecs);
    if (n != 0) {
        *s = scratch;
        *len = strlen(scratch);
    }
}

void
format_t(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;

    format_tim(tx, "[%d/%b/%Y:%T %z]", s, len);
}

void
format_T_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_DT(tx, "Resp", 1, s, len);
}

void
format_T_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                size_t *len)
{
    (void) name;
    (void) tag;
    format_DT(tx, "BerespBody", 1, s, len);
}

static inline void
format_U(tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *qs = NULL;

    logline_t *rec = get_tag(tx, tag);
    get_payload(rec);
    *s = VSB_data(payload);
    qs = memchr(VSB_data(payload), '?', rec->len);
    if (qs == NULL)
        *len = rec->len;
    else {
        *qs = '\0';
        *len = qs - *s;
    }
}

void
format_U_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_U(tx, SLT_ReqURL, s, len);
}

void
format_U_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_U(tx, SLT_BereqURL, s, len);
}

static inline void
format_u(tx_t *tx, enum VSL_tag_e tag, char **s, size_t *len)
{
    char *hdr;

    if ((hdr = get_hdr(tx, tag, "Authorization")) != NULL
        && strcasecmp(get_fld(hdr, 0), "Basic") == 0) {
        char *c, *auth = get_fld(hdr, 1);
        VB64_init();
        VB64_decode(scratch, config.max_reclen, auth, auth + strlen(auth));
        c = strchr(scratch, ':');
        if (c != NULL)
            *c = '\0';
        *s = scratch;
        *len = strlen(scratch);
    }
    else {
        strcpy(scratch, "-");
        *s = scratch;
        *len = 1;
    }
}

void
format_u_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_u(tx, SLT_ReqHeader, s, len);
}

void
format_u_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) name;
    (void) tag;
    format_u(tx, SLT_BereqHeader, s, len);
}

static inline void
format_Xio(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    *s = get_hdr(tx, tag, name);
    if (s)
        *len = strlen(*s);
}

void
format_Xi_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) tag;
    format_Xio(tx, name, SLT_ReqHeader, s, len);
}

void
format_Xi_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                  size_t *len)
{
    (void) tag;
    format_Xio(tx, name, SLT_BereqHeader, s, len);
}

void
format_Xo_client(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                 size_t *len)
{
    (void) tag;
    format_Xio(tx, name, SLT_RespHeader, s, len);
}

void
format_Xo_backend(tx_t *tx, char *name, enum VSL_tag_e tag, char **s,
                  size_t *len)
{
    (void) tag;
    format_Xio(tx, name, SLT_BerespHeader, s, len);
}

void
format_Xt(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) tag;
    format_tim(tx, (const char *) name, s, len);
}

static inline void
format_Xttfb(tx_t *tx, const char *tname, char **s, size_t *len)
{
    char *ts;

    ts = get_hdr(tx, SLT_Timestamp, tname);
    if (ts == NULL)
        return;
    *s = get_fld(ts, 1);
    *len = strlen(*s);
}

void
format_Xttfb_client(tx_t *tx, char *name, enum VSL_tag_e tag,
                    char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_Xttfb(tx, "Process", s, len);
}

void
format_Xttfb_backend(tx_t *tx, char *name, enum VSL_tag_e tag,
                     char **s, size_t *len)
{
    (void) name;
    (void) tag;
    format_Xttfb(tx, "Beresp", s, len);
}

void
format_VCL_disp(tx_t *tx, char *name, enum VSL_tag_e tag,
                char **s, size_t *len)
{
    logline_t *rec;

    (void) tag;
    *s = dash;

    VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
        CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
        if (rec->tag != SLT_VCL_call && rec->tag != SLT_VCL_return)
            continue;
        get_payload(rec);
        char *data = VSB_data(payload);
        if (rec->tag == SLT_VCL_call) {
            if (strcasecmp(data, "hit") == 0)
                *s = hit;
            else if (strcasecmp(data, "miss") == 0)
                *s = miss;
            else if (strcasecmp(data, "pass") == 0) {
                if (*name == 'm')
                    *s = miss;
                else
                    *s = pass;
            }
            else if (strcasecmp(data, "error") == 0) {
                if (*name == 'm')
                    *s = miss;
                else
                    *s = error;
            }
        }
        else if (strcasecmp(data, "pipe") == 0) {
            if (*name == 'm')
                *s = miss;
            else
                *s = pipe;
        }
    }
    *len = strlen(*s);
}

void
format_VCL_Log(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) tag;
    
    char *l = get_hdr(tx, SLT_VCL_Log, name);
    if (l == NULL)
        return;
    *s = l;
    *len = strlen(l);
}

void
format_SLT(tx_t *tx, char *name, enum VSL_tag_e tag, char **s, size_t *len)
{
    (void) name;
    format(tx, tag, s, len);
}

#if 0

static void
format_incomplete(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) tag;

    char *colon = strchr(name, ':');
    AN(colon);
    if (ll->incomplete)
        strncpy(scratch, name, colon - name);
    else
        strcpy(scratch, colon + 1);

    *s = scratch;
    *len = strlen(scratch);
}

static int
add_fmt(compiled_fmt_t *fmt, struct vsb *os, unsigned n, formatter_f formatter,
    const char *name, enum VSL_tag_e tag)
{
    fmt->str[n] = (char *) malloc(VSB_len(os) + 1);
    if (fmt->str[n] == NULL)
        return errno;
    if (name == NULL)
        fmt->args[n].name = NULL;
    else {
        fmt->args[n].name = (char *) malloc(strlen(name) + 1);
        if (fmt->args[n].name == NULL)
            return errno;
        strcpy(fmt->args[n].name, name);
    }
    VSB_finish(os);
    strcpy(fmt->str[n], VSB_data(os));
    VSB_clear(os);
    fmt->formatter[n] = formatter;
    fmt->args[n].tag = tag;
    return 0;
}

#define ADD_FMT(spec, fmt, os, n, format_ltr, name, tag) do {		\
    if (C(spec))							\
        add_fmt((fmt), (os), (n), format_ltr##_client, (name), (tag));	\
    else if (B(spec))							\
        add_fmt((fmt), (os), (n), format_ltr##_backend, (name), (tag));	\
    } while(0)

#define ADD_TAG(tags, tag) (tags[SLT_##tag]) = 1

#define ADD_CB_TAG(spec, tags, ctag, btag) do {                 \
    if (C(spec)) ADD_TAG(tags, ctag); else ADD_TAG(tags, btag);	\
    } while(0)

static int
compile_fmt(char *format, compiled_fmt_t *fmt, unsigned spec, char *err)
{
    const char *p;
    unsigned n = 1;
    struct vsb *os;

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
    memset(fmt->tags, 0, MAX_VSL_TAG);

    /* starting tags */
    if (C(spec)) {
        ADD_TAG(fmt->tags, SessionOpen);
        ADD_TAG(fmt->tags, ReqStart);
    }
    if (B(spec)) {
        ADD_TAG(fmt->tags, BackendOpen);
        ADD_TAG(fmt->tags, BackendXID);
    }
    /* always read the closing tags for clients and backends */
    if (C(spec) || B(spec)) {
        ADD_TAG(fmt->tags, ReqEnd);
        ADD_TAG(fmt->tags, BackendReuse);
        ADD_TAG(fmt->tags, BackendClose);
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
        if (Z(spec)
            && sscanf(p, "{tag:%s}x", scratch) != 1
            && *p != 't'
            && sscanf(p, "{%s}t", scratch) != 1) {
            sprintf(err, "Unknown format starting at: %s", --p);
            return 1;
        }
        
        switch (*p) {

        case 'd':
            VSB_putc(os, C(spec) ? 'c' : 'b');
            break;
            
        case 'b':
            ADD_FMT(spec, fmt, os, n, format_b, NULL, 0);
            ADD_TAG(fmt->tags, Length);
            ADD_CB_TAG(spec, fmt->tags, TxHeader, RxHeader);
            n++;
            break;

        case 'H':
            ADD_FMT(spec, fmt, os, n, format_H, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxProtocol, TxProtocol);
            n++;
            break;
            
        case 'h':
            ADD_FMT(spec, fmt, os, n, format_h, NULL, 0);
            if (C(spec))
                ADD_TAG(fmt->tags, ReqStart);
            else {
                ADD_TAG(fmt->tags, BackendOpen);
                ADD_TAG(fmt->tags, BackendReuse);
                ADD_TAG(fmt->tags, BackendClose);
            }
            n++;
            break;
            
        case 'l':
            VSB_putc(os, '-');
            break;

        case 'm':
            ADD_FMT(spec, fmt, os, n, format_m, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxRequest, TxRequest);
            n++;
            break;

        case 'q':
            ADD_FMT(spec, fmt, os, n, format_q, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxURL, TxURL);
            n++;
            break;

        case 'r':
            ADD_FMT(spec, fmt, os, n, format_r, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxRequest, TxRequest);
            ADD_CB_TAG(spec, fmt->tags, RxHeader, TxHeader);
            ADD_CB_TAG(spec, fmt->tags, RxURL, TxURL);
            ADD_CB_TAG(spec, fmt->tags, RxProtocol, TxProtocol);
            n++;
            break;

        case 's':
            ADD_FMT(spec, fmt, os, n, format_s, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, TxStatus, RxStatus);
            n++;
            break;

        case 't':
            add_fmt(fmt, os, n, format_t, NULL, 0);
            if (C(spec)) {
                ADD_TAG(fmt->tags, ReqEnd);
                ADD_TAG(fmt->tags, TxHeader);
            }
            else if (B(spec))
                ADD_TAG(fmt->tags, RxHeader);
            n++;
            break;

        case 'U':
            ADD_FMT(spec, fmt, os, n, format_U, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxURL, TxURL);
            n++;
            break;

        case 'u':
            ADD_FMT(spec, fmt, os, n, format_u, NULL, 0);
            ADD_CB_TAG(spec, fmt->tags, RxHeader, TxHeader);
            n++;
            break;

        case '{': {
            const char *tmp;
            char fname[100], type;
            tmp = p;
            type = 0;
            while (*tmp != '\0' && *tmp != '}')
                tmp++;
            if (*tmp == '}') {
                tmp++;
                type = *tmp;
                memcpy(fname, p+1, tmp-p-2);
                fname[tmp-p-2] = 0;
            }

            switch (type) {
            case 'i':
                ADD_FMT(spec, fmt, os, n, format_Xi, fname, 0);
                ADD_CB_TAG(spec, fmt->tags, RxHeader, TxHeader);
                n++;
                p = tmp;
                break;
            case 'o':
                ADD_FMT(spec, fmt, os, n, format_Xo, fname, 0);
                ADD_CB_TAG(spec, fmt->tags, TxHeader, RxHeader);
                n++;
                p = tmp;

                break;
            case 't':
                add_fmt(fmt, os, n, format_Xt, fname, 0);
                if (C(spec)) {
                    ADD_TAG(fmt->tags, ReqEnd);
                    ADD_TAG(fmt->tags, RxHeader);
                }
                else if (B(spec)) {
                    ADD_TAG(fmt->tags, TxHeader);
                }
                n++;
                p = tmp;
                break;
            case 'x':
                if (strcmp(fname, "Varnish:time_firstbyte") == 0) {
                    if (C(spec))
                        ADD_TAG(fmt->tags, ReqEnd);
#ifdef BESTATS
                    else {
                        ADD_TAG(fmt->tags, BackendReq);
                        ADD_TAG(fmt->tags, Fetch_Hdr);
                    }
                    ADD_FMT(spec, fmt, os, n, format_Xttfb, NULL, 0);
#else
                    else {
                        sprintf(err,
                            "Varnish:time_firstbyte only permitted "
                            "for client formats");
                        return 1;
                    }
                    add_fmt(fmt, os, n, format_Xttfb_client, NULL, 0);
#endif
                }
                else if (strcmp(fname, "Varnish:hitmiss") == 0) {
                    if (C(spec)) {
                        add_fmt(fmt, os, n, format_VCL_disp, "m", 0);
                        ADD_TAG(fmt->tags, VCL_call);
                    }
                    else {
                        sprintf(err,
                           "Varnish:hitmiss only permitted for client formats");
                        return 1;
                    }
                }
                else if (strcmp(fname, "Varnish:handling") == 0) {
                    if (C(spec)) {
                        add_fmt(fmt, os, n, format_VCL_disp, "n", 0);
                        ADD_TAG(fmt->tags, VCL_call);
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
                    add_fmt(fmt, os, n, format_VCL_Log, fname+8, 0);
                    ADD_TAG(fmt->tags, VCL_Log);
                }
                else if (strncmp(fname, "tag:", 4) == 0) {
                    int t = 0;
                    
                    /* retrieve the tag contents from the log */
                    if ((t = VSL_Name2Tag(fname+4, strlen(fname+4))) < 0) {
                        sprintf(err, "Unknown or non-unique tag %s", fname+4);
                        return 1;
                    }
                    add_fmt(fmt, os, n, format_SLT, NULL, t);
                    fmt->tags[t] = 1;
                }
                else if (strncmp(fname, "incomplete:", 11) == 0) {
                    if (strchr(fname+11, ':') == NULL) {
                        sprintf(err, "':' not found in incomplete formatter %s",
                            fname+11);
                        return 1;
                    }
                    add_fmt(fmt, os, n, format_incomplete, fname+11, 0);
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
    add_fmt(fmt, os, n, NULL, NULL, 0);
    VSB_delete(os);
    return 0;
}

int
FMT_Init(char *err)
{
    scratch = (char *) malloc(config.max_reclen);
    if (scratch == NULL)
        return errno;

    if (!EMPTY(config.cformat))
        if (compile_fmt(config.cformat, &cformat, VSL_S_CLIENT, err) != 0)
            return EINVAL;

    if (!EMPTY(config.bformat))
        if (compile_fmt(config.bformat, &bformat, VSL_S_BACKEND, err) != 0)
            return EINVAL;

    if (!EMPTY(config.zformat))
        if (compile_fmt(config.zformat, &zformat, 0, err) != 0)
            return EINVAL;

    strcpy(hit, "hit");
    strcpy(miss, "miss");
    strcpy(pass, "pass");
    strcpy(dash, "-");
    
    for (int i = 0; i < MAX_VSL_TAG; i++) {
        char tag = cformat.tags[i] | bformat.tags[i] | zformat.tags[i];
        if (tag) {
            strcat(i_arg, VSL_tags[i]);
            strcat(i_arg, ",");
            
            switch(i) {
            case SLT_RxHeader:
                read_rx_hdr = 1;
                break;
            case SLT_TxHeader:
                read_tx_hdr = 1;
                break;
            case SLT_VCL_Log:
                read_vcl_log = 1;
                break;
            case SLT_VCL_call:
                read_vcl_call = 1;
                break;
            default:
                idx2tag[ntags] = i;
                tag2idx[i] = ntags++;
            }
        }
        else
            tag2idx[i] = idx2tag[i] = -1;
    }

    return 0;
}

char *
FMT_Get_i_Arg(void)
{
    return i_arg;
}

int
FMT_Get_nTags(void)
{
    return ntags;
}

int
FMT_Read_Hdr(enum VSL_tag_e tag)
{
    switch(tag) {
    case SLT_RxHeader:
        return read_rx_hdr;
    case SLT_TxHeader:
        return read_tx_hdr;
    case SLT_VCL_Log:
        return read_vcl_log;
    case SLT_VCL_call:
        return read_vcl_call;
    default:
        /* Not allowed */
        AN(0);
    }
    /* Unreachable */
    return -1;
}

void
FMT_Format(logline_t *ll, struct vsb *os)
{
    compiled_fmt_t fmt;

    CHECK_OBJ_NOTNULL(ll, LOGLINE_MAGIC);
    assert(ll->state == DATA_DONE);
    
    if (C(ll->spec))
        fmt = cformat;
    else if (B(ll->spec))
        fmt = bformat;
    else
        fmt = zformat;

    for (int i = 0; i < fmt.n; i++) {
        char *s = NULL;
        size_t len = 0;

        if (fmt.str[i] != NULL)
            VSB_cat(os, fmt.str[i]);
        if (fmt.formatter[i] != NULL) {
            (fmt.formatter[i])(ll, fmt.args[i].name, fmt.args[i].tag, &s, &len);
            if (s != NULL && len > 0)
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

void
FMT_Shutdown(void)
{
    free(scratch);

    if (!EMPTY(config.cformat))
        free_format(&cformat);
    if (!EMPTY(config.bformat))
        free_format(&bformat);
    if (!EMPTY(config.zformat))
        free_format(&zformat);
}

#endif
