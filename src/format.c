/*-
 * Copyright (c) 2013 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013 Otto Gmbh & Co KG
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

#include "varnishevent.h"

#include "vas.h"
#include "miniobj.h"
#include "base64.h"

#define TAG(ll,t) ((ll)->tag[tag2idx[(t)]])

typedef void formatter_f(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len);

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

static compiled_fmt_t cformat, bformat, zformat;

static char i_arg[BUFSIZ] = "";

static int read_rx_hdr = 0, read_tx_hdr = 0, read_vcl_log = 0,
    read_vcl_call = 0, ntags = 0;

static char *scratch;

static char hit[4];
static char miss[5];
static char pass[5];
static char dash[2];

static inline record_t *
get_hdr(const char *hdr, hdr_t *tbl)
{
    int l = strlen(hdr);
    
    for (int i = 0; i < tbl->nrec; i++)
        if (strncasecmp(hdr, tbl->record[i].data, l) == 0
            && tbl->record[i].data[l] == ':'
            && tbl->record[i].data[l+1] == ' ')
            return &tbl->record[i];
    return NULL;
}

#define GET_HDR(ll, dir, hdr) get_hdr((hdr), (ll)-> dir## _headers)

static inline char *
get_fld(record_t *rec, int n)
{
    char *ret = NULL, *s;
    int i = 0;

    AN(scratch);
    strncpy(scratch, rec->data, rec->len);
    s = scratch;
    do {
        ret = strtok(s, " \t");
        s = NULL;
    } while (++i < n && ret != NULL);
    
    return ret;
}

static inline int
get_tm(tx_t *ll, struct tm * t) {
    char *ts = NULL;
    record_t *date_rec = NULL;
    time_t tt = 0;
            
    if (C(ll->spec)) {
        if (TAG(ll,SLT_ReqEnd).len
            && (ts = get_fld(&TAG(ll,SLT_ReqEnd), 2)) != NULL)
                tt = (time_t) atol(ts);
        else
            date_rec = GET_HDR(ll, rx, "Date");
    }
    else if (B(ll->spec)) {
        if ((date_rec = GET_HDR(ll, rx, "Date")) == NULL)
            tt = (time_t) ll->t;
    }
    else
        tt = (time_t) ll->t;
    
    if (date_rec)
        tt = TIM_parse(&date_rec->data[strlen("Date: ")]);
    if (tt != 0) {
        localtime_r(&tt, t);
        return 1;
    }
    else
        return 0;
}

#define RETURN_REC(rec, s, len) do {            \
    (*s) = (rec).data;                          \
    (*(len)) = (rec).len;                       \
} while (0)

#define RETURN_HDR(rec, hdr, s, len) do {	\
    (*s) = &((rec)->data[strlen(hdr)+2]);	\
    (*(len)) = (rec)->len - (strlen(hdr)+2);	\
} while (0)

#define RETURN_FLD(rec, fld, s, len) do {	\
    (*s) = get_fld(&(rec), fld);		\
    (*(len)) = strlen(*s);			\
} while (0)

#define FORMAT(dir, ltr, slt) 						\
static void								\
format_##ltr##_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,	\
                     char **s, size_t *len)                             \
{									\
    (void) name;							\
    (void) tag;								\
    if (TAG(ll,SLT_##slt).len)						\
        RETURN_REC(TAG(ll,SLT_##slt), s, len);				\
}

#define FORMAT_b(dir, hx) 					\
static void							\
format_b_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,	\
    char **s, size_t *len)                                      \
{								\
    (void) name;						\
    (void) tag;							\
    record_t *rec;						\
    if (TAG(ll,SLT_Length).len)                                 \
        RETURN_REC(TAG(ll,SLT_Length), s, len);                 \
    else if ((rec = GET_HDR(ll, hx, "content-length")) != NULL)	\
        RETURN_HDR(rec, "content-length", s, len);		\
}

FORMAT_b(client, tx)
FORMAT_b(backend, rx)

FORMAT(client, H, RxProtocol)
FORMAT(backend, H, TxProtocol)

static void
format_h_client(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) name;
    (void) tag;
    
    if (TAG(ll,SLT_ReqStart).len)
        RETURN_FLD(TAG(ll,SLT_ReqStart), 0, s, len);
}

static void
format_h_backend(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) name;
    (void) tag;
    
    if (TAG(ll,SLT_BackendOpen).len)
        RETURN_FLD(TAG(ll,SLT_BackendOpen), 0, s, len);
    else if (TAG(ll,SLT_BackendReuse).len)
        RETURN_REC(TAG(ll,SLT_BackendReuse), s, len);
    else if (TAG(ll,SLT_BackendClose).len)
        RETURN_REC(TAG(ll,SLT_BackendClose), s, len);
}

FORMAT(client, m, RxRequest)
FORMAT(backend, m, TxRequest)

#define FORMAT_q(dir, xurl) 						\
static void								\
format_q_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,		\
    char **s, size_t *len)                                              \
{									\
    (void) name;							\
    (void) tag;								\
    char *qs = NULL;							\
    qs = memchr(TAG(ll,SLT_##xurl).data, '?', TAG(ll,SLT_##xurl).len);  \
    if (qs != NULL) {							\
        *s = qs + 1;							\
        *len = TAG(ll,SLT_##xurl).len - (qs - TAG(ll,SLT_##xurl).data - 1); \
    }									\
}

FORMAT_q(client, RxURL)
FORMAT_q(backend, TxURL)

#define FORMAT_r(dir, dx, hx)                                   \
static void                                                     \
format_r_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,   \
    char **s, size_t *len)                                      \
{                                                               \
    (void) name;                                                \
    (void) tag;                                                 \
                                                                \
    record_t *rec;                                              \
                                                                \
    rec = &TAG(ll, SLT_##dx##Request);                          \
    if (rec->len)                                               \
        snprintf(scratch, rec->len+1, "%s", rec->data);         \
    else                                                        \
        strcpy(scratch, "-");                                   \
    strcat(scratch, " ");                                       \
                                                                \
    if ((rec = GET_HDR(ll, hx, "Host")) != NULL) {              \
        if (strncmp(rec->data, "http://", 7) != 0)              \
            strcat(scratch, "http://");                         \
        strncat(scratch, rec->data+6, rec->len-6);              \
    }                                                           \
    else                                                        \
        strcat(scratch, "http://localhost");                    \
                                                                \
    rec = &TAG(ll, SLT_##dx##URL);                              \
    if (rec->len)                                               \
        strncat(scratch, rec->data, rec->len);                  \
    else                                                        \
        strcat(scratch, "-");                                   \
                                                                \
    strcat(scratch, " ");                                       \
    rec = &TAG(ll, SLT_##dx##Protocol);                         \
    if (rec->len)                                               \
        strncat(scratch, rec->data, rec->len);                  \
    else                                                        \
        strcat(scratch, "HTTP/1.0");                            \
                                                                \
    *s = scratch;                                               \
    *len = strlen(scratch);                                     \
}

FORMAT_r(client, Rx, rx)
FORMAT_r(backend, Tx, tx)

FORMAT(client, s, TxStatus)
FORMAT(backend, s, RxStatus)

#define FORMAT_tim(ltr, fmt, extra)                                     \
static void                                                             \
format_##ltr(logline_t *ll, char *name, enum VSL_tag_e tag,             \
    char **s, size_t *len)                                              \
{                                                                       \
    struct tm t;                                                        \
    (void) tag;                                                         \
    extra;                                                              \
    if (get_tm(ll, &t)) {                                               \
        AN(scratch);                                                    \
        size_t n = strftime(scratch, config.max_reclen, fmt, &t);       \
        if (n == 0)                                                     \
            *scratch = '\0';                                            \
        *s = scratch;                                                   \
        *len = strlen(scratch);                                         \
    }                                                                   \
 }

FORMAT_tim(t, "[%d/%b/%Y:%T %z]", (void) name)

#define FORMAT_U(dir, dx)                                               \
static void                                                             \
format_U_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,           \
    char **s, size_t *len)                                              \
{                                                                       \
    char *q = NULL;                                                     \
    unsigned ulen;                                                      \
    (void) name;                                                        \
    (void) tag;                                                         \
    q = memchr(TAG(ll,SLT_##dx##URL).data, '?', TAG(ll,SLT_##dx##URL).len); \
    if (q == NULL)                                                      \
        ulen = TAG(ll,SLT_##dx##URL).len;                               \
    else                                                                \
        ulen = q - TAG(ll,SLT_##dx##URL).data;                          \
    *s = TAG(ll,SLT_##dx##URL).data;                                    \
    *len = ulen;                                                        \
}

FORMAT_U(client, Rx)
FORMAT_U(backend, Tx)

#define FORMAT_u(dir, hx)                                               \
static void                                                             \
format_u_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,           \
    char **s, size_t *len)                                              \
{                                                                       \
    (void) name;                                                        \
    (void) tag;                                                         \
    record_t *rec;                                                      \
                                                                        \
    if ((rec = GET_HDR(ll, hx, "Authorization")) != NULL                \
        && strncasecmp(rec->data + strlen("Authorization: "), "Basic",  \
                       strlen("Basic")) == 0) {                         \
        char *c, *auth = get_fld(rec, 3);                               \
        VB64_init();                                                    \
        VB64_decode(scratch, config.max_reclen, auth);                  \
        c = strchr(scratch, ':');                                       \
        if (c != NULL)                                                  \
            *c = '\0';                                                  \
        *s = scratch;                                                   \
        *len = strlen(scratch);                                         \
    }                                                                   \
    else {                                                              \
        strcpy(scratch, "-");                                           \
        *s = scratch;                                                   \
        *len = 1;                                                       \
    }                                                                   \
}

FORMAT_u(client, rx)
FORMAT_u(backend, tx)

#define FORMAT_Xio(dir, io, hx)						\
static void								\
format_X##io##_##dir(logline_t *ll, char *name, enum VSL_tag_e tag,	\
    char **s, size_t *len)						\
{									\
    (void) tag;								\
    record_t *rec = GET_HDR(ll, hx, name);				\
    if (rec)								\
        RETURN_HDR(rec, name, s, len);					\
}

FORMAT_Xio(client, i, rx)
FORMAT_Xio(backend, i, tx)
FORMAT_Xio(client, o, tx)
FORMAT_Xio(backend, o, rx)

FORMAT_tim(Xt, name, )

static void
format_Xttfb_client(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) name;
    (void) tag;
    
    if (TAG(ll,SLT_ReqEnd).len)
        RETURN_FLD(TAG(ll,SLT_ReqEnd), 5, s, len);
}

#ifdef BESTATS
static void
format_Xttfb_backend(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) name;
    (void) tag;
    
    if (TAG(ll,SLT_BackendReq).len && TAG(ll,SLT_Fetch_Hdr).len) {
        double req_end, fetch_start;
                        
        errno = 0;
        req_end = strtod(get_fld(&TAG(ll,SLT_BackendReq), 2), NULL);
        AZ(errno);
        fetch_start = strtod(get_fld(&TAG(ll,SLT_Fetch_Hdr), 2), NULL);
        AZ(errno);
        sprintf(scratch, "%.9f", fetch_start - req_end);
        *s = scratch;
        *len = strlen(scratch);
    }
}
#endif

static void
format_VCL_disp(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    hdr_t *vcl_call = ll->vcl_call;
    (void) tag;

    *s = dash;

    for (int i = 0; i < vcl_call->nrec; i++) {
        record_t *rec = &vcl_call->record[i];
        if (strncmp(rec->data, "hit", rec->len) == 0) {
            *s = hit;
            break;
        }
        else if (strncmp(rec->data, "miss", rec->len) == 0) {
            *s = miss;
            break;
        }
        else if (strncmp(rec->data, "pass", rec->len) == 0) {
            if (*name == 'm')
                *s = miss;
            else
                *s = pass;
            break;
        }
        else if (strncmp(rec->data, "pipe", rec->len) == 0)
            break;
    }

    *len = strlen(*s);
}


static void
format_VCL_Log(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) tag;
    
    record_t *rec = get_hdr(name, ll->vcl_log);
    if (rec)
        RETURN_HDR(rec, name, s, len);
}

static void
format_SLT(logline_t *ll, char *name, enum VSL_tag_e tag,
    char **s, size_t *len)
{
    (void) name;
    
    if (TAG(ll,tag).len)
        RETURN_REC(TAG(ll,tag), s, len);
}

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