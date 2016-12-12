/*-
 * Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2015 Otto Gmbh & Co KG
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
#include <math.h>
#include <time.h>
#include <stdarg.h>

#include "minunit.h"

#include "../varnishevent.h"
#include "../format.h"

#define NRECORDS 10
#define SHORT_STRING "foo bar baz quux"

int tests_run = 0;

/* So that we don't have to link monitor.o, and hence varnishevent.o */
void
MON_StatsUpdate(stats_update_t update, unsigned nrec, unsigned nchunk)
{
    (void) update;
    (void) nrec;
    (void) nchunk;
}

static void
reset_tag2idx(int n, ...)
{
    va_list tags;
    enum VSL_tag_e tag;
    int idx = 0;

    for (int i = 0; i < MAX_VSL_TAG; i++)
        tag2idx[i] = -1;
    va_start(tags, n);
    for (int i = 0; i < n; i++) {
        tag = va_arg(tags, enum VSL_tag_e);
        tag2idx[tag] = idx++;
    }
    va_end(tags);
    max_idx = idx;
}

static void
reset_hdrs(void)
{
    for (int i = 0; i < MAX_VSL_TAG; i++)
        if (hdr_trie[i] != NULL) {
            HDR_Fini(hdr_trie[i]);
            hdr_trie[i] = NULL;
        }
}

static void
add_hdr(enum VSL_tag_e tag, const char *hdr, int idx)
{
    hdr_trie[tag] = HDR_InsertIdx(hdr_trie[tag], hdr, idx);
    if (idx > hidx[tag])
        hidx[tag] = idx;
}

static void
init_rec_chunk(enum VSL_tag_e tag, rec_t *rec, chunk_t *chunk)
{
    rec->tag = tag;
    rec->magic = RECORD_MAGIC;
    rec->occupied = 1;
    VSTAILQ_INIT(&rec->chunks);
    VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
    chunk->magic = CHUNK_MAGIC;
    chunk->data = (char *) calloc(1, config.chunk_size);
}

static void
set_rec(tx_t *tx, enum VSL_tag_e tag, rec_t *rec)
{
    int idx = tag2idx[tag];
    tx->recs[idx]->rec = rec;
    rec->tag = tag;
}

static void
add_rec_chunk(tx_t *tx, enum VSL_tag_e tag, rec_t *rec, chunk_t *chunk)
{
    set_rec(tx, tag, rec);
    init_rec_chunk(tag, rec, chunk);
}

static void
init_tx(tx_t *tx, rec_node_t node[], rec_node_t *nptr[])
{
    tx->magic = TX_MAGIC;
    tx->recs = nptr;
    tx->state = TX_FORMATTING;
    for (int i = 0; i < max_idx; i++) {
        node[i].magic = REC_NODE_MAGIC;
        node[i].rec = NULL;
        node[i].hdrs = NULL;
        nptr[i] = &node[i];
    }
}

static void
init_tx_arg(tx_t *tx, rec_node_t node[], rec_node_t *nptr[], arg_t *args)
{
    init_tx(tx, node, nptr);
    args->name = NULL;
    args->tag = SLT__Bogus;
}

static void
set_record_data(rec_t *rec, chunk_t *chunk, const char *data,
                enum VSL_tag_e tag)
{
    rec->len = strlen(data) + 1;
    strcpy(chunk->data, data);
    if (tag != SLT__Bogus)
        rec->tag = tag;
    chunk->occupied = 1;
}

static void
add_record_data(tx_t *tx, enum VSL_tag_e tag, rec_t *rec, chunk_t *chunk,
                const char *data)
{
    add_rec_chunk(tx, tag, rec, chunk);
    set_record_data(rec, chunk, data, tag);
}

static void
init_hdr_recs(tx_t *tx, enum VSL_tag_e tag)
{
    int idx = tag2idx[tag];

    tx->recs[idx]->rec = NULL;
    tx->recs[idx]->hdrs = (rec_t **) calloc(HDR_N(hdr_trie[tag]),
                                            sizeof(rec_t *));
}

static void
set_hdr_rec(tx_t *tx, enum VSL_tag_e tag, int hdr_idx, rec_t *rec)
{
    int idx = tag2idx[tag];
    tx->recs[idx]->rec = NULL;
    tx->recs[idx]->hdrs[hdr_idx] = rec;
    rec->tag = tag;
}

static void
set_hdr_data(tx_t *tx, rec_t *rec, chunk_t *chunk, int hdr_idx,
             enum VSL_tag_e tag, const char *data)
{
    init_rec_chunk(tag, rec, chunk);
    set_record_data(rec, chunk, data, tag);
    set_hdr_rec(tx, tag, hdr_idx, rec);
}

static void
clear_rec(tx_t *tx, enum VSL_tag_e tag)
{
    int idx = tag2idx[tag];
    tx->recs[idx]->rec = NULL;
}

static void
clear_hdr(tx_t *tx, enum VSL_tag_e tag, int hdr_idx)
{
    int idx = tag2idx[tag];
    tx->recs[idx]->hdrs[hdr_idx] = NULL;
}

static inline void
set_arg_hdr_idx(arg_t *arg, enum VSL_tag_e tag, const char *hdr)
{
    arg->hdr_idx = HDR_FindIdx(hdr_trie[tag], hdr);
}

/* N.B.: Always run the tests in this order */
static const char
*test_format_init(void)
{
    char err[BUFSIZ];
    int status;

    printf("... initializing format tests\n");

    CONF_Init();
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    return NULL;
}

static const char
*test_format_get_payload(void)
{
    rec_t rec;
    chunk_t chunk;
    char *p;

    printf("... testing get_payload()\n");

    memset(&rec, 0, sizeof(rec_t));
    rec.magic = RECORD_MAGIC;
    rec.occupied = 1;
    VSTAILQ_INIT(&rec.chunks);
    memset(&chunk, 0, sizeof(chunk_t));
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    chunk.occupied = 1;
    MAN(chunk.data);

    /* Record with one chunk */
    rec.len = strlen(SHORT_STRING);
    strcpy(chunk.data, SHORT_STRING);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    p = get_payload(&rec);
    MASSERT(strcmp(p, SHORT_STRING) == 0);

    /* Record exactly at chunk_size */
    rec.len = config.chunk_size;
    sprintf(chunk.data, "%0*d", config.chunk_size - 1, 0);
    p = get_payload(&rec);
    char *str = (char *) malloc(config.chunk_size);
    MAN(str);
    sprintf(str, "%0*d", config.chunk_size - 1, 0);
    MASSERT(strcmp(p, str) == 0);
    free(str);

    /* Record with chunks that fill out shm_reclen */
    rec.len = config.max_reclen;
    int n = config.max_reclen;
    sprintf(chunk.data, "%0*d", config.chunk_size, 0);
    n -= config.chunk_size;
    while (n > 0) {
        int cp = n;
        if (cp > config.chunk_size)
            cp = config.chunk_size;
        chunk_t *c = (chunk_t *) malloc(sizeof(chunk_t));
        MAN(c);
        c->magic = CHUNK_MAGIC;
        c->data = (char *) calloc(1, config.chunk_size);
        sprintf(c->data, "%0*d", cp, 0);
        VSTAILQ_INSERT_TAIL(&rec.chunks, c, chunklist);
        n -= cp;
    }
    str = (char *) malloc(config.max_reclen);
    MAN(str);
    sprintf(str, "%0*d", config.max_reclen, 0);
    p = get_payload(&rec);
    MASSERT(strcmp(p, str) == 0);
    free(str);

    /* Empty record */
    rec.len = 0;
    *chunk.data = '\0';
    p = get_payload(&rec);
    MASSERT(strlen(p) == 0);

    return NULL;
}

static const char
*test_format_get_tag(void)
{
#define MAX_IDX 2
    tx_t tx;
    rec_node_t node[MAX_IDX], *n[MAX_IDX];
    rec_t recs[MAX_IDX], *rec;

    printf("... testing get_tag()\n");

    max_idx = MAX_IDX;
    for (int i = 0; i < MAX_VSL_TAG; i++)
        if (i < MAX_IDX)
            tag2idx[i] = i;
        else
            tag2idx[i] = -1;

    tx.magic = TX_MAGIC;
    tx.recs = n;
    tx.state = TX_FORMATTING;
    for (int i = 0; i < MAX_IDX; i++) {
        memset(&node[i], 0, sizeof(rec_node_t));
        memset(&recs[i], 0, sizeof(rec_t));
        recs[i].magic = RECORD_MAGIC;
        recs[i].tag = i;
        recs[i].occupied = 1;
        node[i].magic = REC_NODE_MAGIC;
        node[i].rec = &recs[i];
        node[i].hdrs = NULL;
        n[i] = &node[i];
    }

    for (int i = 0; i < MAX_IDX; i++) {
        rec = get_tag(&tx, i);
        MASSERT(rec == &recs[i]);
    }

    /* No such tag in tx */
    for (int i = MAX_IDX + 1; i < MAX_VSL_TAG; i++) {
        rec = get_tag(&tx, i);
        MAZ(rec);
    }

    /* Empty record */
    for (int i = 0; i < MAX_IDX; i++) {
        node[i].rec = NULL;
        rec = get_tag(&tx, i);
        MAZ(rec);
    }

    return NULL;
#undef MAX_IDX
}

static const char
*test_format_get_hdr(void)
{
#define MAX_IDX 1
#define NHDRS 5
    tx_t tx;
    const char *h[] = { "Bar", "Baz", "Foo", "Garply", "Xyzzy" };
    rec_node_t node[MAX_IDX], *n[MAX_IDX];
    rec_t recs[MAX_IDX * NHDRS], *rhdrs[MAX_IDX][NHDRS];
    chunk_t c[MAX_IDX * NHDRS], *c2;
    char *hdr, *exp;

    printf("... testing get_hdr()\n");

    max_idx = MAX_IDX;
    for (int i = 0; i < MAX_VSL_TAG; i++)
        if (i < MAX_IDX) {
            tag2idx[i] = i;
            for (int j = 0; j < NHDRS; j++)
                hdr_trie[i] = HDR_InsertIdx(hdr_trie[i], h[j], j);
            hidx[i] = NHDRS - 1;
        }
        else {
            tag2idx[i] = -1;
            hdr_trie[i] = NULL;
            hidx[i] = -1;
        }

    tx.magic = TX_MAGIC;
    tx.recs = n;
    tx.state = TX_FORMATTING;
    for (int i = 0; i < MAX_IDX; i++) {
        memset(&node[i], 0, sizeof(rec_node_t));
        node[i].magic = REC_NODE_MAGIC;
        node[i].rec = NULL;
        node[i].hdrs = rhdrs[i];
        for (int j = 0; j < NHDRS; j++) {
            int idx = i * NHDRS + j;
            MASSERT(idx < MAX_IDX * NHDRS);
            memset(&recs[idx], 0, sizeof(rec_t));
            memset(&c[idx], 0, sizeof(chunk_t));
            c[idx].magic = CHUNK_MAGIC;
            c[idx].data = (char *) calloc(1, config.chunk_size);
            c[idx].occupied = 1;
            recs[idx].magic = RECORD_MAGIC;
            recs[idx].occupied = 1;
            VSTAILQ_INIT(&recs[idx].chunks);
            VSTAILQ_INSERT_TAIL(&recs[idx].chunks, &c[idx], chunklist);
            node[i].hdrs[j] = NULL;
        }
        n[i] = &node[i];
    }

    recs[0].tag = 0;
    recs[0].len = strlen("Foo: quux");
    strcpy(c[0].data, "Foo: quux");
    tx.recs[0]->hdrs[2] = &recs[0];
    hdr = get_hdr(&tx, 0, 2);
    MAN(hdr);
    MASSERT(strcmp(hdr, "quux") == 0);

    /* Ignore whitespace */
    recs[0].len = strlen("  Foo  :  quux");
    strcpy(c[0].data, "  Foo  :  quux");
    hdr = get_hdr(&tx, 0, 2);
    MAN(hdr);
    MASSERT(strcmp(hdr, "quux") == 0);

    /* Multiple headers in tx */
    recs[0].len = strlen("Foo: h0");
    strcpy(c[0].data, "Foo: h0");
    recs[1].len = strlen("Bar: h1");
    strcpy(c[1].data, "Bar: h1");
    tx.recs[0]->hdrs[0] = &recs[1];
    recs[2].len = strlen("Baz: h2");
    strcpy(c[2].data, "Baz: h2");
    tx.recs[0]->hdrs[1] = &recs[2];
    recs[3].len = strlen("Garply: h3");
    strcpy(c[3].data, "Garply: h3");
    tx.recs[0]->hdrs[3] = &recs[3];
    recs[4].len = strlen("Xyzzy: h4");
    strcpy(c[4].data, "Xyzzy: h4");
    tx.recs[0]->hdrs[4] = &recs[4];

    hdr = get_hdr(&tx, 0, 2);
    MAN(hdr);
    MASSERT(strcmp(hdr, "h0") == 0);
    hdr = get_hdr(&tx, 0, 0);
    MAN(hdr);
    MASSERT(strcmp(hdr, "h1") == 0);
    hdr = get_hdr(&tx, 0, 1);
    MAN(hdr);
    MASSERT(strcmp(hdr, "h2") == 0);
    hdr = get_hdr(&tx, 0, 3);
    MAN(hdr);
    MASSERT(strcmp(hdr, "h3") == 0);
    hdr = get_hdr(&tx, 0, 4);
    MAN(hdr);
    MASSERT(strcmp(hdr, "h4") == 0);

    /* Header spans more than one chunk */
    memset(c[4].data + strlen("Xyzzy: "), 'x',
           config.chunk_size - strlen("Xyzzy: "));
    c2 = (chunk_t *) calloc(1, sizeof(chunk_t));
    MAN(c2);
    c2->magic = CHUNK_MAGIC;
    c2->data = (char *) calloc(1, config.chunk_size);
    MAN(c2->data);
    memset(c2->data, 'x', config.chunk_size);
    c2->occupied = 1;
    VSTAILQ_INSERT_TAIL(&recs[4].chunks, c2, chunklist);
    recs[4].len = config.chunk_size * 2;
    hdr = get_hdr(&tx, 0, 4);
    MAN(hdr);
    int len = 2 * config.chunk_size - strlen("Xyzzy: ");
    exp = (char *) malloc(len);
    MAN(exp);
    memset(exp, 'x', len);
    MASSERT(memcmp(hdr, exp, len) == 0);

    /* header not in tx */
    node[0].hdrs[4] = NULL;
    hdr = get_hdr(&tx, 0, 4);
    MAZ(hdr);

    return NULL;
#undef MAX_IDX
}

static const char
*test_format_get_fld(void)
{
    char *fld, str[sizeof(SHORT_STRING)];
    size_t len;

    printf("... testing get_fld()\n");

    strcpy(str, SHORT_STRING);
    fld = get_fld(str, 0, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "foo", len) == 0);

    strcpy(str, SHORT_STRING);
    fld = get_fld(str, 1, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "bar", len) == 0);

    strcpy(str, SHORT_STRING);
    fld = get_fld(str, 2, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "baz", len) == 0);

    strcpy(str, SHORT_STRING);
    fld = get_fld(str, 3, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "quux", len) == 0);

    strcpy(str, SHORT_STRING);
    fld = get_fld(str, 4, &len);
    MAZ(strlen(fld));

    strcpy(str, "   ");
    fld = get_fld(str, 0, &len);
    MAZ(strlen(fld));
    fld = get_fld(str, 1, &len);
    MAZ(strlen(fld));
    fld = get_fld(str, 2, &len);
    MAZ(strlen(fld));

    return NULL;
}

static const char
*test_format_get_rec_fld(void)
{
    rec_t rec;
    chunk_t chunk;
    char *fld;
    size_t len;

    printf("... testing get_rec_fld()\n");

    memset(&rec, 0, sizeof(rec_t));
    memset(&chunk, 0, sizeof(chunk_t));

    rec.magic = RECORD_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    rec.occupied = 1;
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    chunk.occupied = 1;
    MAN(chunk.data);
    rec.len = strlen(SHORT_STRING);
    strcpy(chunk.data, SHORT_STRING);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);

    fld = get_rec_fld(&rec, 0, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "foo", len) == 0);

    strcpy(chunk.data, SHORT_STRING);
    fld = get_rec_fld(&rec, 1, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "bar", len) == 0);

    strcpy(chunk.data, SHORT_STRING);
    fld = get_rec_fld(&rec, 2, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "baz", len) == 0);

    strcpy(chunk.data, SHORT_STRING);
    fld = get_rec_fld(&rec, 3, &len);
    MAN(fld);
    MASSERT(strncmp(fld, "quux", len) == 0);

    strcpy(chunk.data, SHORT_STRING);
    fld = get_rec_fld(&rec, 4, &len);
    MAZ(strlen(fld));

    rec.len = strlen("     ");
    strcpy(chunk.data, "     ");
    fld = get_rec_fld(&rec, 0, &len);
    MAZ(strlen(fld));
    fld = get_rec_fld(&rec, 1, &len);
    MAZ(strlen(fld));
    fld = get_rec_fld(&rec, 2, &len);
    MAZ(strlen(fld));

    return NULL;
}

static const char
*test_format_b(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec1, rec2;
    chunk_t c1, c2;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_b_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqAcct, SLT_BereqAcct);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define REQACCT_PAYLOAD "60 0 60 178 105 283"
    add_record_data(&tx, SLT_ReqAcct, &rec1, &c1, REQACCT_PAYLOAD);
    add_record_data(&tx, SLT_BereqAcct, &rec2, &c2, REQACCT_PAYLOAD);

    format_b_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    format_b_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    return NULL;
#undef NTAGS
}

static const char
*test_format_D(void)
{
#define NTAGS 1
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t r1, r2;
    chunk_t c1, c2;
    arg_t args;
    char *str = NULL;
    size_t len;

    printf("... testing format_D_*()\n");

    reset_tag2idx(NTAGS, SLT_Timestamp);
    MASSERT(max_idx == NTAGS);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "BerespBody", 0);
    add_hdr(SLT_Timestamp, "Resp", 1);

    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);

#define TS_RESP_PAYLOAD "Resp: 1427799478.166798 0.015963 0.000125"
    init_rec_chunk(SLT_Timestamp, &r1, &c1);
    set_record_data(&r1, &c1, TS_RESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 1, &r1);
    set_arg_hdr_idx(&args, SLT_Timestamp, "Resp:");
    format_D_client(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "15963", 5) == 0);
    MASSERT(len == 5);

#define TS_BERESP_PAYLOAD "BerespBody: 1427799478.166678 0.015703 0.000282"
    init_rec_chunk(SLT_Timestamp, &r2, &c2);
    set_record_data(&r2, &c2, TS_BERESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &r2);
    set_arg_hdr_idx(&args, SLT_Timestamp, "BerespBody:");
    str = NULL;
    len = 0;
    format_D_backend(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "15703", 5) == 0);
    MASSERT(len == 5);

    return NULL;
#undef NTAGS
}

static const char
*test_format_H(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec1, rec2;
    chunk_t c1, c2;
    arg_t args;
    char *str;
    size_t len, explen;

    printf("... testing format_H_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqProtocol, SLT_BereqProtocol);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define PROTOCOL_PAYLOAD "HTTP/1.1"
    add_record_data(&tx, SLT_ReqProtocol, &rec1, &c1, PROTOCOL_PAYLOAD);
    add_record_data(&tx, SLT_BereqProtocol, &rec2, &c2, PROTOCOL_PAYLOAD);

    format_H_client(&tx, &args, &str, &len);
    explen = strlen(PROTOCOL_PAYLOAD);
    MASSERT(strncmp(str, PROTOCOL_PAYLOAD, explen) == 0);
    MASSERT(len == explen);

    format_H_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, PROTOCOL_PAYLOAD, explen) == 0);
    MASSERT(len == explen);

    return NULL;
#undef NTAGS
}

static const char
*test_format_h(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec1, rec2;
    chunk_t c1, c2;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_h_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqStart, SLT_Backend);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define REQSTART_PAYLOAD "127.0.0.1 33544"
    add_record_data(&tx, SLT_ReqStart, &rec1, &c1, REQSTART_PAYLOAD);
    format_h_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "127.0.0.1", 9) == 0);
    MASSERT(len == 9);

#define BACKEND_PAYLOAD "14 default default(127.0.0.1,,80)"
    add_record_data(&tx, SLT_Backend, &rec2, &c2, BACKEND_PAYLOAD);
    format_h_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "default(127.0.0.1,,80)", 22) == 0);
    MASSERT(len == 22);

    return NULL;
#undef NTAGS
}

static const char
*test_format_I(void)
{
#define NTAGS 3
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[2];
    chunk_t c[2];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_I_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqAcct, SLT_BereqAcct, SLT_PipeAcct);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

    add_record_data(&tx, SLT_ReqAcct, &rec[0], &c[0], REQACCT_PAYLOAD);
    format_I_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "60", 2) == 0);
    MASSERT(len == 2);

    add_record_data(&tx, SLT_BereqAcct, &rec[1], &c[1], REQACCT_PAYLOAD);
    format_I_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "283", 3) == 0);
    MASSERT(len == 3);

#define PIPEACCT_PAYLOAD "60 60 178 105"
    clear_rec(&tx, SLT_ReqAcct);
    add_record_data(&tx, SLT_PipeAcct, &rec[0], &c[0], PIPEACCT_PAYLOAD);
    format_I_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "178", 3) == 0);
    MASSERT(len == 3);

    return NULL;
#undef NTAGS
}

static const char
*test_format_m(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[NTAGS];
    chunk_t c[NTAGS];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_m_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqMethod, SLT_BereqMethod);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define REQMETHOD_PAYLOAD "GET"
    add_record_data(&tx, SLT_ReqMethod, &rec[0], &c[0], REQMETHOD_PAYLOAD);
    format_m_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET", 3) == 0);
    MASSERT(len == 3);

    add_record_data(&tx, SLT_BereqMethod, &rec[1], &c[1], REQMETHOD_PAYLOAD);
    format_m_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET", 3) == 0);
    MASSERT(len == 3);

    return NULL;
#undef NTAGS
}

static const char
*test_format_O(void)
{
#define NTAGS 3
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[2];
    chunk_t c[2];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_O_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqAcct, SLT_BereqAcct, SLT_PipeAcct);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

    add_record_data(&tx, SLT_ReqAcct, &rec[0], &c[0], REQACCT_PAYLOAD);
    format_O_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "283", 3) == 0);
    MASSERT(len == 3);

    add_record_data(&tx, SLT_BereqAcct, &rec[1], &c[1], REQACCT_PAYLOAD);
    format_O_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "60", 2) == 0);
    MASSERT(len == 2);

    clear_rec(&tx, SLT_ReqAcct);
    add_record_data(&tx, SLT_PipeAcct, &rec[0], &c[0], PIPEACCT_PAYLOAD);
    format_O_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    return NULL;
#undef NTAGS
}

static const char
*test_format_q(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[NTAGS];
    chunk_t c[NTAGS];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_q_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqURL, SLT_BereqURL);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define URL_QUERY_PAYLOAD "/foo?bar=baz&quux=wilco"
    add_record_data(&tx, SLT_ReqURL, &rec[0], &c[0], URL_QUERY_PAYLOAD);
    format_q_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar=baz&quux=wilco", 18) == 0);
    MASSERT(len == 18);

    add_record_data(&tx, SLT_BereqURL, &rec[1], &c[1], URL_QUERY_PAYLOAD);
    format_q_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar=baz&quux=wilco", 18) == 0);
    MASSERT(len == 18);

#define URL_PAYLOAD "/foo"
    set_record_data(&rec[0], &c[0], URL_PAYLOAD, SLT_ReqURL);
    str = NULL;
    len = 0;
    format_q_client(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    set_record_data(&rec[1], &c[1], URL_PAYLOAD, SLT_BereqURL);
    format_q_backend(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    return NULL;
#undef NTAGS
}

static const char
*test_format_r(void)
{
#define NTAGS 8
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec_method, rec_host, rec_url, rec_proto;
    chunk_t chunk_method, chunk_host, chunk_url, chunk_proto;
    arg_t cargs, bargs;
    char *str;
    size_t len;

    printf("... testing format_r_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqMethod, SLT_ReqHeader, SLT_ReqURL,
                  SLT_ReqProtocol, SLT_BereqMethod, SLT_BereqHeader,
                  SLT_BereqURL, SLT_BereqProtocol);
    MASSERT(max_idx == NTAGS);
    reset_hdrs();
    add_hdr(SLT_ReqHeader, "Host", 0);
    add_hdr(SLT_BereqHeader, "Host", 0);
    init_tx(&tx, node, nptr);
    init_hdr_recs(&tx, SLT_ReqHeader);
    init_hdr_recs(&tx, SLT_BereqHeader);
    set_arg_hdr_idx(&cargs, SLT_ReqHeader, "Host:");
    set_arg_hdr_idx(&bargs, SLT_BereqHeader, "Host:");

    add_record_data(&tx, SLT_ReqMethod, &rec_method, &chunk_method, "GET");
    init_rec_chunk(SLT_ReqHeader, &rec_host, &chunk_host);
    set_record_data(&rec_host, &chunk_host, "Host: www.foobar.com",
                    SLT_ReqHeader);
    set_hdr_rec(&tx, SLT_ReqHeader, 0, &rec_host);
    add_record_data(&tx, SLT_ReqURL, &rec_url, &chunk_url, URL_PAYLOAD);
    add_record_data(&tx, SLT_ReqProtocol, &rec_proto, &chunk_proto,
                    PROTOCOL_PAYLOAD);
    format_r_client(&tx, &cargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.1", 38) == 0);
    MASSERT(len == 38);

    set_record_data(&rec_method, &chunk_method, "GET", SLT_BereqMethod);
    set_rec(&tx, SLT_BereqMethod, &rec_method);
    set_record_data(&rec_host, &chunk_host, "Host: www.foobar.com",
                    SLT_BereqHeader);
    set_hdr_rec(&tx, SLT_BereqHeader, 0, &rec_host);
    set_record_data(&rec_url, &chunk_url, URL_PAYLOAD, SLT_BereqURL);
    set_rec(&tx, SLT_BereqURL, &rec_url);
    set_record_data(&rec_proto, &chunk_proto, PROTOCOL_PAYLOAD,
                    SLT_BereqProtocol);
    set_rec(&tx, SLT_BereqProtocol, &rec_proto);
    format_r_backend(&tx, &bargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.1", 38) == 0);
    MASSERT(len == 38);

    /* No method record */
    clear_rec(&tx, SLT_ReqMethod);
    rec_host.tag = SLT_ReqHeader;
    rec_url.tag = SLT_ReqURL;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &cargs, &str, &len);
    MASSERT(strncmp(str, "- http://www.foobar.com/foo HTTP/1.1", 36) == 0);
    MASSERT(len == 36);

    clear_rec(&tx, SLT_BereqMethod);
    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &bargs, &str, &len);
    MASSERT(strncmp(str, "- http://www.foobar.com/foo HTTP/1.1" ,36) == 0);
    MASSERT(len == 36);

    /* No host header */
    set_rec(&tx, SLT_ReqMethod, &rec_method);
    clear_hdr(&tx, SLT_ReqHeader, 0);
    rec_url.tag = SLT_ReqURL;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &cargs, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    set_rec(&tx, SLT_BereqMethod, &rec_method);
    clear_hdr(&tx, SLT_BereqHeader, 0);
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &bargs, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    /* No URL record */
    rec_method.tag = SLT_ReqMethod;
    clear_rec(&tx, SLT_ReqURL);
    set_hdr_rec(&tx, SLT_ReqHeader, 0, &rec_host);
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &cargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com- HTTP/1.1", 35) == 0);
    MASSERT(len == 35);

    rec_method.tag = SLT_BereqMethod;
    clear_rec(&tx, SLT_BereqURL);
    set_hdr_rec(&tx, SLT_BereqHeader, 0, &rec_host);
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &bargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com- HTTP/1.1", 35) == 0);
    MASSERT(len == 35);

    /* Proto record empty */
    rec_method.tag = SLT_ReqMethod;
    rec_host.tag = SLT_ReqHeader;
    set_rec(&tx, SLT_ReqURL, &rec_url);
    clear_rec(&tx, SLT_ReqProtocol);
    format_r_client(&tx, &cargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.0", 38) == 0);
    MASSERT(len == 38);

    rec_method.tag = SLT_BereqMethod;
    rec_host.tag = SLT_BereqHeader;
    set_rec(&tx, SLT_BereqURL, &rec_url);
    clear_rec(&tx, SLT_BereqProtocol);
    format_r_backend(&tx, &bargs, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.0", 38) == 0);
    MASSERT(len == 38);

    return NULL;
#undef NTAGS
}

static const char
*test_format_s(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[NTAGS];
    chunk_t c[NTAGS];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_s_*()\n");

    reset_tag2idx(NTAGS, SLT_RespStatus, SLT_BerespStatus);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

#define STATUS_PAYLOAD "200"
    add_record_data(&tx, SLT_RespStatus, &rec[0], &c[0], STATUS_PAYLOAD);
    format_s_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, STATUS_PAYLOAD, 3) == 0);
    MASSERT(len == 3);

    add_record_data(&tx, SLT_BerespStatus, &rec[1], &c[1], STATUS_PAYLOAD);
    format_s_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, STATUS_PAYLOAD, 3) == 0);
    MASSERT(len == 3);

    return NULL;
#undef NTAGS
}

static const char
*test_format_t(void)
{
#define NTAGS 1
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str = NULL, strftime_s[BUFSIZ], fmt[] = "[%d/%b/%Y:%T %z]";
    size_t len, explen;
    struct tm *tm;
    time_t t = 1427743146;

    printf("... testing format_t()\n");

    reset_tag2idx(NTAGS, SLT_Timestamp);
    MASSERT(max_idx == NTAGS);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "Start", 0);

    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);

#define T1 "Start: 1427743146.529143 0.000000 0.000000"
    init_rec_chunk(SLT_Timestamp, &rec, &chunk);
    set_record_data(&rec, &chunk, T1, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &rec);
    tm = localtime(&t);
    MAN(strftime(strftime_s, config.max_reclen, fmt, tm));
    set_arg_hdr_idx(&args, SLT_Timestamp, "Start:");
    format_t(&tx, &args, &str, &len);
    MAN(str);
    explen = strlen(strftime_s);
    VMASSERT(strncmp(str, strftime_s, explen) == 0, "'%s' != '%s'", str,
             strftime_s);
    MASSERT(len == explen);

    return NULL;
#undef NTAGS
}

static const char
*test_format_T(void)
{
#define NTAGS 1
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t r1, r2;
    chunk_t c1, c2;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_T_*()\n");

    reset_tag2idx(NTAGS, SLT_Timestamp);
    MASSERT(max_idx == NTAGS);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "BerespBody", 0);
    add_hdr(SLT_Timestamp, "Resp", 1);

    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);

    init_rec_chunk(SLT_Timestamp, &r1, &c1);
    set_record_data(&r1, &c1, TS_RESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 1, &r1);
    set_arg_hdr_idx(&args, SLT_Timestamp, "Resp:");
    format_T_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0", 1) == 0);
    MASSERT(len == 1);

    init_rec_chunk(SLT_Timestamp, &r2, &c2);
    set_record_data(&r2, &c2, TS_BERESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &r2);
    set_arg_hdr_idx(&args, SLT_Timestamp, "BerespBody:");
    format_T_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0", 1) == 0);
    MASSERT(len == 1);

    return NULL;
#undef NTAGS
}

static const char
*test_format_U(void)
{
#define NTAGS 2
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[NTAGS];
    chunk_t c[NTAGS];
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_U_*()\n");

    reset_tag2idx(NTAGS, SLT_ReqURL, SLT_BereqURL);
    MASSERT(max_idx == NTAGS);
    init_tx_arg(&tx, node, nptr, &args);

    /* With query string */
    add_record_data(&tx, SLT_ReqURL, &rec[0], &c[0], URL_QUERY_PAYLOAD);
    format_U_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    add_record_data(&tx, SLT_BereqURL, &rec[1], &c[1], URL_QUERY_PAYLOAD);
    format_U_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    /* Without query string */
    set_record_data(&rec[0], &c[0], URL_PAYLOAD, SLT_ReqURL);
    format_U_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    set_record_data(&rec[1], &c[1], URL_PAYLOAD, SLT_BereqURL);
    format_U_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    return NULL;
#undef NTAGS
}

static const char
*test_format_u(void)
{
    tx_t tx;
    rec_node_t node[2], *nptr[2];
    rec_t rec_req, rec_bereq;
    chunk_t chunk_req, chunk_bereq;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_u_*()\n");

    reset_tag2idx(2, SLT_ReqHeader, SLT_BereqHeader);
    MASSERT(max_idx == 2);
    reset_hdrs();
    add_hdr(SLT_ReqHeader, "Authorization", 0);
    add_hdr(SLT_BereqHeader, "Authorization", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_ReqHeader);
    init_hdr_recs(&tx, SLT_BereqHeader);
    args.hdr_idx = 0;

#define BASIC_AUTH_PAYLOAD "Authorization: Basic dmFybmlzaDo0ZXZlcg=="
    init_rec_chunk(SLT_ReqHeader, &rec_req, &chunk_req);
    set_record_data(&rec_req, &chunk_req, BASIC_AUTH_PAYLOAD, SLT_ReqHeader);
    set_hdr_rec(&tx, SLT_ReqHeader, 0, &rec_req);
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "varnish", 7) == 0);
    MASSERT(len == 7);

    init_rec_chunk(SLT_BereqHeader, &rec_bereq, &chunk_bereq);
    set_record_data(&rec_bereq, &chunk_bereq, BASIC_AUTH_PAYLOAD,
                    SLT_BereqHeader);
    set_hdr_rec(&tx, SLT_BereqHeader, 0, &rec_bereq);
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "varnish", 7) == 0);
    MASSERT(len == 7);

    /* No header record */
    clear_hdr(&tx, SLT_ReqHeader, 0);
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    clear_hdr(&tx, SLT_BereqHeader, 0);
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    /* No basic auth header
     * Not a real example of a digest auth header, but kept short, so
     * that we can test with only one chunk.
     */
#define DIGEST_AUTH_PAYLOAD "Authorization: Digest username=\"Mufasa\", realm=\"realm@host.com\""
    set_record_data(&rec_req, &chunk_req, DIGEST_AUTH_PAYLOAD, SLT_ReqHeader);
    set_hdr_rec(&tx, SLT_ReqHeader, 0, &rec_req);
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    set_record_data(&rec_bereq, &chunk_bereq, DIGEST_AUTH_PAYLOAD,
                    SLT_BereqHeader);
    set_hdr_rec(&tx, SLT_BereqHeader, 0, &rec_bereq);
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    return NULL;
}

static const char
*test_format_Xi(void)
{
    tx_t tx;
    rec_node_t node[2], *nptr[2];
    rec_t rec_req, rec_bereq;
    chunk_t chunk_req, chunk_bereq;
    arg_t args;
    char *str, hdr[] = "Foo:";
    size_t len;

    printf("... testing format_Xi_*()\n");

    reset_tag2idx(2, SLT_ReqHeader, SLT_BereqHeader);
    MASSERT(max_idx == 2);
    reset_hdrs();
    add_hdr(SLT_ReqHeader, "Foo", 0);
    add_hdr(SLT_BereqHeader, "Foo", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_ReqHeader);
    init_hdr_recs(&tx, SLT_BereqHeader);
    args.name = hdr;

    init_rec_chunk(SLT_ReqHeader, &rec_req, &chunk_req);
    set_record_data(&rec_req, &chunk_req, "Foo: bar", SLT_ReqHeader);
    set_hdr_rec(&tx, SLT_ReqHeader, 0, &rec_req);
    format_Xi_client(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    init_rec_chunk(SLT_BereqHeader, &rec_bereq, &chunk_bereq);
    set_record_data(&rec_bereq, &chunk_bereq, "Foo: bar", SLT_BereqHeader);
    set_hdr_rec(&tx, SLT_BereqHeader, 0, &rec_bereq);
    format_Xi_backend(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_Xo(void)
{
    tx_t tx;
    rec_node_t node[2], *nptr[2];
    rec_t rec_resp, rec_beresp;
    chunk_t chunk_resp, chunk_beresp;
    arg_t args;
    char *str, hdr[] = "Baz:";
    size_t len;

    printf("... testing format_Xo_*()\n");

    reset_tag2idx(2, SLT_RespHeader, SLT_BerespHeader);
    MASSERT(max_idx == 2);
    reset_hdrs();
    add_hdr(SLT_RespHeader, "Baz", 0);
    add_hdr(SLT_BerespHeader, "Baz", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_RespHeader);
    init_hdr_recs(&tx, SLT_BerespHeader);
    args.name = hdr;

    init_rec_chunk(SLT_RespHeader, &rec_resp, &chunk_resp);
    set_record_data(&rec_resp, &chunk_resp, "Baz: quux", SLT_RespHeader);
    set_hdr_rec(&tx, SLT_RespHeader, 0, &rec_resp);
    format_Xo_client(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "quux", 4) == 0);
    MASSERT(len == 4);

    init_rec_chunk(SLT_BerespHeader, &rec_beresp, &chunk_beresp);
    set_record_data(&rec_beresp, &chunk_beresp, "Baz: quux", SLT_BerespHeader);
    set_hdr_rec(&tx, SLT_BerespHeader, 0, &rec_beresp);
    format_Xo_backend(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "quux", 4) == 0);
    MASSERT(len == 4);

    return NULL;
}

static const char
*test_format_Xt(void)
{
    tx_t tx;
    rec_node_t node[1], *nptr[1];
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str = NULL, strftime_s[BUFSIZ];
    size_t len, explen;
    char fmt[] =
        "%a %A %b %B %c %C %d %D %e %F %g %G %h %H %I %j %m %M %n %p %r %R %S "\
        "%t %T %u %U %V %w %W %x %X %y %Y %z %Z %%";
    char afmt[] =
        "%Ec %EC %Ex %EX %Ey %Ey %Od %Oe %OH %OI %Om %OM %OS %Ou %OU %OV %Ow "\
        "%OW %Oy";
    char subs[] = "%i";
    struct tm *tm;
    time_t t = 1427743146;

    printf("... testing format_Xt()\n");

    reset_tag2idx(1, SLT_Timestamp);
    MASSERT(max_idx == 1);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "Start", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);
    set_arg_hdr_idx(&args, SLT_Timestamp, "Start:");

    init_rec_chunk(SLT_Timestamp, &rec, &chunk);
    set_record_data(&rec, &chunk, T1, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &rec);
    tm = localtime(&t);
    MAN(strftime(strftime_s, config.max_reclen, fmt, tm));
    explen = strlen(strftime_s);
    args.name = fmt;
    format_Xt(&tx, &args, &str, &len);
    MAN(str);
    VMASSERT(strncmp(str, strftime_s, explen) == 0, "'%s' != '%s'", str,
             strftime_s);
    MASSERT(len == explen);

    /* Alternative strftime formatters */
    MAN(strftime(strftime_s, config.max_reclen, afmt, tm));
    explen = strlen(strftime_s);
    args.name = afmt;
    format_Xt(&tx, &args, &str, &len);
    MAN(str);
    VMASSERT(strncmp(str, strftime_s, explen) == 0, "'%s' != '%s'", str,
             strftime_s);
    MASSERT(len == explen);

    /* subsecond formatter */
    args.name = subs;
    format_Xt(&tx, &args, &str, &len);
    MAN(str);
    /* us accuracy ... */
    VMASSERT(strncmp(str, "529143", 6) == 0, "'%s' != '529143'", str);
    MASSERT(len == 6);

    return NULL;
}

static const char
*test_format_Xttfb(void)
{
    tx_t tx;
    rec_node_t node[2], *nptr[2];
    rec_t rec_req, rec_bereq;
    chunk_t chunk_req, chunk_bereq;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_Xttfb_*()\n");

    reset_tag2idx(1, SLT_Timestamp);
    MASSERT(max_idx == 1);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "Beresp", 0);
    add_hdr(SLT_Timestamp, "Process", 1);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);

#define TS_PROCESS_PAYLOAD "Process: 1427979230.712416 0.000166 0.000166"
    init_rec_chunk(SLT_Timestamp, &rec_req, &chunk_req);
    set_record_data(&rec_req, &chunk_req, TS_PROCESS_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 1, &rec_req);
    set_arg_hdr_idx(&args, SLT_Timestamp, "Process:");
    format_Xttfb_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0.000166", 8) == 0);
    MASSERT(len == 8);

#define TS_BERESP_HDR_PAYLOAD "Beresp: 1427979243.588828 0.002837 0.002743"
    init_rec_chunk(SLT_Timestamp, &rec_bereq, &chunk_bereq);
    set_record_data(&rec_bereq, &chunk_bereq, TS_BERESP_HDR_PAYLOAD,
                    SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &rec_bereq);
    set_arg_hdr_idx(&args, SLT_Timestamp, "Beresp:");
    format_Xttfb_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0.002837", 8) == 0);
    MASSERT(len == 8);

    return NULL;
}

static const char
*test_format_VCL_disp(void)
{
    tx_t tx;
    arg_t args;
    char *str, hitmiss[] = "m", handling[] = "n";
    size_t len;

    printf("... testing format_VCL_disp()\n");

    tx.magic = TX_MAGIC;

    /* %{Varnish:hitmiss} for a hit */
    tx.disp = DISP_HIT;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "hit", 3) == 0);
    MASSERT(len == 3);

    /* %{Varnish:handling} for a hit */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "hit", 3) == 0);
    MASSERT(len == 3);

    /* %{Varnish:hitmiss} for a miss */
    tx.disp = DISP_MISS;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "miss", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:handling} for a miss */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "miss", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:hitmiss} for a pass */
    tx.disp = DISP_PASS;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "miss", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:handling} for a pass */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "pass", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:hitmiss} for an error */
    tx.disp = DISP_ERROR;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "miss", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:handling} for an error */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "error", 5) == 0);
    MASSERT(len == 5);

    /* %{Varnish:hitmiss} for none of the above */
    tx.disp = DISP_NONE;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    /* %{Varnish:handling} for noe of the above */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    /* %{Varnish:hitmiss} for a pipe */
    tx.disp = DISP_PIPE;
    args.name = hitmiss;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "miss", 4) == 0);
    MASSERT(len == 4);

    /* %{Varnish:handling} for an pipe */
    args.name = handling;
    format_VCL_disp(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "pipe", 4) == 0);
    MASSERT(len == 4);

    return NULL;
}

static const char
*test_format_VCL_Log(void)
{
    tx_t tx;
    rec_node_t node[1], *nptr[1];
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str, hdr[] = "foo:";
    size_t len;

    printf("... testing format_VCL_Log()\n");

    reset_tag2idx(1, SLT_VCL_Log);
    MASSERT(max_idx == 1);
    reset_hdrs();
    add_hdr(SLT_VCL_Log, "foo", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_VCL_Log);
    args.name = hdr;

    init_rec_chunk(SLT_VCL_Log, &rec, &chunk);
    set_record_data(&rec, &chunk, "foo: bar", SLT_VCL_Log);
    set_hdr_rec(&tx, SLT_VCL_Log, 0, &rec);
    set_arg_hdr_idx(&args, SLT_VCL_Log, "foo:");
    format_VCL_Log(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    /* No match */
    clear_hdr(&tx, SLT_VCL_Log, 0);
    str = NULL;
    len = 0;
    format_VCL_Log(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    return NULL;
}

static const char
*test_format_SLT(void)
{
    tx_t tx;
    rec_node_t node[2], *nptr[2];
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str = NULL, *substr;
    size_t len = 0;

    printf("... testing format_SLT()\n");

    reset_tag2idx(1, SLT_FetchError);
    MASSERT(max_idx == 1);
    init_tx_arg(&tx, node, nptr, &args);

    add_record_data(&tx, SLT_FetchError, &rec, &chunk, "no backend connection");
    args.tag = SLT_FetchError;
    args.fld = -1;
    args.hdr_idx = -1;
    format_SLT(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, "no backend connection", 21) == 0);
    MASSERT(len == 21);

    /* record not found */
    reset_tag2idx(2, SLT_FetchError, SLT_BereqHeader);
    MASSERT(max_idx == 2);
    init_tx(&tx, node, nptr);
    add_record_data(&tx, SLT_BereqHeader, &rec, &chunk, "Foo: bar");
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    /* Binary tag with non-printables in the payload */
    reset_tag2idx(1, SLT_Debug);
    MASSERT(max_idx == 1);
    init_tx(&tx, node, nptr);
    add_record_data(&tx, SLT_Debug, &rec, &chunk, "");
    memcpy(chunk.data, "foo\0\xFF bar\0\\\"\n\r\t", 16);
    rec.len = 16;
    str = NULL;
    len = 0;
    args.tag = SLT_Debug;
    format_SLT(&tx, &args, &str, &len);
    MAN(str);
#define EXP_SLT_BINARY "\"foo\\0\\377 bar\\0\\\\\\\"\\n\\r\\t\""
    VMASSERT(strncmp(str, EXP_SLT_BINARY, strlen(EXP_SLT_BINARY)) == 0,
             "format_SLT with binary data: Expected '%s', got '%s'",
             EXP_SLT_BINARY, str);
    MASSERT(len == strlen(EXP_SLT_BINARY));

    /* Binary tag with no non-printables in the payload */
    reset_tag2idx(1, SLT_Debug);
    MASSERT(max_idx == 1);
    init_tx(&tx, node, nptr);
    add_record_data(&tx, SLT_Debug, &rec, &chunk, "RES_MODE 2");
    str = NULL;
    len = 0;
    args.tag = SLT_Debug;
    format_SLT(&tx, &args, &str, &len);
    MAN(str);
#define EXP_SLT "RES_MODE 2"
    VMASSERT(strcmp(str, EXP_SLT) == 0,
             "format_SLT with no binary data: Expected '%s', got '%s'",
             EXP_SLT, str);
    MASSERT(len == strlen(EXP_SLT));

    /* header selector */
    reset_tag2idx(1, SLT_Timestamp);
    MASSERT(max_idx == 1);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "Resp", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);
    init_rec_chunk(SLT_Timestamp, &rec, &chunk);
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &rec);
    args.tag = SLT_Timestamp;
    set_arg_hdr_idx(&args, SLT_Timestamp, "Resp:");
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAN(str);
    substr = strstr(TS_RESP_PAYLOAD, "14");
    MASSERT(strncmp(str, substr, strlen(substr)) == 0);
    MASSERT(len == strlen(substr));

    /* field selector */
    reset_tag2idx(1, SLT_ReqAcct);
    MASSERT(max_idx == 1);
    init_tx_arg(&tx, node, nptr, &args);
    add_record_data(&tx, SLT_ReqAcct, &rec, &chunk, "277 0 277 319 0 319");
    args.tag = SLT_ReqAcct;
    args.fld = 3;
    args.hdr_idx = -1;
    format_SLT(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "319", 3) == 0);
    MASSERT(len == 3);

    /* field not found */
    args.fld = 6;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAZ(len);
    
    /* header and field selector */
    reset_tag2idx(1, SLT_Timestamp);
    MASSERT(max_idx == 1);
    reset_hdrs();
    add_hdr(SLT_Timestamp, "Resp", 0);
    init_tx_arg(&tx, node, nptr, &args);
    init_hdr_recs(&tx, SLT_Timestamp);
    init_rec_chunk(SLT_Timestamp, &rec, &chunk);
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    set_hdr_rec(&tx, SLT_Timestamp, 0, &rec);
    args.tag = SLT_Timestamp;
    set_arg_hdr_idx(&args, SLT_Timestamp, "Resp:");
    args.fld = 0;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAN(str);
    MASSERT(strncmp(str, substr, len) == 0);
    MASSERT(len == strlen("1427799478.166798"));

    /* header not found */
    set_arg_hdr_idx(&args, SLT_Timestamp, "Foo:");
    args.fld = -1;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);
    
    /* header field not found */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    args.name = strdup("Resp");
    args.fld = 3;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAZ(len);
    
    return NULL;
}

static const char
*test_format_p_vxid(void)
{
    tx_t tx;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_vxid() and format_pvxid()\n");

    tx.vxid = 4711;
    tx.pvxid = 1147;
    format_vxid(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "4711", 4) == 0);
    MASSERT(len == 4);

    str = NULL;
    len = 0;
    format_pvxid(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "1147", 4) == 0);
    MASSERT(len == 4);

    return NULL;
}

static const char
*test_FMT_Fini(void)
{
    printf("... testing FMT_Fini()\n");

    /* should not crash */
    FMT_Fini();
    return NULL;
}

#define ASSERT_TAG_NOHDR(idx) do {              \
        MASSERT(tag2idx[idx] != -1);            \
        MASSERT(hdr_trie[idx] == NULL);         \
        MASSERT(hidx[idx] == -1);               \
    } while(0)

#define ASSERT_TAG_HDR(idx) do {                \
        MASSERT(tag2idx[idx] != -1);            \
        MASSERT(hdr_trie[idx] != NULL);         \
        MASSERT(hidx[idx] >= 0);                \
    } while(0)

#define ASSERT_NOTAG_NOHDR(idx) do {            \
        MASSERT(tag2idx[idx] == -1);            \
        MASSERT(hdr_trie[idx] == NULL);         \
        MASSERT(hidx[idx] == -1);               \
    } while(0)

#define CHECK_HDRS(idx, ...) do {                               \
	const char *hdrs[] = {__VA_ARGS__};                     \
	int sz = sizeof(hdrs)/sizeof(hdrs[0]);                  \
	MASSERT(HDR_N(hdr_trie[idx]) == sz);                    \
        MASSERT(hidx[idx] == sz - 1);                           \
	for (int j = 0; j < sz; j++ ) {                         \
            int _idx = HDR_FindIdx(hdr_trie[idx], hdrs[j]);     \
	    MASSERT(_idx >= 0);                                 \
	    MASSERT(_idx <= hidx[idx]);                         \
        }                                                       \
    } while (0)

static int
get_hdr_idx(enum VSL_tag_e tag, const char *hdr)
{
    return HDR_FindIdx(hdr_trie[tag], hdr);
}

static void
setup_full_client_tx(tx_t *tx, rec_node_t node[], rec_node_t *nptr[],
                     rec_t rec[], chunk_t c[])
{
#define TS_REQ_PAYLOAD "Req: 1429213569.602005 0.000000 0.000000"
    init_tx(tx, node, nptr);
    tx->state = TX_SUBMITTED;
    tx->disp = DISP_HIT;
    tx->type = VSL_t_req;

    init_hdr_recs(tx, SLT_Timestamp);
    set_hdr_data(tx, &rec[0], &c[0], get_hdr_idx(SLT_Timestamp, "Start:"),
                 SLT_Timestamp, T1);
    add_record_data(tx, SLT_ReqStart,    &rec[1], &c[1], REQSTART_PAYLOAD);
    add_record_data(tx, SLT_ReqMethod,   &rec[2], &c[2], "GET");
    add_record_data(tx, SLT_ReqURL,      &rec[3], &c[3], URL_QUERY_PAYLOAD);
    add_record_data(tx, SLT_ReqProtocol, &rec[4], &c[4], PROTOCOL_PAYLOAD);
    init_hdr_recs(tx, SLT_ReqHeader);
    set_hdr_data(tx, &rec[5], &c[5],
                 get_hdr_idx(SLT_ReqHeader, "Authorization:"),
                 SLT_ReqHeader, BASIC_AUTH_PAYLOAD);
    set_hdr_data(tx, &rec[6], &c[6], get_hdr_idx(SLT_ReqHeader, "Host:"),
                 SLT_ReqHeader, "Host: foobar.com");
    set_hdr_data(tx, &rec[7], &c[7], get_hdr_idx(SLT_ReqHeader, "Foo:"),
                 SLT_ReqHeader, "Foo: foohdr");
    add_record_data(tx, SLT_RespStatus, &rec[9],  &c[9], "200");
    add_record_data(tx, SLT_ReqAcct,    &rec[10], &c[10], REQACCT_PAYLOAD);
    set_hdr_data(tx, &rec[11], &c[11], get_hdr_idx(SLT_Timestamp, "Resp:"),
                 SLT_Timestamp, TS_RESP_PAYLOAD);
    init_hdr_recs(tx, SLT_RespHeader);
    set_hdr_data(tx, &rec[12], &c[12], get_hdr_idx(SLT_RespHeader, "Bar:"),
                 SLT_RespHeader, "Bar: barhdr");
    set_hdr_data(tx, &rec[13], &c[13],
                 get_hdr_idx(SLT_Timestamp, "Process:"), SLT_Timestamp,
                 TS_PROCESS_PAYLOAD);
    init_hdr_recs(tx, SLT_VCL_Log);
    set_hdr_data(tx, &rec[15], &c[15], get_hdr_idx(SLT_VCL_Log, "baz:"),
                 SLT_VCL_Log, "baz: logload");
    add_record_data(tx, SLT_VCL_acl, &rec[16], &c[16],
                    "MATCH ACL \"10.0.0.0\"/8");
    add_record_data(tx, SLT_Debug, &rec[17], &c[17], "");
    rec[17].len = 10;
    memcpy(c[17].data, "foo\0\xFF bar\0", 10);
    set_hdr_data(tx, &rec[18], &c[18], get_hdr_idx(SLT_Timestamp, "Req:"),
                 SLT_Timestamp, TS_REQ_PAYLOAD);
}

/* Assumes that setup_full_client_tx() has been called first, so that
   some values are already in the records and chunks. */
static void
setup_full_backend_tx(tx_t *tx, rec_node_t node[], rec_node_t *nptr[],
                     rec_t rec[], chunk_t c[])
{
#define TS_BEREQ_PAYLOAD "Bereq: 1429210777.728290 0.000048 0.000048"
    init_tx(tx, node, nptr);
    tx->state = TX_SUBMITTED;
    tx->disp = DISP_NONE;
    tx->type = VSL_t_bereq;

    init_hdr_recs(tx, SLT_Timestamp);
    set_hdr_data(tx, &rec[0], &c[0], get_hdr_idx(SLT_Timestamp, "Start:"),
                 SLT_Timestamp, T1);
    add_record_data(tx, SLT_Backend,       &rec[1], &c[1], BACKEND_PAYLOAD);
    add_record_data(tx, SLT_BereqMethod,   &rec[2], &c[2], "GET");
    add_record_data(tx, SLT_BereqURL,      &rec[3], &c[3], URL_QUERY_PAYLOAD);
    add_record_data(tx, SLT_BereqProtocol, &rec[4], &c[4], PROTOCOL_PAYLOAD);

    init_hdr_recs(tx, SLT_BereqHeader);
    set_hdr_data(tx, &rec[5], &c[5],
                 get_hdr_idx(SLT_BereqHeader, "Authorization:"),
                 SLT_BereqHeader, BASIC_AUTH_PAYLOAD);
    set_hdr_data(tx, &rec[6], &c[6], get_hdr_idx(SLT_BereqHeader, "Host:"),
                 SLT_BereqHeader, "Host: foobar.com");
    set_hdr_data(tx, &rec[7], &c[7], get_hdr_idx(SLT_BereqHeader, "Foo:"),
                 SLT_BereqHeader, "Foo: foohdr");
    add_record_data(tx, SLT_BerespStatus, &rec[9],  &c[9], "200");
    add_record_data(tx, SLT_BereqAcct,    &rec[10], &c[10], REQACCT_PAYLOAD);
    set_hdr_data(tx, &rec[11], &c[11],
                 get_hdr_idx(SLT_Timestamp, "Beresp:"), SLT_Timestamp,
                 TS_BERESP_HDR_PAYLOAD);
    init_hdr_recs(tx, SLT_BerespHeader);
    set_hdr_data(tx, &rec[12], &c[12],
                 get_hdr_idx(SLT_BerespHeader, "Bar:"), SLT_BerespHeader,
                 "Bar: barhdr");
    set_hdr_data(tx, &rec[13], &c[13],
                 get_hdr_idx(SLT_Timestamp, "BerespBody:"), SLT_Timestamp,
                 TS_BERESP_PAYLOAD);
    init_hdr_recs(tx, SLT_VCL_Log);
    set_hdr_data(tx, &rec[15], &c[15], get_hdr_idx(SLT_VCL_Log, "baz:"),
                 SLT_VCL_Log, "baz: logload");
    add_record_data(tx, SLT_Fetch_Body, &rec[16], &c[16], "2 chunked stream");
    add_record_data(tx, SLT_Debug, &rec[17], &c[17], "");
    rec[17].len = 10;
    memcpy(c[17].data, "foo\0\xFF bar\0", 10);
    set_hdr_data(tx, &rec[18], &c[18], get_hdr_idx(SLT_Timestamp, "Bereq:"),
                 SLT_Timestamp, TS_BEREQ_PAYLOAD);
}

static const char
*test_FMT_interface(void)
{
#define NTAGS 25
    char err[BUFSIZ], strftime_s[BUFSIZ], *os;
    int status;
    tx_t tx;
    rec_node_t node[NTAGS], *nptr[NTAGS];
    rec_t rec[NTAGS];
    chunk_t c[NTAGS];
    struct tm *tm;
    time_t t = 1427743146;
    size_t len;

    printf("... testing FMT_*() interface\n");

    reset_tag2idx(0);
    reset_hdrs();
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    MASSERT(8 == FMT_GetMaxIdx());
    MASSERT(11 == FMT_Estimate_RecsPerTx());
    for (int i = 0; i < MAX_VSL_TAG; i++)
        switch(i) {
        case SLT_ReqMethod:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqURL:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqProtocol:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_RespStatus:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqStart:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Authorization:", "Host:", "Referer:", "User-agent:");
            break;
        case SLT_Timestamp:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Start:");
            break;
        default:
            ASSERT_NOTAG_NOHDR(i);
            break;
        }

    init_tx(&tx, node, nptr);
    tx.state = TX_SUBMITTED;
    tx.vxid = 4711;
    tx.pvxid = 1147;
    tx.type = VSL_t_req;

    init_hdr_recs(&tx, SLT_Timestamp);
    set_hdr_data(&tx, &rec[0], &c[0], 0, SLT_Timestamp, T1);
    add_record_data(&tx, SLT_ReqStart,    &rec[1], &c[1], REQSTART_PAYLOAD);
    add_record_data(&tx, SLT_ReqMethod,   &rec[2], &c[2], "GET");
    add_record_data(&tx, SLT_ReqURL,      &rec[3], &c[3], URL_PAYLOAD);
    add_record_data(&tx, SLT_ReqProtocol, &rec[4], &c[4], PROTOCOL_PAYLOAD);
    init_hdr_recs(&tx, SLT_ReqHeader);
    set_hdr_data(&tx, &rec[5], &c[5], 0, SLT_ReqHeader, BASIC_AUTH_PAYLOAD);
    set_hdr_data(&tx, &rec[6], &c[6], 1, SLT_ReqHeader, "Host: bazquux.com");
    set_hdr_data(&tx, &rec[7], &c[7], 2, SLT_ReqHeader,
                 "Referer: http://foobar.com/");
    set_hdr_data(&tx, &rec[8], &c[8], 3, SLT_ReqHeader, "User-Agent: Mozilla");
    add_record_data(&tx, SLT_RespStatus, &rec[9],  &c[9], "200");
    add_record_data(&tx, SLT_ReqAcct,    &rec[10], &c[10], REQACCT_PAYLOAD);

    os = FMT_Format(&tx, &len);
#define EXP_DEFAULT_OUTPUT "127.0.0.1 - varnish [%d/%b/%Y:%T %z] "\
        "\"GET http://bazquux.com/foo HTTP/1.1\" 200 105 "\
        "\"http://foobar.com/\" \"Mozilla\"\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_DEFAULT_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    /* Client format with all formatters */
    FMT_Fini();

#define FULL_CLIENT_FMT "%b %d %D %H %h %I %{Foo}i %{Bar}o %l %m %O %q %r %s "\
        "%t %T %{%F-%T.%i}t %U %u %{Varnish:time_firstbyte}x "\
        "%{Varnish:hitmiss}x %{Varnish:handling}x %{VCL_Log:baz}x "\
        "%{tag:VCL_acl}x %{tag:Debug}x %{tag:Timestamp:Req}x "\
        "%{tag:ReqAcct[0]}x %{tag:Timestamp:Resp[2]}x %{vxid}x %{pvxid}x "\
        "%{Varnish:side}x"
    VSB_clear(config.cformat);
    VSB_cat(config.cformat, FULL_CLIENT_FMT);
    VSB_finish(config.cformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    MASSERT(15 == FMT_GetMaxIdx());
    MASSERT(18 == FMT_Estimate_RecsPerTx());

    for (int i = 0; i < MAX_VSL_TAG; i++)
        switch(i) {
        case SLT_Debug:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqMethod:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqURL:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqProtocol:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_RespStatus:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqStart:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_acl:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_call:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_return:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_PipeAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Authorization:", "Foo:", "Host:");
            break;
        case SLT_RespHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bar:");
            break;
        case SLT_VCL_Log:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "baz:");
            break;
        case SLT_Timestamp:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Process:", "Req:", "Resp:", "Start:");
            break;
        default:
            ASSERT_NOTAG_NOHDR(i);
            break;
        }

    setup_full_client_tx(&tx, node, nptr, rec, c);
    os = FMT_Format(&tx, &len);
#define EXP_FULL_CLIENT_OUTPUT "105 c 15963 HTTP/1.1 127.0.0.1 60 foohdr "\
        "barhdr - GET 283 bar=baz&quux=wilco GET "\
        "http://foobar.com/foo?bar=baz&quux=wilco HTTP/1.1 200 "\
        "[%d/%b/%Y:%T %z] 0 %F-%T.529143 /foo varnish 0.000166 hit hit "\
        "logload MATCH ACL \"10.0.0.0\"/8 \"foo\\0\\377 bar\" " \
        "1429213569.602005 0.000000 0.000000 60 0.000125 4711 1147 c\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_CLIENT_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    /* Backend format with all formatters */
    FMT_Fini();

#define FULL_BACKEND_FMT "%b %d %D %H %h %I %{Foo}i %{Bar}o %l %m %O %q %r %s "\
        "%t %T %{%F-%T.%i}t %U %u %{Varnish:time_firstbyte}x %{VCL_Log:baz}x "\
        "%{tag:Fetch_Body}x %{tag:Debug}x %{tag:Timestamp:Bereq}x "\
        "%{tag:BereqAcct[5]}x %{tag:Timestamp:Bereq[1]}x %{vxid}x %{pvxid}x "\
        "%{Varnish:side}x"
    VSB_clear(config.bformat);
    VSB_cat(config.bformat, FULL_BACKEND_FMT);
    VSB_finish(config.bformat);
    VSB_clear(config.cformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    MASSERT(12 == FMT_GetMaxIdx());
    MASSERT(17 == FMT_Estimate_RecsPerTx());

    for (int i = 0; i < MAX_VSL_TAG; i++)
        switch(i) {
        case SLT_Debug:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqMethod:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqURL:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqProtocol:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BerespStatus:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_Backend:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_Fetch_Body:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Authorization:", "Foo:", "Host:");
            break;
        case SLT_BerespHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bar:");
            break;
        case SLT_VCL_Log:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "baz:");
            break;
        case SLT_Timestamp:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bereq:", "Beresp:", "BerespBody:", "Start:");
            break;
        default:
            ASSERT_NOTAG_NOHDR(i);
            break;
        }

    setup_full_backend_tx(&tx, node, nptr, rec, c);
    os = FMT_Format(&tx, &len);
#define EXP_FULL_BACKEND_OUTPUT "105 b 15703 HTTP/1.1 default(127.0.0.1,,80) "\
        "283 foohdr barhdr - GET 60 bar=baz&quux=wilco GET "\
        "http://foobar.com/foo?bar=baz&quux=wilco HTTP/1.1 200 "\
        "[%d/%b/%Y:%T %z] 0 %F-%T.529143 /foo varnish 0.002837 logload "\
        "2 chunked stream \"foo\\0\\377 bar\" "\
        "1429210777.728290 0.000048 0.000048 283 0.000048 4711 1147 b\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_BACKEND_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    /* Both backend and client formats */
    FMT_Fini();

    VSB_clear(config.cformat);
    VSB_cat(config.cformat, FULL_CLIENT_FMT);
    VSB_finish(config.cformat);
    VSB_clear(config.bformat);
    VSB_cat(config.bformat, FULL_BACKEND_FMT);
    VSB_finish(config.bformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    MASSERT(24 == FMT_GetMaxIdx());
    MASSERT(18 == FMT_Estimate_RecsPerTx());

    for (int i = 0; i < MAX_VSL_TAG; i++)
        switch(i) {
        case SLT_Debug:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqMethod:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqURL:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqProtocol:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_RespStatus:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqStart:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_acl:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_call:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_VCL_return:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_PipeAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_ReqHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Authorization:", "Foo:", "Host:");
            break;
        case SLT_RespHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bar:");
            break;
        case SLT_VCL_Log:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "baz:");
            break;
        case SLT_Timestamp:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bereq:", "Beresp:", "BerespBody:", "Process:",
                       "Req:", "Resp:", "Start:");
            break;
        case SLT_BereqMethod:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqURL:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqProtocol:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BerespStatus:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_Backend:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqAcct:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_Fetch_Body:
            ASSERT_TAG_NOHDR(i);
            break;
        case SLT_BereqHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Authorization:", "Foo:", "Host:");
            break;
        case SLT_BerespHeader:
            ASSERT_TAG_HDR(i);
            CHECK_HDRS(i, "Bar:");
            break;
        default:
            ASSERT_NOTAG_NOHDR(i);
            break;
        }

    setup_full_client_tx(&tx, node, nptr, rec, c);
    os = FMT_Format(&tx, &len);
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_CLIENT_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    setup_full_backend_tx(&tx, node, nptr, rec, c);
    os = FMT_Format(&tx, &len);
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_BACKEND_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    /* Raw format */
    FMT_Fini();

#define FULL_RAW_FMT "%t %{%F-%T.%i}t %{tag:Backend_health}x %{vxid}x"
    VSB_clear(config.rformat);
    VSB_cat(config.rformat, FULL_RAW_FMT);
    VSB_finish(config.rformat);
    VSB_clear(config.bformat);
    VSB_clear(config.cformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    MASSERT(1 == FMT_GetMaxIdx());
    MASSERT(1 == FMT_Estimate_RecsPerTx());

    for (int i = 0; i < MAX_VSL_TAG; i++)
        switch(i) {
        case SLT_Backend_health:
            ASSERT_TAG_NOHDR(i);
            break;
        default:
            ASSERT_NOTAG_NOHDR(i);
            break;
        }

    init_tx(&tx, node, nptr);
    tx.state = TX_SUBMITTED;
    tx.type = VSL_t_raw;
    tx.t = 1427743146.529143;
#define HEALTH_PAYLOAD "b Still healthy 4--X-RH 5 4 5 0.032728 0.035774 " \
        "HTTP/1.1 200 OK"
    add_record_data(&tx, SLT_Backend_health, &rec[0],  &c[0], HEALTH_PAYLOAD);
    os = FMT_Format(&tx, &len);
#define EXP_FULL_RAW_OUTPUT "[%d/%b/%Y:%T %z] %F-%T.529143 "\
        "b Still healthy 4--X-RH 5 4 5 0.032728 0.035774 HTTP/1.1 200 OK 4711\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_RAW_OUTPUT, tm));
    VMASSERT(strcmp(os, strftime_s) == 0, "'%s' != '%s'", os, strftime_s);
    MASSERT(len == strlen(strftime_s));

    /* Illegal backend formats */
    FMT_Fini();
    VSB_clear(config.bformat);
    VSB_cat(config.bformat, "%{Varnish:hitmiss}x");
    VSB_finish(config.bformat);
    VSB_clear(config.rformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err,
                   "Varnish:hitmiss only permitted for client formats") == 0);

    FMT_Fini();
    VSB_clear(config.bformat);
    VSB_cat(config.bformat, "%{Varnish:handling}x");
    VSB_finish(config.bformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err,
                   "Varnish:handling only permitted for client formats") == 0);

    /* Illegal raw formats */
    FMT_Fini();
    VSB_clear(config.rformat);
    VSB_cat(config.rformat, "%r");
    VSB_finish(config.rformat);
    VSB_clear(config.bformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err, "Unknown format starting at: %r") == 0);

    /* Unknown formatters */
    FMT_Fini();
    VSB_clear(config.cformat);
    VSB_cat(config.cformat, "%a");
    VSB_finish(config.cformat);
    VSB_clear(config.rformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err, "Unknown format starting at: %a") == 0);

    /* Illegal header name */
    FMT_Fini();
    VSB_clear(config.cformat);
    VSB_cat(config.cformat, "%{Foo:}i");
    VSB_finish(config.cformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err, "illegal header name: 'Foo:'") == 0);

    /* Peculiar but legal header name */
    FMT_Fini();
    VSB_clear(config.cformat);
    VSB_cat(config.cformat, "%{!#$%'*+.^_`|~}i");
    VSB_finish(config.cformat);
    status = FMT_Init(err);
    MAZ(status);

    return NULL;
}

static const char
*test_long_output(void)
{
#define NFORMATS 8193
#define XID 47114711
#define xstr(s) #s
#define str(s) xstr(s)
    char err[1024], *os;
    int status;
    tx_t tx;
    size_t len;
    struct vsb *exp;

    printf("... testing long formatted output\n");

    exp = VSB_new_auto();
    VSB_clear(config.cformat);
    for (int i = 0; i < NFORMATS; i++) {
        VSB_cat(config.cformat, "%{vxid}x");
        VSB_cat(exp, str(XID));
    }
    VSB_putc(exp, '\n');
    VSB_finish(config.cformat);
    VSB_finish(exp);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    tx.magic = TX_MAGIC;
    tx.state = TX_SUBMITTED;
    tx.type = VSL_t_req;
    tx.vxid = 47114711;

    os = FMT_Format(&tx, &len);
    MASSERT(len == NFORMATS * (sizeof(str(XID)) - 1) + 1);
    MASSERT(strncmp(os, VSB_data(exp), len) == 0);

    return NULL;
}

static const char
*all_tests(void)
{
    mu_run_test(test_format_init);
    mu_run_test(test_format_get_payload);
    mu_run_test(test_format_get_tag);
    mu_run_test(test_format_get_hdr);
    mu_run_test(test_format_get_fld);
    mu_run_test(test_format_get_rec_fld);
    mu_run_test(test_format_b);
    mu_run_test(test_format_D);
    mu_run_test(test_format_H);
    mu_run_test(test_format_h);
    mu_run_test(test_format_I);
    mu_run_test(test_format_m);
    mu_run_test(test_format_O);
    mu_run_test(test_format_q);
    mu_run_test(test_format_r);
    mu_run_test(test_format_s);
    mu_run_test(test_format_t);
    mu_run_test(test_format_T);
    mu_run_test(test_format_U);
    mu_run_test(test_format_u);
    mu_run_test(test_format_Xi);
    mu_run_test(test_format_Xo);
    mu_run_test(test_format_Xt);
    mu_run_test(test_format_Xttfb);
    mu_run_test(test_format_VCL_disp);
    mu_run_test(test_format_VCL_Log);
    mu_run_test(test_format_SLT);
    mu_run_test(test_format_p_vxid);
    mu_run_test(test_FMT_Fini);
    mu_run_test(test_FMT_interface);
    mu_run_test(test_long_output);

    return NULL;
}

TEST_RUNNER
