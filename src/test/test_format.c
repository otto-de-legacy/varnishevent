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

#include "minunit.h"

#include "../varnishevent.h"
#include "../format.h"

#define NRECORDS 10
#define SHORT_STRING "foo bar baz quux"

int tests_run = 0;

static void
add_rec_chunk(tx_t *tx, rec_t *rec, chunk_t *chunk)
{
    VSTAILQ_INSERT_TAIL(&tx->recs, rec, reclist);
    rec->magic = RECORD_MAGIC;
    rec->occupied = 1;
    VSTAILQ_INIT(&rec->chunks);
    VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
    chunk->magic = CHUNK_MAGIC;
    chunk->data = (char *) calloc(1, config.chunk_size);
}

static void
init_tx_rec_chunk_arg(tx_t *tx, rec_t *rec, chunk_t *chunk, arg_t *args)
{
    tx->magic = TX_MAGIC;
    VSTAILQ_INIT(&tx->recs);
    add_rec_chunk(tx, rec, chunk);
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
add_record_data(tx_t *tx, rec_t *rec, chunk_t *chunk, const char *data,
                enum VSL_tag_e tag)
{
    add_rec_chunk(tx, rec, chunk);
    set_record_data(rec, chunk, data, tag);
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
    tx_t tx;
    rec_t recs[NRECORDS], *rec;

    printf("... testing get_tag()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.recs);
    for (int i = 0; i < NRECORDS; i++) {
        memset(&recs[i], 0, sizeof(rec_t));
        recs[i].magic = RECORD_MAGIC;
        recs[i].tag = SLT_ReqHeader;
        recs[i].occupied = 1;
        VSTAILQ_INSERT_TAIL(&tx.recs, &recs[i], reclist);
    }
    recs[NRECORDS / 2].tag = SLT_RespHeader;
    recs[NRECORDS - 1].tag = SLT_RespHeader;
    rec = get_tag(&tx, SLT_RespHeader);
    MASSERT(rec == &recs[NRECORDS - 1]);

    /* Record not found */
    recs[NRECORDS / 2].tag = SLT_ReqHeader;
    recs[NRECORDS - 1].tag = SLT_ReqHeader;
    rec = get_tag(&tx, SLT_RespHeader);
    MAZ(rec);

    /* Empty line list */
    VSTAILQ_INIT(&tx.recs);
    rec = get_tag(&tx, SLT_ReqHeader);
    MAZ(rec);

    return NULL;
}

static const char
*test_format_get_hdr(void)
{
    tx_t tx;
    rec_t recs[NRECORDS];
    chunk_t c[NRECORDS];
    char *hdr;

    printf("... testing get_hdr()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.recs);
    for (int i = 0; i < NRECORDS; i++) {
        memset(&recs[i], 0, sizeof(rec_t));
        recs[i].magic = RECORD_MAGIC;
        recs[i].tag = SLT_ReqHeader;
        recs[i].len = strlen("Bar: baz");
        recs[i].occupied = 1;
        VSTAILQ_INSERT_TAIL(&tx.recs, &recs[i], reclist);
        VSTAILQ_INIT(&recs[i].chunks);
        memset(&c[i], 0, sizeof(chunk_t));
        c[i].magic = CHUNK_MAGIC;
        c[i].data = (char *) calloc(1, config.chunk_size);
        c[i].occupied = 1;
        strcpy(c[i].data, "Bar: baz");
        VSTAILQ_INSERT_TAIL(&recs[i].chunks, &c[i], chunklist);
    }
    recs[NRECORDS / 2].len = strlen("Foo: quux");
    strcpy(c[NRECORDS / 2].data, "Foo: quux");
    recs[NRECORDS - 1].len = strlen("Foo: wilco");
    strcpy(c[NRECORDS - 1].data, "Foo: wilco");
    hdr = get_hdr(&tx, SLT_ReqHeader, "Foo");
    MAN(hdr);
    MASSERT(strcmp(hdr, "wilco") == 0);

    /* Case-insensitive match */
    hdr = get_hdr(&tx, SLT_ReqHeader, "fOO");
    MAN(hdr);
    MASSERT(strcmp(hdr, "wilco") == 0);

    /* Ignore whitespace  */
    recs[NRECORDS - 1].len = strlen("  Foo  :  wilco");
    strcpy(c[NRECORDS - 1].data, "  Foo  :  wilco");
    hdr = get_hdr(&tx, SLT_ReqHeader, "Foo");
    MAN(hdr);
    MASSERT(strcmp(hdr, "wilco") == 0);

    /* Record not found */
    recs[NRECORDS / 2].tag = SLT_RespHeader;
    recs[NRECORDS - 1].tag = SLT_RespHeader;
    hdr = get_hdr(&tx, SLT_ReqHeader, "Foo");
    MAZ(hdr);

    /* Empty line list */
    VSTAILQ_INIT(&tx.recs);
    hdr = get_hdr(&tx, SLT_ReqHeader, "Foo");
    MAZ(hdr);

    return NULL;
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
*test_format_H(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len, explen;

    printf("... testing format_H_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define PROTOCOL_PAYLOAD "HTTP/1.1"
    set_record_data(&rec, &chunk, PROTOCOL_PAYLOAD, SLT_ReqProtocol);
    format_H_client(&tx, &args, &str, &len);
    explen = strlen(PROTOCOL_PAYLOAD);
    MASSERT(strncmp(str, PROTOCOL_PAYLOAD, explen) == 0);
    MASSERT(len == explen);

    rec.tag = SLT_BereqProtocol;
    format_H_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, PROTOCOL_PAYLOAD, explen) == 0);
    MASSERT(len == explen);

    return NULL;
}

static const char
*test_format_b(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_b_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define REQACCT_PAYLOAD "60 0 60 178 105 283"
    set_record_data(&rec, &chunk, REQACCT_PAYLOAD, SLT_ReqAcct);
    format_b_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BereqAcct;
    format_b_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_D(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_D_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define TS_RESP_PAYLOAD "Resp: 1427799478.166798 0.015963 0.000125"
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    format_D_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "15963", 5) == 0);
    MASSERT(len == 5);

#define TS_BERESP_PAYLOAD "BerespBody: 1427799478.166678 0.015703 0.000282"
    set_record_data(&rec, &chunk, TS_BERESP_PAYLOAD, SLT_Timestamp);
    format_D_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "15703", 5) == 0);
    MASSERT(len == 5);

    return NULL;
}

static const char
*test_format_h(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_h_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define REQSTART_PAYLOAD "127.0.0.1 33544"
    set_record_data(&rec, &chunk, REQSTART_PAYLOAD, SLT_ReqStart);
    format_h_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "127.0.0.1", 9) == 0);
    MASSERT(len == 9);

#define BACKEND_PAYLOAD "14 default default(127.0.0.1,,80)"
    set_record_data(&rec, &chunk, BACKEND_PAYLOAD, SLT_Backend);
    format_h_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "default(127.0.0.1,,80)", 22) == 0);
    MASSERT(len == 22);

    return NULL;
}

static const char
*test_format_I(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_I_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, REQACCT_PAYLOAD, SLT_ReqAcct);
    format_I_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "60", 2) == 0);
    MASSERT(len == 2);

    set_record_data(&rec, &chunk, REQACCT_PAYLOAD, SLT_BereqAcct);
    format_I_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "283", 3) == 0);
    MASSERT(len == 3);

#define PIPEACCT_PAYLOAD "60 60 178 105"
    set_record_data(&rec, &chunk, PIPEACCT_PAYLOAD, SLT_PipeAcct);
    format_I_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "178", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_m(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_m_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define REQMETHOD_PAYLOAD "GET"
    set_record_data(&rec, &chunk, REQMETHOD_PAYLOAD, SLT_ReqMethod);
    format_m_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET", 3) == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BereqMethod;
    format_m_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_O(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_O_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, REQACCT_PAYLOAD, SLT_ReqAcct);
    format_O_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "283", 3) == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BereqAcct;
    format_O_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "60", 2) == 0);
    MASSERT(len == 2);

    set_record_data(&rec, &chunk, PIPEACCT_PAYLOAD, SLT_PipeAcct);
    format_O_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "105", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_q(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_q_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define URL_QUERY_PAYLOAD "/foo?bar=baz&quux=wilco"
    set_record_data(&rec, &chunk, URL_QUERY_PAYLOAD, SLT_ReqURL);
    format_q_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar=baz&quux=wilco", 18) == 0);
    MASSERT(len == 18);

    rec.tag = SLT_BereqURL;
    format_q_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar=baz&quux=wilco", 18) == 0);
    MASSERT(len == 18);

#define URL_PAYLOAD "/foo"
    set_record_data(&rec, &chunk, URL_PAYLOAD, SLT_ReqURL);
    str = NULL;
    len = 0;
    format_q_client(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    rec.tag = SLT_BereqURL;
    format_q_backend(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    return NULL;
}

static const char
*test_format_r(void)
{
    tx_t tx;
    rec_t rec_method, rec_host, rec_url, rec_proto;
    chunk_t chunk_method, chunk_host, chunk_url, chunk_proto;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_r_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec_method, &chunk_method, &args);
    MAN(chunk_method.data);
    add_rec_chunk(&tx, &rec_host, &chunk_host);
    MAN(chunk_host.data);
    add_rec_chunk(&tx, &rec_url, &chunk_url);
    MAN(chunk_url.data);
    add_rec_chunk(&tx, &rec_proto, &chunk_proto);
    MAN(chunk_proto.data);

    set_record_data(&rec_method, &chunk_method, "GET", SLT_ReqMethod);
    set_record_data(&rec_host, &chunk_host, "Host: www.foobar.com",
                    SLT_ReqHeader);
    set_record_data(&rec_url, &chunk_url, URL_PAYLOAD, SLT_ReqURL);
    set_record_data(&rec_proto, &chunk_proto, PROTOCOL_PAYLOAD,
                    SLT_ReqProtocol);
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.1", 38) == 0);
    MASSERT(len == 38);

    rec_method.tag = SLT_BereqMethod;
    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.1", 38) == 0);
    MASSERT(len == 38);

    /* No method record */
    rec_method.tag = SLT__Bogus;
    rec_host.tag = SLT_ReqHeader;
    rec_url.tag = SLT_ReqURL;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "- http://www.foobar.com/foo HTTP/1.1", 36) == 0);
    MASSERT(len == 36);

    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "- http://www.foobar.com/foo HTTP/1.1" ,36) == 0);
    MASSERT(len == 36);

    /* No host header */
    rec_method.tag = SLT_ReqMethod;
    set_record_data(&rec_host, &chunk_host, "Foo: bar", SLT_ReqHeader);
    rec_url.tag = SLT_ReqURL;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    rec_method.tag = SLT_BereqMethod;
    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    /* No header record */
    rec_method.tag = SLT_ReqMethod;
    rec_host.tag = SLT__Bogus;
    rec_url.tag = SLT_ReqURL;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    rec_method.tag = SLT_BereqMethod;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://localhost/foo HTTP/1.1", 33) == 0);
    MASSERT(len == 33);

    /* URL record empty */
    set_record_data(&rec_host, &chunk_host, "Host: www.foobar.com",
                    SLT_ReqHeader);
    rec_method.tag = SLT_ReqMethod;
    rec_url.tag = SLT_ReqURL;
    rec_url.len = 0;
    rec_proto.tag = SLT_ReqProtocol;
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com- HTTP/1.1", 35) == 0);
    MASSERT(len == 35);

    rec_method.tag = SLT_BereqMethod;
    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com- HTTP/1.1", 35) == 0);
    MASSERT(len == 35);

    /* Proto record empty */
    rec_method.tag = SLT_ReqMethod;
    rec_host.tag = SLT_ReqHeader;
    rec_url.tag = SLT_ReqURL;
    rec_url.len = strlen(URL_PAYLOAD);
    rec_proto.tag = SLT_ReqProtocol;
    rec_proto.len = 0;
    format_r_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.0", 38) == 0);
    MASSERT(len == 38);

    rec_method.tag = SLT_BereqMethod;
    rec_host.tag = SLT_BereqHeader;
    rec_url.tag = SLT_BereqURL;
    rec_proto.tag = SLT_BereqProtocol;
    format_r_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "GET http://www.foobar.com/foo HTTP/1.0", 38) == 0);
    MASSERT(len == 38);

    return NULL;
}

static const char
*test_format_s(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_s_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define STATUS_PAYLOAD "200"
    set_record_data(&rec, &chunk, STATUS_PAYLOAD, SLT_RespStatus);
    format_s_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, STATUS_PAYLOAD, 3) == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BerespStatus;
    format_s_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, STATUS_PAYLOAD, 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_t(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str = NULL, strftime_s[BUFSIZ], fmt[] = "[%d/%b/%Y:%T %z]";
    size_t len, explen;
    struct tm *tm;
    time_t t = 1427743146;

    printf("... testing format_t()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define T1 "Start: 1427743146.529143 0.000000 0.000000"
    set_record_data(&rec, &chunk, T1, SLT_Timestamp);
    tm = localtime(&t);
    MAN(strftime(strftime_s, config.max_reclen, fmt, tm));
    format_t(&tx, &args, &str, &len);
    MAN(str);
    explen = strlen(strftime_s);
    VMASSERT(strncmp(str, strftime_s, explen) == 0, "'%s' != '%s'", str,
             strftime_s);
    MASSERT(len == explen);

    return NULL;
}

static const char
*test_format_T(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_T_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    format_T_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0", 1) == 0);
    MASSERT(len == 1);

    set_record_data(&rec, &chunk, TS_BERESP_PAYLOAD, SLT_Timestamp);
    format_T_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0", 1) == 0);
    MASSERT(len == 1);

    return NULL;
}

static const char
*test_format_U(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_U_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, URL_QUERY_PAYLOAD, SLT_ReqURL);
    format_U_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    set_record_data(&rec, &chunk, URL_QUERY_PAYLOAD, SLT_BereqURL);
    format_U_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    set_record_data(&rec, &chunk, URL_PAYLOAD, SLT_ReqURL);
    format_U_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    rec.tag = SLT_BereqURL;
    format_U_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "/foo", 4) == 0);
    MASSERT(len == 4);

    return NULL;
}

static const char
*test_format_u(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_u_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define BASIC_AUTH_PAYLOAD "Authorization: Basic dmFybmlzaDo0ZXZlcg=="
    set_record_data(&rec, &chunk, BASIC_AUTH_PAYLOAD, SLT_ReqHeader);
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "varnish", 7) == 0);
    MASSERT(len == 7);

    rec.tag = SLT_BereqHeader;
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "varnish", 7) == 0);
    MASSERT(len == 7);

    /* No header record */
    rec.tag = SLT__Bogus;
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    /* No auth header */
    rec.tag = SLT_ReqHeader;
    rec.len = 0;
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    rec.tag = SLT_BereqHeader;
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    /* No basic auth header
     * Not a real example of a digest auth header, but kept short, so
     * that we can test with only one chunk.
     */
#define DIGEST_AUTH_PAYLOAD "Authorization: Digest username=\"Mufasa\", realm=\"realm@host.com\""
    set_record_data(&rec, &chunk, DIGEST_AUTH_PAYLOAD, SLT_ReqHeader);
    format_u_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    rec.tag = SLT_BereqHeader;
    format_u_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "-", 1) == 0);
    MASSERT(len == 1);

    return NULL;
}

static const char
*test_format_Xi(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str, hdr[] = "Foo";
    size_t len;

    printf("... testing format_Xi_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);
    args.name = hdr;

    set_record_data(&rec, &chunk, "Foo: bar", SLT_ReqHeader);
    format_Xi_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BereqHeader;
    format_Xi_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_Xo(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str, hdr[] = "Baz";
    size_t len;

    printf("... testing format_Xo_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);
    args.name = hdr;

    set_record_data(&rec, &chunk, "Baz: quux", SLT_RespHeader);
    format_Xo_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "quux", 4) == 0);
    MASSERT(len == 4);

    rec.tag = SLT_BerespHeader;
    format_Xo_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "quux", 4) == 0);
    MASSERT(len == 4);

    return NULL;
}

static const char
*test_format_Xt(void)
{
    tx_t tx;
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

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, T1, SLT_Timestamp);
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
    /* ms accuracy ... */
    VMASSERT(strncmp(str, "529143", 6) == 0, "'%s' != '529143'", str);
    MASSERT(len == 6);

    return NULL;
}

static const char
*test_format_Xttfb(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str;
    size_t len;

    printf("... testing format_Xttfb_*()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

#define TS_PROCESS_PAYLOAD "Process: 1427979230.712416 0.000166 0.000166"
    set_record_data(&rec, &chunk, TS_PROCESS_PAYLOAD, SLT_Timestamp);
    format_Xttfb_client(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0.000166", 8) == 0);
    MASSERT(len == 8);

#define TS_BERESP_HDR_PAYLOAD "Beresp: 1427979243.588828 0.002837 0.002743"
    set_record_data(&rec, &chunk, TS_BERESP_HDR_PAYLOAD, SLT_Timestamp);
    format_Xttfb_backend(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "0.002837", 8) == 0);
    MASSERT(len == 8);

    return NULL;
}

static const char
*test_format_VCL_disp(void)
{
    tx_t tx;
    rec_t *recs[NRECORDS];
    chunk_t *c[NRECORDS];
    arg_t args;
    char *str, hitmiss[] = "m", handling[] = "n";
    size_t len;

    printf("... testing format_VCL_disp()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.recs);
    for (int i = 0; i < NRECORDS; i++) {
        recs[i] = (rec_t *) calloc(1, sizeof(rec_t));
        MAN(recs[i]);
        c[i] = (chunk_t *) calloc(1, sizeof(chunk_t));
        MAN(c[i]);
    }

    /* %{Varnish:hitmiss} for a hit */
    add_record_data(&tx, recs[0], c[0], "RECV", SLT_VCL_call);
    add_record_data(&tx, recs[1], c[1], "hash", SLT_VCL_return);
    add_record_data(&tx, recs[2], c[2], "HASH", SLT_VCL_call);
    add_record_data(&tx, recs[3], c[3], "lookup", SLT_VCL_return);
    add_record_data(&tx, recs[4], c[4], "HIT", SLT_VCL_call);
    add_record_data(&tx, recs[5], c[5], "deliver", SLT_VCL_return);
    add_record_data(&tx, recs[6], c[6], "DELIVER", SLT_VCL_call);
    add_record_data(&tx, recs[7], c[7], "deliver", SLT_VCL_return);
    for (int i = 8; i < NRECORDS; i++)
        add_record_data(&tx, recs[i], c[i], "", SLT__Bogus);
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
    add_record_data(&tx, recs[4], c[4], "MISS", SLT_VCL_call);
    add_record_data(&tx, recs[5], c[5], "fetch", SLT_VCL_return);
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
    add_record_data(&tx, recs[4], c[4], "PASS", SLT_VCL_call);
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
    add_record_data(&tx, recs[4], c[4], "ERROR", SLT_VCL_call);
    add_record_data(&tx, recs[5], c[5], "synth", SLT_VCL_return);
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
    add_record_data(&tx, recs[0], c[0], "RECV", SLT_VCL_call);
    add_record_data(&tx, recs[1], c[1], "synth", SLT_VCL_return);
    add_record_data(&tx, recs[2], c[2], "HASH", SLT_VCL_call);
    add_record_data(&tx, recs[3], c[3], "lookup", SLT_VCL_return);
    add_record_data(&tx, recs[4], c[4], "SYNTH", SLT_VCL_call);
    add_record_data(&tx, recs[5], c[5], "deliver", SLT_VCL_return);
    for (int i = 6; i < NRECORDS; i++)
        add_record_data(&tx, recs[i], c[i], "", SLT__Bogus);
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
    add_record_data(&tx, recs[1], c[1], "pipe", SLT_VCL_return);
    for (int i = 2; i < NRECORDS; i++)
        add_record_data(&tx, recs[i], c[i], "", SLT__Bogus);
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
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str, hdr[] = "foo";
    size_t len;

    printf("... testing format_VCL_Log()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);
    args.name = hdr;

    set_record_data(&rec, &chunk, "foo: bar", SLT_VCL_Log);
    format_VCL_Log(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "bar", 3) == 0);
    MASSERT(len == 3);

    /* No match */
    str = NULL;
    len = 0;
    set_record_data(&rec, &chunk, "baz: quux", SLT_VCL_Log);
    format_VCL_Log(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    /* No VCL_Log record */
    set_record_data(&rec, &chunk, "foo: bar", SLT_BereqHeader);
    format_VCL_Log(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    return NULL;
}

static const char
*test_format_SLT(void)
{
    tx_t tx;
    rec_t rec;
    chunk_t chunk;
    arg_t args;
    char *str, *substr;
    size_t len;

    printf("... testing format_SLT()\n");

    init_tx_rec_chunk_arg(&tx, &rec, &chunk, &args);
    MAN(chunk.data);

    set_record_data(&rec, &chunk, "no backend connection", SLT_FetchError);
    args.tag = SLT_FetchError;
    args.fld = -1;
    format_SLT(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "no backend connection", 21) == 0);
    MASSERT(len == 21);

    /* record not found */
    str = NULL;
    len = 0;
    rec.tag = SLT_BereqHeader;
    format_SLT(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);

    /* Binary tag with non-printables in the payload */
    memcpy(chunk.data, "foo\0\xFF bar\0", 10);
    rec.len = 10;
    rec.tag = SLT_Debug;
    args.tag = SLT_Debug;
    format_SLT(&tx, &args, &str, &len);
#define EXP_SLT_BINARY "\"foo\\0\\377 bar\""
    VMASSERT(strncmp(str, EXP_SLT_BINARY, 15) == 0,
             "format_SLT with binary data: Expected '%s', got '%s'",
             EXP_SLT_BINARY, str);
    MASSERT(len == 15);

    /* header selector */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    rec.len = strlen(TS_RESP_PAYLOAD);
    rec.tag = SLT_Timestamp;
    args.tag = SLT_Timestamp;
    args.name = strdup("Resp");
    format_SLT(&tx, &args, &str, &len);
    substr = strstr(TS_RESP_PAYLOAD, "14");
    MASSERT(strncmp(str, substr, strlen(substr)) == 0);
    MASSERT(len == strlen(substr));

    /* field selector */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    args.name = NULL;
    args.fld = 0;
    format_SLT(&tx, &args, &str, &len);
    MASSERT(strncmp(str, "Resp:", 5) == 0);
    MASSERT(len == 5);

    /* header and field selector */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    args.name = strdup("Resp");
    format_SLT(&tx, &args, &str, &len);
    MASSERT(strncmp(str, substr, len) == 0);
    MASSERT(len == strlen("1427799478.166798"));

    /* header not found */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    args.name = strdup("Foo");
    args.fld = -1;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
    MAZ(str);
    MAZ(len);
    
    /* field not found */
    set_record_data(&rec, &chunk, TS_RESP_PAYLOAD, SLT_Timestamp);
    args.name = NULL;
    args.fld = 4;
    str = NULL;
    len = 0;
    format_SLT(&tx, &args, &str, &len);
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

static const char
*test_FMT_interface(void)
{
#define NRECS 20
    char err[BUFSIZ], **i_args, *i_arg, strftime_s[BUFSIZ];
    int status, recs_per_tx;
    tx_t tx;
    rec_t *recs[NRECS];
    chunk_t *c[NRECS];
    struct vsb *os;
    struct tm *tm;
    time_t t = 1427743146;

    printf("... testing FMT_Format(), FMT_Get_i_Arg() and "\
           "FMT_Estimate_RecsPerTx()\n");

    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    os = VSB_new_auto();
    MAN(os);

    tx.magic = TX_MAGIC;
    tx.occupied = 1;
    tx.vxid = 4711;
    tx.pvxid = 1147;
    VSTAILQ_INIT(&tx.recs);
    for (int i = 0; i < NRECS; i++) {
        recs[i] = (rec_t *) calloc(1, sizeof(rec_t));
        MAN(recs[i]);
        c[i] = (chunk_t *) calloc(1, sizeof(chunk_t));
        MAN(c[i]);
    }

    /* Default client format */
    i_args = FMT_Get_I_Args();
    MAN(i_args);
    const char *exp_default_I_args[] = {
        "ReqHeader:^\\s*Authorization\\s*:", "ReqHeader:^\\s*Host\\s*:",
        "ReqHeader:^\\s*Referer\\s*:", "ReqHeader:^\\s*User-agent\\s*:",
        "Timestamp:^\\s*Start\\s*:", NULL
    };
    for (int i = 0; i_args[i] != NULL; i++) {
        MAN(exp_default_I_args[i]);
        VMASSERT(strcmp(i_args[i], exp_default_I_args[i]) == 0, "'%s' != '%s'",
                 i_args[i], exp_default_I_args[i]);
    }

    i_arg = FMT_Get_i_Arg();
    MAN(i_arg);
#define DEFAULT_I_TAGS "ReqMethod,ReqURL,ReqProtocol,RespStatus,ReqStart,"\
        "ReqAcct,"
    VMASSERT(strcmp(i_arg, DEFAULT_I_TAGS) == 0,
             "Default -i arg expected '%s' != '%s'", DEFAULT_I_TAGS, i_arg);

    recs_per_tx = FMT_Estimate_RecsPerTx();
    MASSERT(recs_per_tx == 11);

    tx.type = VSL_t_req;
    add_record_data(&tx, recs[0], c[0], T1, SLT_Timestamp);
    add_record_data(&tx, recs[1], c[1], REQSTART_PAYLOAD, SLT_ReqStart);
    add_record_data(&tx, recs[2], c[2], "GET", SLT_ReqMethod);
    add_record_data(&tx, recs[3], c[3], URL_PAYLOAD, SLT_ReqURL);
    add_record_data(&tx, recs[4], c[4], PROTOCOL_PAYLOAD, SLT_ReqProtocol);
    add_record_data(&tx, recs[5], c[5], BASIC_AUTH_PAYLOAD, SLT_ReqHeader);
    add_record_data(&tx, recs[6], c[6], "Referer: http://foobar.com/",
                    SLT_ReqHeader);
    add_record_data(&tx, recs[7], c[7], "User-Agent: Mozilla", SLT_ReqHeader);
    add_record_data(&tx, recs[8], c[8], "Host: bazquux.com", SLT_ReqHeader);
    add_record_data(&tx, recs[9], c[9], "200", SLT_RespStatus);
    add_record_data(&tx, recs[10], c[10], REQACCT_PAYLOAD, SLT_ReqAcct);
    for (int i = 11; i < NRECS; i++)
        add_record_data(&tx, recs[i], c[i], "", SLT__Bogus);
    FMT_Format(&tx, os);
    VSB_finish(os);
#define EXP_DEFAULT_OUTPUT "127.0.0.1 - varnish [%d/%b/%Y:%T %z] "\
        "\"GET http://bazquux.com/foo HTTP/1.1\" 200 105 "\
        "\"http://foobar.com/\" \"Mozilla\"\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_DEFAULT_OUTPUT, tm));
    VMASSERT(strcmp(VSB_data(os), strftime_s) == 0, "'%s' != '%s'",
             VSB_data(os), strftime_s);

    /* Client format with all formatters */
    FMT_Fini();
    VSB_clear(os);

#define FULL_CLIENT_FMT "%b %d %D %H %h %I %{Foo}i %{Bar}o %l %m %O %q %r %s "\
        "%t %T %{%F-%T.%i}t %U %u %{Varnish:time_firstbyte}x "\
        "%{Varnish:hitmiss}x %{Varnish:handling}x %{VCL_Log:baz}x "\
        "%{tag:VCL_acl}x %{tag:Debug}x %{tag:Timestamp:Req}x "\
        "%{tag:ReqAcct[0]}x %{tag:Timestamp:Resp[2]}x %{vxid}x %{pvxid}x"
    VSB_clear(config.cformat);
    VSB_cpy(config.cformat, FULL_CLIENT_FMT);
    VSB_finish(config.cformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    i_args = FMT_Get_I_Args();
    MAN(i_args);
    const char *exp_full_client_I_args[] = {
        "ReqHeader:^\\s*Foo\\s*:", "ReqHeader:^\\s*Host\\s*:",
        "ReqHeader:^\\s*Authorization\\s*:", "RespHeader:^\\s*Bar\\s*:",
        "VCL_Log:^\\s*baz\\s*:", "Timestamp:^\\s*Resp\\s*:",
        "Timestamp:^\\s*Start\\s*:", "Timestamp:^\\s*Process\\s*:",
        "Timestamp:^\\s*Req\\s*:", NULL
    };
    for (int i = 0; i_args[i] != NULL; i++) {
        MAN(exp_full_client_I_args[i]);
        VMASSERT(strcmp(i_args[i], exp_full_client_I_args[i]) == 0,
                 "'%s' != '%s'", i_args[i], exp_full_client_I_args[i]);
    }
    
    i_arg = FMT_Get_i_Arg();
    MAN(i_arg);
#define FULL_CLIENT_I_TAGS "Debug,ReqMethod,ReqURL,ReqProtocol,RespStatus,"\
        "VCL_acl,VCL_call,VCL_return,ReqStart,ReqAcct,PipeAcct,"
    VMASSERT(strcmp(i_arg, FULL_CLIENT_I_TAGS) == 0,
             "Full client -i arg expected '%s' != '%s'", FULL_CLIENT_I_TAGS,
             i_arg);

    recs_per_tx = FMT_Estimate_RecsPerTx();
    VMASSERT(recs_per_tx == 47, "recs_per_tx(%d) != 47", recs_per_tx);

#define TS_REQ_PAYLOAD "Req: 1429213569.602005 0.000000 0.000000"
    set_record_data(recs[3], c[3], URL_QUERY_PAYLOAD, SLT_ReqURL);
    set_record_data(recs[6], c[6], "Host: foobar.com", SLT_ReqHeader);
    set_record_data(recs[7], c[7], "Foo: foohdr", SLT_ReqHeader);
    set_record_data(recs[8], c[8], "Host: bazquux.com", SLT_ReqHeader);
    set_record_data(recs[11], c[11], TS_RESP_PAYLOAD, SLT_Timestamp);
    set_record_data(recs[12], c[12], "Bar: barhdr", SLT_RespHeader);
    set_record_data(recs[13], c[13], TS_PROCESS_PAYLOAD, SLT_Timestamp);
    set_record_data(recs[14], c[14], "HIT", SLT_VCL_call);
    set_record_data(recs[15], c[15], "baz: logload", SLT_VCL_Log);
    set_record_data(recs[16], c[16], "MATCH ACL \"10.0.0.0\"/8", SLT_VCL_acl);
    set_record_data(recs[17], c[17], "", SLT_Debug);
    recs[17]->len = 10;
    memcpy(c[17]->data, "foo\0\xFF bar\0", 10);
    set_record_data(recs[18], c[18], TS_REQ_PAYLOAD, SLT_Timestamp);
    FMT_Format(&tx, os);
    VSB_finish(os);
#define EXP_FULL_CLIENT_OUTPUT "105 c 15963 HTTP/1.1 127.0.0.1 60 foohdr "\
        "barhdr - GET 283 bar=baz&quux=wilco GET "\
        "http://bazquux.com/foo?bar=baz&quux=wilco HTTP/1.1 200 "\
        "[%d/%b/%Y:%T %z] 0 %F-%T.529143 /foo varnish 0.000166 hit hit "\
        "logload MATCH ACL \"10.0.0.0\"/8 \"foo\\0\\377 bar\" " \
        "1429213569.602005 0.000000 0.000000 60 0.000125 4711 1147\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_CLIENT_OUTPUT, tm));
    VMASSERT(strcmp(VSB_data(os), strftime_s) == 0, "'%s' != '%s'",
             VSB_data(os), strftime_s);

    /* Backend format with all formatters */
    FMT_Fini();
    VSB_clear(os);

#define FULL_BACKEND_FMT "%b %d %D %H %h %I %{Foo}i %{Bar}o %l %m %O %q %r %s "\
        "%t %T %{%F-%T.%i}t %U %u %{Varnish:time_firstbyte}x %{VCL_Log:baz}x "\
        "%{tag:Fetch_Body}x %{tag:Debug}x %{tag:Timestamp:Bereq}x "\
        "%{tag:BereqAcct[5]}x %{tag:Timestamp:Bereq[1]}x %{vxid}x %{pvxid}x"
    VSB_clear(config.bformat);
    VSB_cpy(config.bformat, FULL_BACKEND_FMT);
    VSB_finish(config.bformat);
    VSB_clear(config.cformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    i_args = FMT_Get_I_Args();
    const char *exp_full_backend_I_args[] = {
        "BereqHeader:^\\s*Foo\\s*:", "BereqHeader:^\\s*Host\\s*:",
        "BereqHeader:^\\s*Authorization\\s*:", "BerespHeader:^\\s*Bar\\s*:",
        "VCL_Log:^\\s*baz\\s*:", "Timestamp:^\\s*BerespBody\\s*:",
        "Timestamp:^\\s*Start\\s*:", "Timestamp:^\\s*Beresp\\s*:",
        "Timestamp:^\\s*Bereq\\s*:", NULL
    };
    for (int i = 0; i_args[i] != NULL; i++) {
        MAN(exp_full_backend_I_args[i]);
        VMASSERT(strcmp(i_args[i], exp_full_backend_I_args[i]) == 0,
                 "'%s' != '%s'", i_args[i], exp_full_backend_I_args[i]);
    }

    i_arg = FMT_Get_i_Arg();
    MAN(i_arg);
#define FULL_BACKEND_I_TAGS "Debug,Backend,BereqMethod,BereqURL,BereqProtocol,"\
        "BerespStatus,Fetch_Body,BereqAcct,"
    VMASSERT(strcmp(i_arg, FULL_BACKEND_I_TAGS) == 0,
             "Full backend -i arg expected '%s' != '%s'", FULL_BACKEND_I_TAGS,
             i_arg);

    recs_per_tx = FMT_Estimate_RecsPerTx();
    MASSERT(recs_per_tx == 26);

#define TS_BEREQ_PAYLOAD "Bereq: 1429210777.728290 0.000048 0.000048"
    tx.type = VSL_t_bereq;
    set_record_data(recs[1], c[1], BACKEND_PAYLOAD, SLT_Backend);
    recs[2]->tag = SLT_BereqMethod;
    recs[3]->tag = SLT_BereqURL;
    recs[4]->tag = SLT_BereqProtocol;
    recs[5]->tag = SLT_BereqHeader;
    recs[6]->tag = SLT_BereqHeader;
    recs[7]->tag = SLT_BereqHeader;
    recs[8]->tag = SLT_BereqHeader;
    recs[9]->tag = SLT_BerespStatus;
    recs[10]->tag = SLT_BereqAcct;
    set_record_data(recs[11], c[11], TS_BERESP_PAYLOAD, SLT_Timestamp);
    recs[12]->tag = SLT_BerespHeader;
    set_record_data(recs[13], c[13], TS_BERESP_HDR_PAYLOAD, SLT_Timestamp);
    set_record_data(recs[14], c[14], "", SLT__Bogus);
    set_record_data(recs[16], c[16], "2 chunked stream", SLT_Fetch_Body);
    set_record_data(recs[17], c[17], "", SLT_Debug);
    recs[17]->len = 10;
    memcpy(c[17]->data, "foo\0\xFF bar\0", 10);
    set_record_data(recs[18], c[18], TS_BEREQ_PAYLOAD, SLT_Timestamp);
    FMT_Format(&tx, os);
    VSB_finish(os);
#define EXP_FULL_BACKEND_OUTPUT "105 b 15703 HTTP/1.1 default(127.0.0.1,,80) "\
        "283 foohdr barhdr - GET 60 bar=baz&quux=wilco GET "\
        "http://bazquux.com/foo?bar=baz&quux=wilco HTTP/1.1 200 "\
        "[%d/%b/%Y:%T %z] 0 %F-%T.529143 /foo varnish 0.002837 logload "\
        "2 chunked stream \"foo\\0\\377 bar\" "\
        "1429210777.728290 0.000048 0.000048 283 0.000048 4711 1147\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_BACKEND_OUTPUT, tm));
    VMASSERT(strcmp(VSB_data(os), strftime_s) == 0, "'%s' != '%s'",
             VSB_data(os), strftime_s);

    /* Raw format */
    FMT_Fini();
    VSB_clear(os);

#define FULL_RAW_FMT "%t %{%F-%T.%i}t %{tag:Backend_health}x %{vxid}x"
    VSB_clear(config.rformat);
    VSB_cpy(config.rformat, FULL_RAW_FMT);
    VSB_finish(config.rformat);
    VSB_clear(config.bformat);
    status = FMT_Init(err);
    VMASSERT(status == 0, "FMT_Init: %s", err);

    i_args = FMT_Get_I_Args();
    MAZ(i_args[0]);

    i_arg = FMT_Get_i_Arg();
    MAN(i_arg);
#define FULL_RAW_I_TAGS "Backend_health,"
    VMASSERT(strcmp(i_arg, FULL_RAW_I_TAGS) == 0,
             "Full raw -i arg expected '%s' != '%s'", FULL_RAW_I_TAGS,
             i_arg);

    recs_per_tx = FMT_Estimate_RecsPerTx();
    MASSERT(recs_per_tx == 1);

    tx.type = VSL_t_raw;
    tx.t = 1427743146.529143;
#define HEALTH_PAYLOAD "b Still healthy 4--X-RH 5 4 5 0.032728 0.035774 " \
        "HTTP/1.1 200 OK"
    set_record_data(recs[1], c[1], HEALTH_PAYLOAD, SLT_Backend_health);
    for (int i = 2; i < NRECS; i++)
        add_record_data(&tx, recs[i], c[i], "", SLT__Bogus);
    FMT_Format(&tx, os);
    VSB_finish(os);
#define EXP_FULL_RAW_OUTPUT "[%d/%b/%Y:%T %z] %F-%T.529143 "\
        "b Still healthy 4--X-RH 5 4 5 0.032728 0.035774 HTTP/1.1 200 OK 4711\n"
    tm = localtime(&t);
    MAN(strftime(strftime_s, BUFSIZ, EXP_FULL_RAW_OUTPUT, tm));
    VMASSERT(strcmp(VSB_data(os), strftime_s) == 0, "'%s' != '%s'",
             VSB_data(os), strftime_s);

    /* Illegal backend formats */
    FMT_Fini();
    VSB_clear(config.bformat);
    VSB_cpy(config.bformat, "%{Varnish:hitmiss}x");
    VSB_finish(config.bformat);
    VSB_clear(config.rformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err,
                   "Varnish:hitmiss only permitted for client formats") == 0);

    FMT_Fini();
    VSB_clear(config.bformat);
    VSB_cpy(config.bformat, "%{Varnish:handling}x");
    VSB_finish(config.bformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err,
                   "Varnish:handling only permitted for client formats") == 0);

    /* Illegal raw formats */
    FMT_Fini();
    VSB_clear(config.rformat);
    VSB_cpy(config.rformat, "%r");
    VSB_finish(config.rformat);
    VSB_clear(config.bformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err, "Unknown format starting at: %r") == 0);

    /* Unknown formatters */
    FMT_Fini();
    VSB_clear(config.cformat);
    VSB_cpy(config.cformat, "%a");
    VSB_finish(config.cformat);
    VSB_clear(config.rformat);
    status = FMT_Init(err);
    MAN(status);
    MASSERT(strcmp(err, "Unknown format starting at: %a") == 0);

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

    return NULL;
}

TEST_RUNNER
