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

#include "vre.h"
#include "minunit.h"

#include "../varnishevent.h"
#include "../format.h"

#define NRECORDS 10
#define SHORT_STRING "foo bar baz quux"

int tests_run = 0;

/* N.B.: Always run the tests in this order */
static const char
*test_format_init(void)
{
    const char *error;
    int erroroffset;

    printf("... initializing format tests\n");

    CONF_Init();

    payload = VSB_new(NULL, NULL, DEFAULT_MAX_RECLEN + 1, VSB_FIXEDLEN);
    MAN(payload);

    time_start_re = VRE_compile(TS_START_REGEX, VRE_CASELESS, &error,
                                &erroroffset);
    VMASSERT(time_start_re != NULL,
             "Error compiling " TS_START_REGEX ": %s (offset %d)",
             error, erroroffset);

    time_resp_re = VRE_compile(TS_RESP_REGEX, VRE_CASELESS, &error,
                               &erroroffset);
    VMASSERT(time_resp_re != NULL,
             "Error compiling " TS_RESP_REGEX ": %s (offset %d)",
             error, erroroffset);

    time_beresp_body_re = VRE_compile(TS_BERESP_BODY_REGEX, VRE_CASELESS,
                                      &error, &erroroffset);
    VMASSERT(time_beresp_body_re != NULL,
             "Error compiling " TS_BERESP_BODY_REGEX ": %s (offset %d)",
             error, erroroffset);

    return NULL;
}

static const char
*test_format_get_payload(void)
{
    logline_t rec;
    chunk_t chunk;

    printf("... testing get_payload()\n");

    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

    /* Record with one chunk */
    rec.len = strlen(SHORT_STRING);
    strcpy(chunk.data, SHORT_STRING);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    get_payload(&rec);
    MASSERT(strcmp(VSB_data(payload), SHORT_STRING) == 0);

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
    char *str = (char *) malloc(config.max_reclen);
    MAN(str);
    sprintf(str, "%0*d", config.max_reclen, 0);
    get_payload(&rec);
    MASSERT(strcmp(VSB_data(payload), str) == 0);

    /* Empty record */
    rec.len = 0;
    *chunk.data = '\0';
    get_payload(&rec);
    MASSERT(strlen(VSB_data(payload)) == 0);

    return NULL;
}

static const char
*test_format_get_tag(void)
{
    tx_t tx;
    logline_t recs[NRECORDS], *rec;

    printf("... testing get_tag()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    for (int i = 0; i < NRECORDS; i++) {
        recs[i].magic = LOGLINE_MAGIC;
        recs[i].tag = SLT_ReqHeader;
        VSTAILQ_INSERT_TAIL(&tx.lines, &recs[i], linelist);
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
    VSTAILQ_INIT(&tx.lines);
    rec = get_tag(&tx, SLT_ReqHeader);
    MAZ(rec);

    return NULL;
}

static const char
*test_format_get_hdr(void)
{
    tx_t tx;
#define HDR_REGEX "^\\s*Foo\\s*:\\s*(.+)$"
    logline_t recs[NRECORDS];
    chunk_t c[NRECORDS];
    vre_t *hdr_re;
    const char *error;
    char *hdr;
    int erroroffset;

    printf("... testing get_hdr()\n");

    hdr_re = VRE_compile(HDR_REGEX, VRE_CASELESS, &error, &erroroffset);
    VMASSERT(hdr_re != NULL,
             "Error compiling \"" HDR_REGEX "\": %s (offset %d)",
             error, erroroffset);

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    for (int i = 0; i < NRECORDS; i++) {
        recs[i].magic = LOGLINE_MAGIC;
        recs[i].tag = SLT_ReqHeader;
        recs[i].len = strlen("Bar: baz");
        VSTAILQ_INSERT_TAIL(&tx.lines, &recs[i], linelist);
        VSTAILQ_INIT(&recs[i].chunks);
        c[i].magic = CHUNK_MAGIC;
        c[i].data = (char *) calloc(1, config.chunk_size);
        strcpy(c[i].data, "Bar: baz");
        VSTAILQ_INSERT_TAIL(&recs[i].chunks, &c[i], chunklist);
    }
    recs[NRECORDS / 2].len = strlen("Foo: quux");
    strcpy(c[NRECORDS / 2].data, "Foo: quux");
    recs[NRECORDS - 1].len = strlen("Foo: wilco");
    strcpy(c[NRECORDS - 1].data, "Foo: wilco");
    hdr = get_hdr(&tx, SLT_ReqHeader, hdr_re);
    MAN(hdr);
    MASSERT(strcmp(hdr, "wilco") == 0);

    /* Record not found */
    recs[NRECORDS / 2].tag = SLT_RespHeader;
    recs[NRECORDS - 1].tag = SLT_RespHeader;
    hdr = get_hdr(&tx, SLT_ReqHeader, hdr_re);
    MAZ(hdr);

    /* Empty line list */
    VSTAILQ_INIT(&tx.lines);
    hdr = get_hdr(&tx, SLT_ReqHeader, hdr_re);
    MAZ(hdr);

    return NULL;
}

static const char
*test_format_get_fld(void)
{
    char *fld, str[sizeof(SHORT_STRING)];

    printf("... testing get_fld()\n");

    strcpy(str, SHORT_STRING);

    fld = get_fld(str, 0);
    MAN(fld);
    MASSERT(strcmp(fld, "foo") == 0);

    fld = get_fld(str, 1);
    MAN(fld);
    MASSERT(strcmp(fld, "bar") == 0);

    fld = get_fld(str, 2);
    MAN(fld);
    MASSERT(strcmp(fld, "baz") == 0);

    fld = get_fld(str, 3);
    MAN(fld);
    MASSERT(strcmp(fld, "quux") == 0);

    fld = get_fld(str, 4);
    MAZ(fld);

    strcpy(str, "   ");
    fld = get_fld(str, 0);
    MAZ(fld);
    fld = get_fld(str, 1);
    MAZ(fld);
    fld = get_fld(str, 2);
    MAZ(fld);

    return NULL;
}

static const char
*test_format_get_rec_fld(void)
{
    logline_t rec;
    chunk_t chunk;
    char *fld;

    printf("... testing get_rec_fld()\n");

    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);
    rec.len = strlen(SHORT_STRING);
    strcpy(chunk.data, SHORT_STRING);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);

    fld = get_rec_fld(&rec, 0);
    MAN(fld);
    MASSERT(strcmp(fld, "foo") == 0);

    fld = get_rec_fld(&rec, 1);
    MAN(fld);
    MASSERT(strcmp(fld, "bar") == 0);

    fld = get_rec_fld(&rec, 2);
    MAN(fld);
    MASSERT(strcmp(fld, "baz") == 0);

    fld = get_rec_fld(&rec, 3);
    MAN(fld);
    MASSERT(strcmp(fld, "quux") == 0);

    fld = get_rec_fld(&rec, 4);
    MAZ(fld);

    rec.len = strlen("     ");
    strcpy(chunk.data, "     ");
    fld = get_rec_fld(&rec, 0);
    MAZ(fld);
    fld = get_rec_fld(&rec, 1);
    MAZ(fld);
    fld = get_rec_fld(&rec, 2);
    MAZ(fld);

    return NULL;
}

static const char
*test_format_get_tm(void)
{
#define T1 "Start: 1427743146.529143 0.000000 0.000000"
#define TIME 1427743146.529306
#define TX_TIME 1427744284.563984
    tx_t tx;
    logline_t recs[NRECORDS];
    chunk_t c[NRECORDS];
    double tm;

    printf("... testing get_tm()\n");

    tx.magic = TX_MAGIC;
    tx.t = TX_TIME;
    VSTAILQ_INIT(&tx.lines);
    for (int i = 0; i < NRECORDS; i++) {
        recs[i].magic = LOGLINE_MAGIC;
        recs[i].tag = SLT_ReqHeader;
        recs[i].len = strlen("Bar: baz");
        VSTAILQ_INSERT_TAIL(&tx.lines, &recs[i], linelist);
        VSTAILQ_INIT(&recs[i].chunks);
        c[i].magic = CHUNK_MAGIC;
        c[i].data = (char *) calloc(1, config.chunk_size);
        strcpy(c[i].data, "Bar: baz");
        VSTAILQ_INSERT_TAIL(&recs[i].chunks, &c[i], chunklist);
    }
    recs[NRECORDS / 2].tag = SLT_Timestamp;
    recs[NRECORDS / 2].len = strlen(T1);
    strcpy(c[NRECORDS / 2].data, T1);
    recs[NRECORDS - 1].tag = SLT_Timestamp;
    sprintf(c[NRECORDS - 1].data, "Start: %.6f 0.000000 0.000000", TIME);
    recs[NRECORDS - 1].len = strlen(c[NRECORDS - 1].data);
    tm = get_tm(&tx);
    MASSERT(fabs(tm - TIME) < 1e-6);

    /* Start timestamp not found, use the tx timestamp */
    recs[NRECORDS / 2].tag = SLT_ReqHeader;
    recs[NRECORDS - 1].tag = SLT_ReqHeader;
    tm = get_tm(&tx);
    MASSERT(fabs(tm - TX_TIME) < 1e-6);

    /* Empty line list */
    VSTAILQ_INIT(&tx.lines);
    tm = get_tm(&tx);
    MASSERT(fabs(tm - TX_TIME) < 1e-6);

    return NULL;
}

static const char
*test_format_H(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;
    char *str;
    size_t len;

    printf("... testing format_H_*()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

    rec.len = strlen("HTTP/1.1");
    rec.tag = SLT_ReqProtocol;
    strcpy(chunk.data, "HTTP/1.1");
    format_H_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "HTTP/1.1") == 0);
    MASSERT(len == strlen("HTTP/1.1"));

    rec.tag = SLT_BereqProtocol;
    format_H_backend(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "HTTP/1.1") == 0);
    MASSERT(len == strlen("HTTP/1.1"));

    return NULL;
}

static const char
*test_format_b(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;
    char *str;
    size_t len;

    printf("... testing format_b_*()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

#define REQACCT_PAYLOAD "60 0 60 178 105 283"
    rec.len = strlen(REQACCT_PAYLOAD);
    rec.tag = SLT_ReqAcct;
    strcpy(chunk.data, REQACCT_PAYLOAD);
    format_b_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "105") == 0);
    MASSERT(len == 3);

    rec.tag = SLT_BereqAcct;
    format_b_backend(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "105") == 0);
    MASSERT(len == 3);

    return NULL;
}

static const char
*test_format_D(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;
    char *str;
    size_t len;

    printf("... testing format_D_*()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

#define TS_RESP_PAYLOAD "Resp: 1427799478.166798 0.015963 0.000125"
    rec.len = strlen(TS_RESP_PAYLOAD);
    rec.tag = SLT_Timestamp;
    strcpy(chunk.data, TS_RESP_PAYLOAD);
    format_D_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "15963") == 0);
    MASSERT(len == 5);

#define TS_BERESP_PAYLOAD "BerespBody: 1427799478.166678 0.015703 0.000282"
    rec.len = strlen(TS_BERESP_PAYLOAD);
    strcpy(chunk.data, TS_BERESP_PAYLOAD);
    format_D_backend(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "15703") == 0);
    MASSERT(len == 5);

    return NULL;
}

static const char
*test_format_h(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;
    char *str;
    size_t len;

    printf("... testing format_h_*()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

#define REQSTART_PAYLOAD "127.0.0.1 33544"
    rec.len = strlen(REQSTART_PAYLOAD);
    rec.tag = SLT_ReqStart;
    strcpy(chunk.data, REQSTART_PAYLOAD);
    format_h_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "127.0.0.1") == 0);
    MASSERT(len == 9);

#define BACKEND_PAYLOAD "14 default default(127.0.0.1,,80)"
    rec.tag = SLT_Backend;
    rec.len = strlen(BACKEND_PAYLOAD);
    strcpy(chunk.data, BACKEND_PAYLOAD);
    format_h_backend(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "default(127.0.0.1,,80)") == 0);
    MASSERT(len == 22);

    return NULL;
}

static const char
*test_format_I(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;
    char *str;
    size_t len;

    printf("... testing format_I_*()\n");

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);
    MAN(chunk.data);

    rec.len = strlen(REQACCT_PAYLOAD);
    rec.tag = SLT_ReqAcct;
    strcpy(chunk.data, REQACCT_PAYLOAD);
    format_I_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "60") == 0);
    MASSERT(len == 2);

    rec.len = strlen(REQACCT_PAYLOAD);
    rec.tag = SLT_ReqAcct;
    strcpy(chunk.data, REQACCT_PAYLOAD);
    format_I_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "60") == 0);
    MASSERT(len == 2);

    rec.tag = SLT_BereqAcct;
    format_I_backend(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "283") == 0);
    MASSERT(len == 3);

#define PIPEACCT_PAYLOAD "60 60 178 105"
    rec.tag = SLT_PipeAcct;
    rec.len = strlen(PIPEACCT_PAYLOAD);
    strcpy(chunk.data, PIPEACCT_PAYLOAD);
    format_I_client(&tx, NULL, SLT__Bogus, &str, &len);
    MASSERT(strcmp(str, "178") == 0);
    MASSERT(len == 3);

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
    mu_run_test(test_format_get_tm);
    mu_run_test(test_format_b);
    mu_run_test(test_format_D);
    mu_run_test(test_format_H);
    mu_run_test(test_format_h);
    mu_run_test(test_format_I);
    return NULL;
}

TEST_RUNNER
