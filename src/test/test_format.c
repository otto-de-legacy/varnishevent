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

    payload = VSB_new(NULL, NULL, DEFAULT_MAX_RECLEN, VSB_FIXEDLEN);
    MAN(payload);

    time_start_re = VRE_compile(TS_START_REGEX, VRE_CASELESS, &error,
                                &erroroffset);
    VMASSERT(time_start_re != NULL,
             "Error compiling " TS_START_REGEX ": %s (offset %d)",
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
    sprintf(chunk.data, "%s", SHORT_STRING);
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
    sprintf(str, "%0*d", config.max_reclen - 1, 0);
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
*all_tests(void)
{
    mu_run_test(test_format_init);
    mu_run_test(test_format_get_payload);
    mu_run_test(test_format_get_tag);
    mu_run_test(test_format_get_hdr);
    mu_run_test(test_format_get_fld);
    return NULL;
}

TEST_RUNNER
