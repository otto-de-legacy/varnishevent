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
#define SHORT_STRING "foo bar baz quux"
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
*all_tests(void)
{
    mu_run_test(test_format_init);
    mu_run_test(test_format_get_payload);
    return NULL;
}

TEST_RUNNER
