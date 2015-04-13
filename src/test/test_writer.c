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

#include "../varnishevent.h"
#include "../writer.h"
#include "minunit.h"

int tests_run = 0;
static char errmsg[BUFSIZ];

#define THRESHOLD 1000

void
RDR_Stats(void)
{}

static char
*test_timeout(void)
{
    tx_t tx;
    logline_t rec;
    chunk_t chunk;

    printf("... testing write timeouts\n");

    CONF_Init();
    strcpy(config.cformat, "");
    MAZ(FMT_Init(&errmsg[0]));

    strcpy(config.log_file, "-");
    MAZ(LOG_Open("test_writer"));

    config.output_timeout.tv_sec = 1;
    config.output_timeout.tv_usec = 0;

    MAZ(WRT_Init());

    VSTAILQ_INIT(&wrt_freetx);
    MASSERT(VSTAILQ_EMPTY(&wrt_freetx));

    /* XXX: common helper functions with test_format */
    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.lines);
    VSTAILQ_INSERT_TAIL(&tx.lines, &rec, linelist);
    rec.magic = LOGLINE_MAGIC;
    VSTAILQ_INIT(&rec.chunks);
    VSTAILQ_INSERT_TAIL(&rec.chunks, &chunk, chunklist);
    chunk.magic = CHUNK_MAGIC;
    chunk.data = (char *) calloc(1, config.chunk_size);

    for (int i = 0; i < THRESHOLD; i++) {
        tx.state = DATA_DONE;
        tx.type = VSL_t_req;

        wrt_write(&tx);
        MAZ(to.tv_sec);
        MASSERT(1e6 - to.tv_usec < THRESHOLD);
    }
    return NULL;
}

static const char
*all_tests(void)
{
    mu_run_test(test_timeout);
    return NULL;
}

TEST_RUNNER
