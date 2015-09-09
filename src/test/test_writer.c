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

int
RDR_Depleted(void)
{
    return 0;
}

static char
*test_timeout(void)
{
    tx_t tx;
    rec_node_t node, *nptr[1];

    printf("... testing write timeouts\n");

    CONF_Init();
    VSB_clear(config.cformat);
    MAZ(FMT_Init(&errmsg[0]));

    strcpy(config.log_file, "-");
    MAZ(LOG_Open("test_writer"));

    config.output_timeout.tv_sec = 1;
    config.output_timeout.tv_usec = 0;

    MAZ(WRT_Init());

    VSTAILQ_INIT(&wrt_freetx);
    MASSERT(VSTAILQ_EMPTY(&wrt_freetx));

    tx.magic = TX_MAGIC;
    tx.recs = nptr;
    nptr[0] = &node;
    node.magic = REC_NODE_MAGIC;
    node.rec = NULL;
    node.hdrs = NULL;

    for (int i = 0; i < THRESHOLD; i++) {
        tx.state = TX_SUBMITTED;
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
