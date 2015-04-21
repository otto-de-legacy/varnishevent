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

#include "minunit.h"

#include "../varnishevent.h"

int tests_run = 0;

static txhead_t local_freetx = VSTAILQ_HEAD_INITIALIZER(local_freetx);
static rechead_t local_freerec = VSTAILQ_HEAD_INITIALIZER(local_freerec);
static chunkhead_t local_freechunk = VSTAILQ_HEAD_INITIALIZER(local_freechunk);

/* So that we don't have to link monitor.o, and hence varnishevent.o */
void
MON_StatsUpdate(stats_update_t update, unsigned nrec, unsigned nchunk)
{
    (void) update;
    (void) nrec;
    (void) nchunk;
}

/* N.B.: Always run the tests in this order */
static char
*test_data_init(void)
{
    int err;
    char fmterr[BUFSIZ];
    unsigned tx_free = 0, rec_free = 0, chunk_free = 0;

    printf("... testing data table initialization\n");

    MAZ(LOG_Open("test_data"));
    CONF_Init();
    MAZ(FMT_Init(fmterr));

    VMASSERT((err = DATA_Init()) == 0, "DATA_Init: %s", strerror(err));
    MAN(txn);

    for (int i = 0; i < config.max_data; i++) {
        MCHECK_OBJ(&txn[i], TX_MAGIC);
        MASSERT(!OCCUPIED(&txn[i]));
        MASSERT(txn[i].vxid == -1);
        MASSERT(txn[i].pvxid == -1);
        MASSERT(txn[i].type == VSL_t_unknown);
        MAZ(txn[i].t);
        MASSERT(VSTAILQ_EMPTY(&txn[i].recs));
        if (VSTAILQ_NEXT(&txn[i], freelist) != NULL)
            tx_free++;
    }
    MASSERT(global_nfree_tx == config.max_data);

    for (int i = 0; i < nrecords; i++) {
        MCHECK_OBJ(&records[i], RECORD_MAGIC);
        MASSERT(!OCCUPIED(&records[i]));
        MASSERT(records[i].tag == SLT__Bogus);
        MASSERT(records[i].len == 0);
        MASSERT(VSTAILQ_EMPTY(&records[i].chunks));
        if (VSTAILQ_NEXT(&records[i], freelist) != NULL)
            rec_free++;
    }
    MASSERT(global_nfree_rec == nrecords);

    for (int i = 0; i < nchunks; i++) {
        MCHECK_OBJ(&chunks[i], CHUNK_MAGIC);
        MASSERT(!OCCUPIED(&chunks[i]));
        MASSERT(chunks[i].data == (chunks[0].data + (i * config.chunk_size)));
        if (VSTAILQ_NEXT(&chunks[i], freelist) != NULL)
            chunk_free++;
    }
    MASSERT(global_nfree_chunk == nchunks);

    MASSERT(tx_free == config.max_data - 1);
    MASSERT(rec_free == nrecords - 1);
    MASSERT(chunk_free == nchunks - 1);

    return NULL;
}

static const char
*test_data_take_tx(void)
{
    unsigned nfree, cfree = 0;
    tx_t *tx;

    printf("... testing tx freelist take\n");

    nfree = DATA_Take_Freetx(&local_freetx);
    
    MASSERT(nfree == config.max_data);
    MASSERT(!VSTAILQ_EMPTY(&local_freetx));
    VSTAILQ_FOREACH(tx, &local_freetx, freelist) {
        MCHECK_OBJ_NOTNULL(tx, TX_MAGIC);
        cfree++;
    }
    MAZ(global_nfree_tx);
    MASSERT(nfree == cfree);

    return NULL;
}

static const char
*test_data_take_rec(void)
{
    unsigned nfree, cfree = 0;
    rec_t *rec;

    printf("... testing record freelist take\n");

    nfree = DATA_Take_Freerec(&local_freerec);
   
    MAZ(global_nfree_rec);
    MASSERT(nfree == nrecords);
    MASSERT(!VSTAILQ_EMPTY(&local_freerec));
    VSTAILQ_FOREACH(rec, &local_freerec, freelist) {
        MCHECK_OBJ_NOTNULL(rec, RECORD_MAGIC);
        cfree++;
    }
    MASSERT(nfree == cfree);

    return NULL;
}

static const char
*test_data_take_chunks(void)
{
    unsigned nfree, cfree = 0;
    chunk_t *chunk;

    printf("... testing chunk freelist take\n");

    nfree = DATA_Take_Freechunk(&local_freechunk);
   
    MAZ(global_nfree_chunk);
    MASSERT(nfree == nchunks);
    MASSERT(!VSTAILQ_EMPTY(&local_freechunk));
    VSTAILQ_FOREACH(chunk, &local_freechunk, freelist) {
        MCHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
        cfree++;
    }
    MASSERT(nfree == cfree);

    return NULL;
}

static const char
*test_data_return_tx(void)
{
    printf("... testing tx freelist return\n");

    DATA_Return_Freetx(&local_freetx, config.max_data);

    MASSERT(VSTAILQ_EMPTY(&local_freetx));
    MASSERT(global_nfree_tx == config.max_data);

    return NULL;
}

static const char
*test_data_return_rec(void)
{
    printf("... testing record freelist return\n");

    DATA_Return_Freerec(&local_freerec, nrecords);

    MASSERT(VSTAILQ_EMPTY(&local_freerec));
    MASSERT(global_nfree_rec == nrecords);

    return NULL;
}

static const char
*test_data_return_chunk(void)
{
    printf("... testing chunk freelist return\n");

    DATA_Return_Freechunk(&local_freechunk, nchunks);

    MASSERT(VSTAILQ_EMPTY(&local_freechunk));
    MASSERT(global_nfree_chunk == nchunks);

    return NULL;
}

static const char
*test_data_prepend(void)
{
    tx_t *tx;
    int n = 0;

    printf("... testing freelist prepend\n");

    MASSERT(VSTAILQ_EMPTY(&local_freetx));
    /* Return an empty list */
    DATA_Return_Freetx(&local_freetx, 0);
    MASSERT(VSTAILQ_EMPTY(&local_freetx));
    MASSERT(global_nfree_tx == config.max_data);

    DATA_Take_Freetx(&local_freetx);
    VSTAILQ_INIT(&local_freetx);
    /* insert the first 10 txn to the local list */
    for (int i = 0; i < 10; i++)
        VSTAILQ_INSERT_TAIL(&local_freetx, &txn[i], freelist);
    /* Prepend them to the global free list */
    DATA_Return_Freetx(&local_freetx, 10);
    /* insert the next 10 txn */
    VSTAILQ_INIT(&local_freetx);
    for (int i = 10; i < 20; i++)
        VSTAILQ_INSERT_TAIL(&local_freetx, &txn[i], freelist);
    /* Prepend them to the global list */
    DATA_Return_Freetx(&local_freetx, 10);
    /*
     * Take the global list, and verify that txn 10-19 are at the front,
     * followed by txn 0-9.
     */
    DATA_Take_Freetx(&local_freetx);
    VSTAILQ_FOREACH(tx, &local_freetx, freelist) {
        if (n < 10)
            MASSERT(tx == &txn[n + 10]);
        else
            MASSERT(tx == &txn[n - 10]);
        n++;
    }
    MASSERT(n == 20);

    return NULL;
}

static const char
*test_data_clear_tx(void)
{
#define NRECS 10
#define CHUNKS_PER_REC 3
    tx_t tx;
    rec_t r[NRECS], *rec;
    chunk_t c[NRECS * CHUNKS_PER_REC], *chunk;
    int n = 0;
    unsigned nfree_tx = 4711, nfree_recs = 815, nfree_chunks = 1147;

    printf("... testing transaction clear\n");

    VSTAILQ_INIT(&local_freetx);
    VSTAILQ_INIT(&local_freerec);
    VSTAILQ_INIT(&local_freechunk);

    tx.magic = TX_MAGIC;
    VSTAILQ_INIT(&tx.recs);
    for (int i = 0; i < NRECS; i++) {
        VSTAILQ_INSERT_TAIL(&tx.recs, &r[i], reclist);
        r[i].magic = RECORD_MAGIC;
        VSTAILQ_INIT(&r[i].chunks);
        for (int j = 0; j < CHUNKS_PER_REC; j++) {
            chunk = &c[i*CHUNKS_PER_REC + j];
            VSTAILQ_INSERT_TAIL(&r[i].chunks, chunk, chunklist);
            chunk->magic = CHUNK_MAGIC;
            chunk->data = (char *) calloc(1, config.chunk_size);
        }
    }

    DATA_Clear_Tx(&tx, &local_freetx, &local_freerec, &local_freechunk,
                  &nfree_tx, &nfree_recs, &nfree_chunks);

    MASSERT(nfree_tx == 4712);
    MASSERT(nfree_recs == 815 + NRECS);
    MASSERT(nfree_chunks == 1147 + NRECS*CHUNKS_PER_REC);

    MCHECK_OBJ(&tx, TX_MAGIC);
    MASSERT(!OCCUPIED(&tx));
    MASSERT(tx.vxid == -1);
    MASSERT(tx.pvxid == -1);
    MASSERT(tx.type == VSL_t_unknown);
    MAZ(tx.t);
    MASSERT(VSTAILQ_EMPTY(&tx.recs));

    MASSERT(!VSTAILQ_EMPTY(&local_freetx));
    MASSERT(VSTAILQ_FIRST(&local_freetx) == &tx);
    MAZ(VSTAILQ_NEXT(&tx, freelist));

    MASSERT(!VSTAILQ_EMPTY(&local_freerec));
    VSTAILQ_FOREACH(rec, &local_freerec, freelist) {
        MCHECK_OBJ_NOTNULL(rec, RECORD_MAGIC);
        MASSERT(!OCCUPIED(rec));
        MASSERT(rec->tag == SLT__Bogus);
        MAZ(rec->len);
        MASSERT(VSTAILQ_EMPTY(&tx.recs));
        n++;
    }
    MASSERT(n == NRECS);

    MASSERT(!VSTAILQ_EMPTY(&local_freechunk));
    n = 0;
    VSTAILQ_FOREACH(chunk, &local_freechunk, freelist) {
        MCHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
        MASSERT(!OCCUPIED(chunk));
        MAZ(chunk->data[0]);
        n++;
        free(chunk->data);
    }
    MASSERT(n == NRECS * CHUNKS_PER_REC);

    return NULL;
}

static const char
*all_tests(void)
{
    mu_run_test(test_data_init);
    mu_run_test(test_data_take_tx);
    mu_run_test(test_data_take_rec);
    mu_run_test(test_data_take_chunks);
    mu_run_test(test_data_return_tx);
    mu_run_test(test_data_return_rec);
    mu_run_test(test_data_return_chunk);
    mu_run_test(test_data_prepend);
    mu_run_test(test_data_clear_tx);
    return NULL;
}

TEST_RUNNER
