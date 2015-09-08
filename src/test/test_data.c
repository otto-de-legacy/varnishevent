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
#include <stddef.h>

#include "minunit.h"

#include "../varnishevent.h"
#include "../data.h"

/* __offsetof() used in VSTAILQ_LAST() */
#define __offsetof(t,f) offsetof(t,f)

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
        MASSERT(txn[i].state == TX_FREE);
        MASSERT(txn[i].vxid == -1);
        MASSERT(txn[i].pvxid == -1);
        MASSERT(txn[i].type == VSL_t_unknown);
        MASSERT(txn[i].disp == DISP_NONE);
        MAZ(txn[i].t);
        for (int j = 0; j < max_idx; j++) {
            MCHECK_OBJ_NOTNULL(txn[i].recs[j], REC_NODE_MAGIC);
            MAZ(txn[i].recs[j]->rec);
            if (txn[i].recs[j]->hdrs != NULL)
                for (int k = 0; txn[i].recs[j]->hdrs[k] != magic_end_rec; k++)
                    MAZ(txn[i].recs[j]->hdrs[k]);
        }
        if (VSTAILQ_NEXT(&txn[i], freelist) != NULL)
            tx_free++;
    }
    MASSERT(global_nfree_tx == config.max_data);

    for (int i = 0; i < config.max_data * (max_idx + 1); i++) {
        MCHECK_OBJ(&rec_nodes[i], REC_NODE_MAGIC);
        MAZ(rec_nodes[i].rec);
        if (rec_nodes[i].hdrs != NULL)
            for (int j = 0; rec_nodes[i].hdrs[j] != magic_end_rec; j++)
                MAZ(rec_nodes[i].hdrs[j]);
    }

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

static int chunks_filled = 0;

static void
fill_rec(rec_t *rec, chunk_t *c, int nc)
{
    chunk_t *chunk;

    rec->magic = RECORD_MAGIC;
    rec->len = 42;
    rec->tag = MAX_VSL_TAG/2;
    rec->occupied = 1;
    VSTAILQ_INIT(&rec->chunks);
    for (int i = 0; i < nc; i++) {
        chunk = &c[i];
        VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
        chunk->magic = CHUNK_MAGIC;
        chunk->data = (char *) calloc(1, config.chunk_size);
        chunk->occupied = 1;
        chunks_filled++;
    }
}

#define REC_NODE_CLEARED(n)                                     \
do {                                                            \
    MCHECK_OBJ(n, REC_NODE_MAGIC);                              \
    MAZ((n)->rec);                                              \
    if ((n)->hdrs != NULL) {                                    \
        for (int x = 0; (n)->hdrs[x] != magic_end_rec; x++)     \
            MAZ((n)->hdrs[x]);                                  \
        MASSERT((n)->hdrs[HDRS_PER_NODE] == magic_end_rec);     \
    }                                                           \
} while(0)

#define REC_CLEARED(rec)                        \
do {                                            \
    MCHECK_OBJ_NOTNULL((rec), RECORD_MAGIC);    \
    MASSERT(!OCCUPIED(rec));                    \
    MASSERT((rec)->tag == SLT__Bogus);          \
    MAZ((rec)->len);                            \
    MASSERT(VSTAILQ_EMPTY(&(rec)->chunks));     \
} while(0)

#define CHUNK_CLEARED(chunk)                    \
do {                                            \
    MCHECK_OBJ_NOTNULL((chunk), CHUNK_MAGIC);   \
    MASSERT(!OCCUPIED(chunk));                  \
    MAZ((chunk)->data[0]);                      \
} while(0)
    
static const char
*test_data_clear_tx(void)
{
#define N_NODES (max_idx + 1)
#define HDRS_PER_NODE 5
#define CHUNKS_PER_REC 3
#define NRECS ((max_idx)/2 + (((max_idx) - (max_idx)/2) * HDRS_PER_NODE))
#define NCHUNKS ((NRECS) * (CHUNKS_PER_REC))
    tx_t tx;
    rec_t *rec;
    chunk_t *chunk;
    int n = 0;
    unsigned nfree_tx = 4711, nfree_recs = 815, nfree_chunks = 1147;

    printf("... testing transaction clear\n");

    VSTAILQ_INIT(&local_freetx);
    VSTAILQ_INIT(&local_freerec);
    VSTAILQ_INIT(&local_freechunk);

    tx.magic = TX_MAGIC;
    tx.t = 123456789.0;
    tx.vxid = 314159265;
    tx.pvxid = 2718281828;
    tx.type = VSL_t_req;
    tx.state = TX_WRITTEN;
    tx.disp = DISP_HIT;
    tx.recs = (rec_node_t **) calloc(max_idx, sizeof(rec_node_t *));
    MAN(tx.recs);
    for (int i = 0; i < max_idx/2; i++) {
        tx.recs[i] = &rec_nodes[i];
        rec_nodes[i].magic = REC_NODE_MAGIC;
        rec_nodes[i].rec = &records[i];
        fill_rec(&records[i], &chunks[i * CHUNKS_PER_REC], CHUNKS_PER_REC);
        MASSERT(&chunks[(i * CHUNKS_PER_REC) + CHUNKS_PER_REC - 1]
                == VSTAILQ_LAST(&records[i].chunks, chunk_t, chunklist));
        rec_nodes[i].hdrs = NULL;
    }
    for (int i = max_idx/2; i < max_idx; i++) {
        tx.recs[i] = &rec_nodes[i];
        rec_nodes[i].magic = REC_NODE_MAGIC;
        rec_nodes[i].rec = NULL;
        rec_nodes[i].hdrs = (rec_t **) calloc(HDRS_PER_NODE + 1,
                                              sizeof(rec_t *));
        MAN(rec_nodes[i].hdrs);
        for (int j = 0; j < HDRS_PER_NODE; j++) {
            int idx = max_idx/2 + (i - max_idx/2) * HDRS_PER_NODE + j;
            rec_nodes[i].hdrs[j] = &records[idx];
            fill_rec(&records[idx], &chunks[idx * CHUNKS_PER_REC],
                     CHUNKS_PER_REC);
        }
        rec_nodes[i].hdrs[HDRS_PER_NODE] = magic_end_rec;
    }

    DATA_Clear_Tx(&tx, &local_freetx, &local_freerec, &local_freechunk,
                  &nfree_tx, &nfree_recs, &nfree_chunks);

    MASSERT(nfree_tx == 4712);
    MASSERT(nfree_recs == 815 + NRECS);
    MASSERT(nfree_chunks == 1147 + NCHUNKS);

    MCHECK_OBJ(&tx, TX_MAGIC);
    MASSERT(tx.state == TX_FREE);
    MASSERT(tx.vxid == -1);
    MASSERT(tx.pvxid == -1);
    MASSERT(tx.type == VSL_t_unknown);
    MASSERT(tx.disp == DISP_NONE);
    MAZ(tx.t);
    for (int i = 0; i < max_idx; i++) {
        REC_NODE_CLEARED(tx.recs[i]);
        REC_NODE_CLEARED(&rec_nodes[i]);
    }

    MASSERT(!VSTAILQ_EMPTY(&local_freetx));
    MASSERT(VSTAILQ_FIRST(&local_freetx) == &tx);
    MAZ(VSTAILQ_NEXT(&tx, freelist));

    MASSERT(!VSTAILQ_EMPTY(&local_freerec));
    VSTAILQ_FOREACH(rec, &local_freerec, freelist) {
        REC_CLEARED(rec);
        n++;
    }
    MASSERT(n == NRECS);

    MASSERT(!VSTAILQ_EMPTY(&local_freechunk));
    n = 0;
    VSTAILQ_FOREACH(chunk, &local_freechunk, freelist) {
        CHUNK_CLEARED(chunk);
        n++;
    }
    MASSERT(n == NCHUNKS);

    for (int i = 0; i < NRECS; i++)
        REC_CLEARED(&records[i]);

    for (int i = 0; i < NCHUNKS; i++)
        CHUNK_CLEARED(&chunks[i]);

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
