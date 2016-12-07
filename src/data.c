/*-
 * Copyright (c) 2013-2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013-2015 Otto Gmbh & Co KG
 * All rights reserved
 * Use only with permission
 *
 * Authors: Geoffrey Simmons <geoffrey.simmons@uplex.de>
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

#include <pthread.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <stddef.h>

#include "varnishevent.h"
#include "data.h"
#include "hdrtrie.h"

#include "vas.h"
#include "miniobj.h"
#include "vqueue.h"
#include "vsb.h"
#include "vmb.h"
#include "common/common.h"

#define __offsetof(st, m) offsetof(st,m)

/* Preprend head2 before head1, result in head1, head2 empty afterward */
#define	VSTAILQ_PREPEND(head1, head2) do {                      \
        if (VSTAILQ_EMPTY((head2)))                             \
            break;                                              \
	if (VSTAILQ_EMPTY((head1)))                             \
            (head1)->vstqh_last = (head2)->vstqh_last;          \
	else                                                    \
            *(head2)->vstqh_last = VSTAILQ_FIRST((head1));      \
        VSTAILQ_FIRST((head1)) = VSTAILQ_FIRST((head2));        \
        VSTAILQ_INIT((head2));                                  \
} while (0)

static const char *statename[] = {
    "FREE", "OPEN", "DONE", "SUBMITTED", "FORMATTING", "WRITTEN"
};

static pthread_mutex_t freetx_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freerec_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freechunk_lock = PTHREAD_MUTEX_INITIALIZER;
static char *bufptr;
static txhead_t freetxhead;
static rechead_t freerechead;
static chunkhead_t freechunkhead;

static const char bogus_rec;
const void * const magic_end_rec = &bogus_rec;

static void
data_Cleanup(void)
{
    free(txn);
    free(rec_nodes);
    free(records);
    free(chunks);
    free(bufptr);
    AZ(pthread_mutex_destroy(&freetx_lock));
    AZ(pthread_mutex_destroy(&freerec_lock));
    AZ(pthread_mutex_destroy(&freechunk_lock));
}

static unsigned
data_clear_rec(rec_t *rec, rechead_t * const freerec,
               chunkhead_t * const freechunk)
{
    chunk_t *chunk;
    unsigned nchunk = 0;

    CHECK_OBJ_NOTNULL(rec, RECORD_MAGIC);
    assert(OCCUPIED(rec));
    while ((chunk = VSTAILQ_FIRST(&rec->chunks)) != NULL) {
        CHECK_OBJ(chunk, CHUNK_MAGIC);
        assert(OCCUPIED(chunk));
        chunk->occupied = 0;
        *chunk->data = '\0';
        VSTAILQ_REMOVE_HEAD(&rec->chunks, chunklist);
        VSTAILQ_INSERT_HEAD(freechunk, chunk, freelist);
        nchunk++;
    }
    assert(VSTAILQ_EMPTY(&rec->chunks));
    rec->tag = SLT__Bogus;
    rec->len = 0;
    rec->occupied = 0;
    VSTAILQ_INSERT_HEAD(freerec, rec, freelist);
    return nchunk;
}

void
DATA_Clear_Tx(tx_t * const tx, txhead_t * const freetx,
              rechead_t * const freerec, chunkhead_t * const freechunk,
              unsigned * restrict const nfree_tx,
              unsigned * restrict const nfree_rec,
              unsigned * restrict const nfree_chunk)
{
    unsigned nchunk = 0, nrec = 0;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_WRITTEN);
    
    tx->vxid = -1;
    tx->pvxid = -1;
    tx->type = VSL_t_unknown;
    tx->t = 0.;
    tx->disp = DISP_NONE;

    for (int i = 0; i < max_idx; i++) {
        rec_node_t *rec_node = tx->recs[i];
        CHECK_OBJ_NOTNULL(rec_node, REC_NODE_MAGIC);
        if (rec_node->rec != NULL) {
            CHECK_OBJ(rec_node->rec, RECORD_MAGIC);
            nchunk += data_clear_rec(rec_node->rec, freerec, freechunk);
            nrec++;
            rec_node->rec = NULL;
            continue;
        }
        if (rec_node->hdrs == NULL)
            continue;
        for (int j = 0; rec_node->hdrs[j] != magic_end_rec; j++) {
            rec_t *rec;
            if ((rec = rec_node->hdrs[j]) != NULL) {
                CHECK_OBJ(rec, RECORD_MAGIC);
                nchunk += data_clear_rec(rec, freerec, freechunk);
                nrec++;
                rec_node->hdrs[j] = NULL;
            }
        }
    }
    tx->state = TX_FREE;
    VSTAILQ_INSERT_HEAD(freetx, tx, freelist);
    *nfree_tx += 1;
    *nfree_rec += nrec;
    *nfree_chunk += nchunk;
    MON_StatsUpdate(STATS_WRITTEN, nrec, nchunk);
}

int
DATA_Init(void)
{
    int bufidx = 0, chunks_per_rec, recs_per_tx = FMT_Estimate_RecsPerTx(),
        nrecnodes = config.max_data * (max_idx + 1);

    LOG_Log(LOG_DEBUG, "Estimated %d records per transaction", recs_per_tx);
    nrecords = config.max_data * recs_per_tx;
    AN(config.chunk_size);
    chunks_per_rec
        = (config.max_reclen + config.chunk_size - 1) / config.chunk_size;
    nchunks = nrecords * chunks_per_rec;

    LOG_Log(LOG_DEBUG, "Allocating space for %d chunks (%d bytes)",
            nchunks, nchunks * config.chunk_size);
    bufptr = (char *) calloc(nchunks, config.chunk_size);
    if (bufptr == NULL)
        return errno;

    LOG_Log(LOG_DEBUG, "Allocating table for %d chunks (%d bytes)", nchunks,
            nchunks * sizeof(chunk_t));
    chunks = (chunk_t *) calloc(nchunks, sizeof(chunk_t));
    if (chunks == NULL) {
        free(bufptr);
        return errno;
    }
    VSTAILQ_INIT(&freechunkhead);
    for (int i = 0; i < nchunks; i++) {
        chunks[i].magic = CHUNK_MAGIC;
        chunks[i].occupied = 0;
        chunks[i].data = &bufptr[bufidx++ * config.chunk_size];
        VSTAILQ_INSERT_TAIL(&freechunkhead, &chunks[i], freelist);
    }
    assert(bufidx == nchunks);

    LOG_Log(LOG_DEBUG, "Allocating table for %d records (%d bytes)", nrecords,
            nrecords * sizeof(rec_t));
    records = (rec_t *) calloc(nrecords, sizeof(rec_t));
    if (records == NULL) {
        free(bufptr);
        free(chunks);
        return errno;
    }
    VSTAILQ_INIT(&freerechead);
    for (int i = 0; i < nrecords; i++) {
        records[i].magic = RECORD_MAGIC;
        records[i].occupied = 0;
        records[i].tag = SLT__Bogus;
        records[i].len = 0;
        VSTAILQ_INIT(&records[i].chunks);
        VSTAILQ_INSERT_TAIL(&freerechead, &records[i], freelist);
    }

    LOG_Log(LOG_DEBUG, "Allocating table for %d recnodes (%d bytes)",
            nrecnodes, nrecnodes * sizeof(rec_node_t));
    rec_nodes = (rec_node_t *) calloc(nrecnodes, sizeof(rec_node_t));
    if (rec_nodes == NULL) {
        free(bufptr);
        free(chunks);
        free(records);
        return errno;
    }
    for (int i = 0; i < nrecnodes; i++)
        rec_nodes[i].magic = REC_NODE_MAGIC;

    LOG_Log(LOG_DEBUG, "Allocating table for %d transactions (%d bytes)",
            config.max_data, config.max_data * sizeof(tx_t));
    txn = (tx_t *) calloc(config.max_data, sizeof(tx_t));
    if (txn == NULL) {
        free(bufptr);
        free(chunks);
        free(records);
        free(rec_nodes);
        return errno;
    }
    VSTAILQ_INIT(&freetxhead);
    for (int i = 0; i < config.max_data; i++) {
        txn[i].magic = TX_MAGIC;
        txn[i].state = TX_FREE;
        txn[i].vxid = -1;
        txn[i].pvxid = -1;
        txn[i].type = VSL_t_unknown;
        txn[i].t = 0.;
        txn[i].disp = DISP_NONE;
        txn[i].recs = (rec_node_t **) malloc(max_idx * sizeof(rec_node_t *));
        AN(txn[i].recs);
        for (int j = 0; j < max_idx; j++) {
            assert((i * max_idx) + j < nrecnodes);
            txn[i].recs[j] = &rec_nodes[(i * max_idx) + j];
            CHECK_OBJ(txn[i].recs[j], REC_NODE_MAGIC);
        }
        for (int j = 0; j < MAX_VSL_TAG; j++) {
            int idx, nhdrs;

            idx = tag2idx[j];
            if (idx == -1)
                continue;
            assert(idx < max_idx);
            nhdrs = HDR_N(hdr_trie[j]);
            if (nhdrs == 0) {
                txn[i].recs[idx]->hdrs = NULL;
                continue;
            }
            txn[i].recs[idx]->hdrs = (rec_t **) calloc(nhdrs + 1,
                                                       sizeof(rec_t *));
            txn[i].recs[idx]->hdrs[nhdrs] = TRUST_ME(magic_end_rec);
        }
	VSTAILQ_INSERT_TAIL(&freetxhead, &txn[i], freelist);
    }

    tx_occ = rec_occ = chunk_occ = tx_occ_hi = rec_occ_hi = chunk_occ_hi = 0;
    global_nfree_tx = config.max_data;
    global_nfree_rec = nrecords;
    global_nfree_chunk = nchunks;

    atexit(data_Cleanup);
    
    return(0);
}

/* 
 * take all free entries from the datatable for lockless allocation
 */
#define DATA_Take_Free(type)                            \
unsigned                                                \
DATA_Take_Free##type(struct type##head_s *dst)          \
{                                                       \
    unsigned nfree;                                     \
                                                        \
    AZ(pthread_mutex_lock(&free##type##_lock));         \
    VSTAILQ_PREPEND(dst, &free##type##head);            \
    nfree = global_nfree_##type;                        \
    global_nfree_##type = 0;                            \
    AZ(pthread_mutex_unlock(&free##type##_lock));       \
    return nfree;                                       \
}

DATA_Take_Free(tx)
DATA_Take_Free(rec)
DATA_Take_Free(chunk)

/*
 * return to global freelist
 * returned must be locked by caller, if required
 */
#define DATA_Return_Free(type)                                          \
void                                                                    \
DATA_Return_Free##type(struct type##head_s *returned, unsigned nreturned) \
{                                                                       \
    AZ(pthread_mutex_lock(&free##type##_lock));                         \
    VSTAILQ_PREPEND(&free##type##head, returned);                       \
    global_nfree_##type += nreturned;                                   \
    AZ(pthread_mutex_unlock(&free##type##_lock));                       \
}

DATA_Return_Free(tx)
DATA_Return_Free(rec)
DATA_Return_Free(chunk)

static void
data_dump_rec(int txidx, int nodeidx, int hdridx, rec_t *rec, struct vsb *data)
{
    AN(rec);
    AN(data);

    if (rec->magic != RECORD_MAGIC) {
        LOG_Log(LOG_ERR,
                "Invalid record at tx %d node %d hdr %d, magic = 0x%08x, "
                "expected 0x%08x", txidx, nodeidx, hdridx, rec->magic,
                RECORD_MAGIC);
        return;
    }
    VSB_printf(data, "%s ", VSL_tags[rec->tag]);
    if (rec->len) {
        int n = rec->len;
        chunk_t *chunk = VSTAILQ_FIRST(&rec->chunks);
        while (n > 0 && chunk != NULL) {
            if (chunk->magic != CHUNK_MAGIC) {
                LOG_Log(LOG_ERR,
                        "Invalid chunk at tx %d node %d hdr %d, "
                        "magic = 0x%08x, expected 0x%08x",
                        txidx, nodeidx, hdridx, chunk->magic, CHUNK_MAGIC);
                continue;
            }
            int cp = n;
            if (cp > config.chunk_size)
                cp = config.chunk_size;
            VSB_bcat(data, chunk->data, cp);
            n -= cp;
            chunk = VSTAILQ_NEXT(chunk, chunklist);
        }
    }
}

void
DATA_Dump(void)
{
    struct vsb *data;

    if (txn == NULL)
        return;

    data = VSB_new_auto();
    
    for (int i = 0; i < config.max_data; i++) {
        tx_t *tx;
        rec_node_t *rec_node;

        if (txn[i].magic != TX_MAGIC) {
            LOG_Log(LOG_ERR,
                "Invalid tx at index %d, magic = 0x%08x, expected 0x%08x",
                i, txn[i].magic, TX_MAGIC);
            continue;
        }
        
        if (txn[i].state == TX_FREE)
            continue;

        tx = &txn[i];
        VSB_clear(data);

        VSB_printf(data,
                   "Tx entry %d: vxid=%u pvxid=%d state=%s dir=%c records={",
                   i, tx->vxid, tx->pvxid, statename[tx->state],
                   C(tx->type) ? 'c' : B(tx->type) ? 'b' : '-');

        for (int j = 0; j < max_idx; j++) {
            rec_t *rec;

            rec_node = tx->recs[j];
            AN(rec_node);
            if (rec_node->magic != REC_NODE_MAGIC) {
                LOG_Log(LOG_ERR, "Invalid rec node at tx %d node %d, "
                        "magic = 0x%08x, expected 0x%08x", i, j,
                        rec_node->magic, REC_NODE_MAGIC);
                continue;
            }
            if (rec_node->rec != NULL) {
                data_dump_rec(i, j, -1, rec_node->rec, data);
                continue;
            }
            if (rec_node->hdrs == NULL)
                continue;
            for (int k = 0; rec_node->hdrs[k] != magic_end_rec; k++) {
                rec = rec_node->hdrs[k];
                if (rec == NULL)
                    continue;
                data_dump_rec(i, j, k, rec, data);
            }
        }

        VSB_putc(data, '}');
        VSB_finish(data);

        LOG_Log(LOG_INFO, "%s", VSB_data(data));
    }
}
