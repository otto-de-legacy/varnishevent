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

#include "varnishevent.h"
#include "vas.h"
#include "miniobj.h"
#include "vqueue.h"
#include "vsb.h"

/* Preprend head2 before head1, result in head1, head2 empty afterward */
#define	VSTAILQ_PREPEND(head1, head2) do {                      \
	if (VSTAILQ_EMPTY((head1))) {                           \
		(head1)->vstqh_first = (head2)->vstqh_first;    \
		(head1)->vstqh_last = (head2)->vstqh_last;      \
	}                                                       \
	else if (!VSTAILQ_EMPTY((head2))) {                     \
		(head2)->vstqh_last = &(head1)->vstqh_first;    \
		(head1)->vstqh_first = (head2)->vstqh_first;    \
	}                                                       \
        VSTAILQ_INIT((head2));                                  \
} while (0)

static const char *statename[3] = { "EMPTY", "DONE" };

static pthread_mutex_t freetx_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freeline_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freechunk_lock = PTHREAD_MUTEX_INITIALIZER;
static char *bufptr;
static txhead_t freetxhead;
static linehead_t freelinehead;
static chunkhead_t freechunkhead;

static void
data_Cleanup(void)
{
    free(txn);
    free(lines);
    free(chunks);
    free(bufptr);
    AZ(pthread_mutex_destroy(&freetx_lock));
    AZ(pthread_mutex_destroy(&freeline_lock));
    AZ(pthread_mutex_destroy(&freechunk_lock));
}

void
DATA_Clear_Tx(tx_t * const tx, txhead_t * const freetx,
              linehead_t * const freerec, chunkhead_t * const freechunk,
              unsigned * restrict const nfree_tx,
              unsigned * restrict const nfree_rec,
              unsigned * restrict const nfree_chunk)
{
    logline_t *rec;
    chunk_t *chunk;

    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    
    tx->state = TX_EMPTY;
    tx->vxid = -1;
    tx->type = VSL_t_unknown;
    tx->t = 0.;

    while ((rec = VSTAILQ_FIRST(&tx->lines)) != NULL) {
        CHECK_OBJ(rec, LOGLINE_MAGIC);
        rec->state = DATA_EMPTY;
        rec->tag = SLT__Bogus;
        rec->len = 0;
        while ((chunk = VSTAILQ_FIRST(&rec->chunks)) != NULL) {
            CHECK_OBJ(chunk, CHUNK_MAGIC);
            chunk->state = DATA_EMPTY;
            *chunk->data = '\0';
            VSTAILQ_REMOVE_HEAD(&rec->chunks, chunklist);
            VSTAILQ_INSERT_HEAD(freechunk, chunk, freelist);
            *nfree_chunk += 1;
        }
        assert(VSTAILQ_EMPTY(&rec->chunks));
        VSTAILQ_REMOVE_HEAD(&tx->lines, linelist);
        VSTAILQ_INSERT_HEAD(freerec, rec, freelist);
        *nfree_rec += 1;
    }
    assert(VSTAILQ_EMPTY(&tx->lines));
    VSTAILQ_INSERT_HEAD(freetx, tx, freelist);
    *nfree_tx += 1;
}

int
DATA_Init(void)
{
    int bufidx = 0, chunks_per_rec, lines_per_tx = FMT_Estimate_RecsPerTx();
    
    nrecords = config.max_data * lines_per_tx;
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
        chunks[i].state = DATA_EMPTY;
        chunks[i].data = &bufptr[bufidx++ * config.chunk_size];
        VSTAILQ_INSERT_TAIL(&freechunkhead, &chunks[i], freelist);
    }
    assert(bufidx == nchunks);

    LOG_Log(LOG_DEBUG, "Allocating table for %d records (%d bytes)", nrecords,
            nrecords * sizeof(logline_t));
    lines = (logline_t *) calloc(nrecords, sizeof(logline_t));
    if (lines == NULL) {
        free(bufptr);
        free(chunks);
        return errno;
    }
    VSTAILQ_INIT(&freelinehead);
    for (int i = 0; i < nrecords; i++) {
        lines[i].magic = LOGLINE_MAGIC;
        lines[i].state = DATA_EMPTY;
        lines[i].tag = SLT__Bogus;
        lines[i].len = 0;
        VSTAILQ_INIT(&lines[i].chunks);
        VSTAILQ_INSERT_TAIL(&freelinehead, &lines[i], freelist);
    }

    LOG_Log(LOG_DEBUG, "Allocating table for %d transactions (%d bytes)",
            config.max_data, config.max_data * sizeof(tx_t));
    txn = (tx_t *) calloc(config.max_data, sizeof(tx_t));
    if (txn == NULL) {
        free(bufptr);
        free(chunks);
        free(lines);
        return errno;
    }
    VSTAILQ_INIT(&freetxhead);
    for (int i = 0; i < config.max_data; i++) {
        txn[i].magic = TX_MAGIC;
        txn[i].state = TX_EMPTY;
        txn[i].vxid = -1;
        txn[i].type = VSL_t_unknown;
        VSTAILQ_INIT(&txn[i].lines);
	VSTAILQ_INSERT_TAIL(&freetxhead, &txn[i], freelist);
    }

    data_open = data_done = data_occ_hi = 0;
    global_nfree_tx = config.max_data;
    global_nfree_line = nrecords;
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
DATA_Take_Free(line)
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
DATA_Return_Free(line)
DATA_Return_Free(chunk)

void
DATA_Dump(void)
{
    struct vsb *data;

    if (txn == NULL)
        return;

    data = VSB_new_auto();
    
    for (int i = 0; i < config.max_data; i++) {
        tx_t *tx;
        logline_t *rec;

        if (txn[i].magic != TX_MAGIC) {
            LOG_Log(LOG_ALERT,
                "Invalid tx at index %d, magic = 0x%08x, expected 0x%08x",
                i, txn[i].magic, TX_MAGIC);
            continue;
        }
        
        if (txn[i].state == TX_EMPTY)
            continue;

        tx = &txn[i];
        VSB_clear(data);

        VSB_printf(data, "Tx entry %d: vxid=%u state=%s dir=%c records={",
            i, tx->vxid, statename[tx->state],
            C(tx->type) ? 'c' : B(tx->type) ? 'b' : '-');

        VSTAILQ_FOREACH(rec, &tx->lines, linelist) {
            if (rec == NULL)
                continue;
            if (rec->magic != LOGLINE_MAGIC) {
                LOG_Log(LOG_ALERT,
                    "Invalid record at tx %d, magic = 0x%08x, expected 0x%08x",
                    i, rec->magic, LOGLINE_MAGIC);
                continue;
            }
            VSB_printf(data, "%s ", VSL_tags[rec->tag]);
            if (rec->len) {
                int n = rec->len;
                chunk_t *chunk = VSTAILQ_FIRST(&rec->chunks);
                while (n > 0 && chunk != NULL) {
                    if (chunk->magic != CHUNK_MAGIC) {
                        LOG_Log(LOG_ALERT,
                            "Invalid chunk at tx %d, magic = 0x%08x, "
                            "expected 0x%08x",
                            i, chunk->magic, CHUNK_MAGIC);
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

        VSB_putc(data, '}');
        VSB_finish(data);

        LOG_Log(LOG_INFO, "%s", VSB_data(data));
    }
}
