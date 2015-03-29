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

#define FAKE_DEFAULT_LINES_PER_TX 10

#if 0
static const char *statename[3] = { "EMPTY", "OPEN", "DONE" };
#endif

static pthread_mutex_t freetx_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freeline_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t freechunk_lock = PTHREAD_MUTEX_INITIALIZER;
static char *bufptr;
static txhead_t freetxhead;
static linehead_t freelinehead;
static chunkhead_t freechunkhead;

static int lines_per_tx = FAKE_DEFAULT_LINES_PER_TX;

#if 0
static void
free_hdrs(hdr_t *hdrs)
{
    if (hdrs != NULL) {
        free(hdrs->record);
        free(hdrs);
    }
}
#endif

static void
data_Cleanup(void)
{
    for (int i = 0; i < config.max_data; i++) {
            /* XXX: etc. ... */
    }
    free(txn);
    free(bufptr);
    AZ(pthread_mutex_destroy(&freetx_lock));
    AZ(pthread_mutex_destroy(&freeline_lock));
    AZ(pthread_mutex_destroy(&freechunk_lock));
}

void
DATA_Clear_Logline(tx_t *tx)
{
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    
    tx->state = TX_EMPTY;
    /* XXX: etc. ... */
}

int
DATA_Init(void)
{
        int bufidx = 0, chunks_per_rec;

#if 0
    lines_per_tx = FMT_Get_LinesPerTx();
#endif
    
    /* XXX: set up tables of txen, lines & chunks, set/estimate sizes */
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
    VSTAILQ_CONCAT(dst, &free##type##head);             \
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
void
DATA_Return_Freelist(struct txhead_s *returned, unsigned nreturned)
{
    AZ(pthread_mutex_lock(&freetx_lock));
    VSTAILQ_CONCAT(&freetxhead, returned);
    global_nfree_tx += nreturned;
    AZ(pthread_mutex_unlock(&freetx_lock));
}

#define DUMP_HDRS(vsb, ll, hdr) do {                    \
    if (ll->hdr)                                        \
        for (j = 0; j < ll->hdr->nrec; j++)             \
            if (ll->hdr->record[j].len) {               \
                VSB_putc(vsb, '[');                     \
                VSB_bcat(vsb, ll->hdr->record[j].data,  \
                    ll->hdr->record[j].len);            \
                VSB_cat(vsb, "] ");                     \
            }                                           \
 } while (0)

void
DATA_Dump(void)
{
#if 0
    struct vsb *data;
    logline_t *ll;

    data = VSB_new_auto();
    
    for (int i = 0; i < config.max_data; i++) {
        int j;

        if (logline == NULL || logline[i].magic != LOGLINE_MAGIC)
            continue;
        
        if (logline[i].state == DATA_EMPTY)
            continue;

        ll = &logline[i];
        VSB_clear(data);

        VSB_printf(data, "Data entry %d: state=%s dir=%c tags={",
            i, statename[ll->state],
            C(ll->spec) ? 'c' : B(ll->spec) ? 'b' : '-');

        for (j = 0; j < ntags; j++)
            if (ll->tag[j].len) {
                VSB_cat(data, VSL_tags[idx2tag[j]]);
                VSB_cat(data, "=[");
                VSB_bcat(data, ll->tag[j].data, ll->tag[j].len);
                VSB_cat(data, "] ");
            }

        VSB_cat(data, "} rx_headers={");
        DUMP_HDRS(data, ll, rx_headers);

        VSB_cat(data, "} tx_headers={");
        DUMP_HDRS(data, ll, tx_headers);

        VSB_cat(data, "} vcl_log={");
        DUMP_HDRS(data, ll, vcl_log);
        VSB_putc(data, '}');
        VSB_finish(data);

        LOG_Log(LOG_INFO, "%s", VSB_data(data));
    }
#endif        
}
