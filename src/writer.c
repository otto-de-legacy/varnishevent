/*-
 * Copyright (c) 2013-2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013-2015 Otto Gmbh & Co KG
 * All rights reserved
 * Use only with permission
 *
 * Authors: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 *	    Nils Goroll <nils.goroll@uplex.de>
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

#include "config.h"

#include <pthread.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>
#include <poll.h>
#include <errno.h>

#include "varnishevent.h"
#include "writer.h"

#include "vas.h"
#include "miniobj.h"
#include "vsb.h"
#include "vmb.h"
#include "vtim.h"

typedef enum {
    WRT_NOTSTARTED = 0,
    WRT_INITIALIZING,
    WRT_RUNNING,
    WRT_WAITING,
    WRT_SHUTTINGDOWN,
    WRT_EXITED,
    WRT_STATE_E_LIMIT
} wrt_state_e;

static const char* statename[WRT_STATE_E_LIMIT] = { 
    [WRT_NOTSTARTED]    = "not started",
    [WRT_INITIALIZING]	= "initializing",
    [WRT_RUNNING]	= "running",
    [WRT_WAITING]	= "waiting",
    [WRT_SHUTTINGDOWN]	= "shutting down",
    [WRT_EXITED]	= "exited"
};

/* Single writer thread, consumer for the SPSC queue. */
static pthread_t writer;

rechead_t wrt_freerecs;
chunkhead_t wrt_freechunks;

static unsigned	wrt_nfree_tx, wrt_nfree_recs, wrt_nfree_chunks;

static FILE *fo;
static struct pollfd fds[1];
static int blocking = 0, timeout = -1;
static char *obuf = NULL;
static pthread_mutex_t reopen_lock = PTHREAD_MUTEX_INITIALIZER;

/* stats */
static unsigned long deqs = 0;
static unsigned long bytes = 0;
static unsigned long waits = 0;
static unsigned long writes = 0;
static unsigned long errors = 0;
static unsigned long timeouts = 0;
static double pollt = 0., writet = 0.;

typedef struct writer_data_s {
    unsigned magic;
#define WRITER_DATA_MAGIC 0xd8eef137
    unsigned status;  /* exit status */
    wrt_state_e state;
} writer_data_t;

static writer_data_t wrt_data;
    
static unsigned run, reopen = 0, tx_thresh, rec_thresh, chunk_thresh;

static int
open_log(void)
{
    struct stat st;

    if (EMPTY(config.output_file) || strcmp(config.output_file, "-") == 0)
        fo = stdout;
    else {
        if ((fo = fopen(config.output_file, config.append ? "a" : "w"))
            == NULL)
            return errno;
        if (stat(config.output_file, &st) < 0)
            return errno;
        if (S_ISDIR(st.st_mode))
            return EISDIR;
        blocking = !S_ISREG(st.st_mode);
        if (blocking) {
            fds[0].fd = fileno(fo);
            fds[0].events = POLLOUT;
        }
    }

    if (obuf != NULL)
        free(obuf);
    obuf = (char *) malloc(config.output_bufsiz);
    if (obuf == NULL)
        return errno;
    
    if (setvbuf(fo, obuf, _IOFBF, config.output_bufsiz) != 0)
        return errno;
    
    return 0;
}

static void
wrt_signal_data_ready(void)
{
    if (RDR_Waiting()) {
        AZ(pthread_mutex_lock(&data_ready_lock));
        if (RDR_Waiting())
            AZ(pthread_cond_signal(&data_ready_cond));
        AZ(pthread_mutex_unlock(&data_ready_lock));
    }
}

static inline void
wrt_return_freelist(void)
{
    if (wrt_nfree_chunks > 0) {
        DATA_Return_Freechunk(&wrt_freechunks, wrt_nfree_chunks);
        wrt_signal_data_ready();
        LOG_Log(LOG_DEBUG, "Writer: returned %u chunks to free list",
                wrt_nfree_chunks);
        wrt_nfree_chunks = 0;
        assert(VSTAILQ_EMPTY(&wrt_freechunks));
    }
    if (wrt_nfree_recs > 0) {
        DATA_Return_Freerec(&wrt_freerecs, wrt_nfree_recs);
        wrt_signal_data_ready();
        LOG_Log(LOG_DEBUG, "Writer: returned %u records to free list",
                wrt_nfree_recs);
        wrt_nfree_recs = 0;
        assert(VSTAILQ_EMPTY(&wrt_freerecs));
    }
    if (wrt_nfree_tx > 0) {
        DATA_Return_Freetx(&wrt_freetx, wrt_nfree_tx);
        wrt_signal_data_ready();
        LOG_Log(LOG_DEBUG, "Writer: returned %u tx to free list", wrt_nfree_tx);
        wrt_nfree_tx = 0;
        assert(VSTAILQ_EMPTY(&wrt_freetx));
    }
}

void
wrt_write(tx_t *tx)
{
    char *os;
    int ready = 1;
    
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_SUBMITTED);

    AZ(pthread_mutex_lock(&reopen_lock));
    if (reopen && fo != stdout) {
        int errnum;

        wrt_return_freelist();
        if (fflush(fo) != 0)
            LOG_Log(LOG_ERR, "Cannot flush to %s, DATA DISCARDED: %s",
                    config.output_file, strerror(errno));
        if (fclose(fo) != 0) {
            LOG_Log(LOG_ALERT, "Cannot close %s, exiting: %s",
                    config.output_file, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if ((errnum = open_log()) != 0) {
            LOG_Log(LOG_ALERT, "Cannot reopen %s, exiting: %s",
                    config.output_file, strerror(errnum));
            exit(EXIT_FAILURE);
        }
        reopen = 0;
    }
    AZ(pthread_mutex_unlock(&reopen_lock));

    VRMB();
    os = FMT_Format(tx);
    assert(tx->state == TX_WRITTEN);

    if (blocking) {
        int nfds;

        ready = 0;
        do {
            double start = VTIM_mono();
            nfds = poll(fds, 1, timeout);
            pollt += VTIM_mono() - start;
            if (nfds < 0)
                assert(errno == EAGAIN || errno == EINTR);
        } while (nfds < 0);
        AZ(fds[0].revents & POLLNVAL);
        if (fds[0].revents & POLLERR) {
            LOG_Log(LOG_ERR,
                    "Error waiting for ready output %d (%s), "
                    "DATA DISCARDED: %s", errno, strerror(errno), os);
            errors++;
        }
        else if (nfds == 0) {
            wrt_return_freelist();
            LOG_Log(LOG_ERR,
                    "Timeout waiting for ready output, DATA DISCARDED: %s", os);
            timeouts++;
        }
        else if (nfds != 1)
            WRONG("More than one ready file descriptor for output");
        else {
            AN(fds[0].revents & POLLOUT);
            ready = 1;
        }
    }
    if (ready) {
        double start = VTIM_mono();
        int ret = fprintf(fo, "%s", os);
        writet += VTIM_mono() - start;
        if (ret < 0) {
            LOG_Log(LOG_ERR, "Output error %d (%s), DATA DISCARDED: %s",
                    errno, strerror(errno), os);
            errors++;
        }
        else {
            writes++;
            bytes += strlen(os);
        }
    }

    /* clean up */
    DATA_Clear_Tx(tx, &wrt_freetx, &wrt_freerecs, &wrt_freechunks,
                  &wrt_nfree_tx, &wrt_nfree_recs, &wrt_nfree_chunks);

    assert(tx->state == TX_FREE);

    if (RDR_Waiting() || RDR_Depleted() || wrt_nfree_tx > tx_thresh
        || wrt_nfree_recs > rec_thresh || wrt_nfree_chunks > chunk_thresh)
        wrt_return_freelist();
}

static void
*wrt_main(void *arg)
{
    writer_data_t *wrt = (writer_data_t *) arg;
    tx_t *tx;

    LOG_Log0(LOG_NOTICE, "Writer thread starting");
    CHECK_OBJ_NOTNULL(wrt, WRITER_DATA_MAGIC);
    thread_setname(pthread_self(), "vevent_writer");
    wrt->state = WRT_INITIALIZING;

    VSTAILQ_INIT(&wrt_freetx);
    wrt_nfree_tx = 0;

    wrt->state = WRT_RUNNING;

    VMB();
    while (run) {
	tx = SPSCQ_Deq();
	if (tx != NULL) {
	    deqs++;
            CHECK_OBJ(tx, TX_MAGIC);
            wrt_write(tx);
	    continue;
        }

        /*
	 * wait until data are available, or quit is signaled.
         * flush ouput and return space before sleeping
         */
        if (fflush(fo) != 0) {
            LOG_Log(LOG_ERR, "Output flush failed, error %d (%s)",
                errno, strerror(errno));
            errors++;
        }
        wrt_return_freelist();
        
        wrt->state = WRT_WAITING;
        AZ(pthread_mutex_lock(&spscq_ready_lock));
        /*
	 * run is guaranteed to be fresh after the lock
	 */
        if (run && !RDR_Waiting()) {
            waits++;
            AZ(pthread_cond_wait(&spscq_ready_cond, &spscq_ready_lock));
        }
        wrt->state = WRT_RUNNING;
        AZ(pthread_mutex_unlock(&spscq_ready_lock));
    }

    wrt->state = WRT_SHUTTINGDOWN;
    
    /* Prepare to exit, drain the queue */
    while ((tx = SPSCQ_Deq()) != NULL) {
        deqs++;
        CHECK_OBJ(tx, TX_MAGIC);
        wrt_write(tx);
    }
    if (fflush(fo) != 0) {
        LOG_Log(LOG_ERR, "Output flush failed, error %d (%s)",
            errno, strerror(errno));
        errors++;
    }

    wrt->status = EXIT_SUCCESS;
    LOG_Log0(LOG_NOTICE, "Writer thread exiting");
    wrt->state = WRT_EXITED;
    pthread_exit((void *) wrt);
}

int
WRT_Init(void)
{
    int err;

    if ((err = open_log()) != 0)
        return err;

    wrt_data.magic = WRITER_DATA_MAGIC;
    wrt_data.state = WRT_NOTSTARTED;

    if (config.output_timeout != 0.)
        timeout = config.output_timeout * 1e3;

    tx_thresh = config.max_data >> 2;
    rec_thresh = nrecords >> 2;
    chunk_thresh = nchunks >> 2;

    run = 1;
    return 0;
}

void
WRT_Start(void)
{
    AZ(pthread_create(&writer, NULL, wrt_main, &wrt_data));
}

void
WRT_Stats(void)
{
    LOG_Log(LOG_INFO,
            "Writer (%s): seen=%lu writes=%lu bytes=%lu errors=%lu timeouts=%lu"
            " waits=%lu free_tx=%u free_rec=%u free_chunk=%u pollt=%.6f"
            " writet=%.6f",
            statename[wrt_data.state], deqs, writes, bytes, errors, timeouts,
            waits, wrt_nfree_tx, wrt_nfree_recs, wrt_nfree_chunks, pollt,
            writet);
}

int
WRT_Running(void)
{
    return wrt_data.state > WRT_INITIALIZING
        && wrt_data.state < WRT_EXITED;
}

int
WRT_Waiting(void)
{
    return wrt_data.state == WRT_WAITING;
}

void
WRT_Reopen(void)
{
    AZ(pthread_mutex_lock(&reopen_lock));
    reopen = 1;
    AZ(pthread_mutex_unlock(&reopen_lock));
}

void
WRT_Halt(void)
{
    writer_data_t *wrt;
    
    AZ(pthread_mutex_lock(&spscq_ready_lock));
    run = 0;
    AZ(pthread_cond_signal(&spscq_ready_cond));
    AZ(pthread_mutex_unlock(&spscq_ready_lock));

    AZ(pthread_join(writer, (void **) &wrt));
    CHECK_OBJ_NOTNULL(wrt, WRITER_DATA_MAGIC);
    if (wrt->status != EXIT_SUCCESS)
        LOG_Log0(LOG_ERR, "Writer thread returned failure status");
}

void
WRT_Fini(void)
{
    /* WRT_Halt() must always be called first */
    AZ(run);
    fclose(fo);
    free(obuf);
    AZ(pthread_mutex_destroy(&reopen_lock));
}
