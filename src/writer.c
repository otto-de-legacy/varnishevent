/*-
 * Copyright (c) 2013 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013 Otto Gmbh & Co KG
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

#include <pthread.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>

#include "varnishevent.h"

#include "vas.h"
#include "miniobj.h"
#include "vsb.h"

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
pthread_t writer;

/* local freelist - return space in chunks */
static struct txhead_s wrt_freelist;
static unsigned	wrt_nfree;

static struct vsb *os;

static FILE *fo;
int fd;
fd_set set;
struct timeval to;
struct timeval *timeout = NULL;
static char *obuf = NULL;
static pthread_mutex_t reopen_lock = PTHREAD_MUTEX_INITIALIZER;

/* stats */
static unsigned long deqs = 0;
static unsigned long bytes = 0;
static unsigned long waits = 0;
static unsigned long writes = 0;
static unsigned long errors = 0;
static unsigned long timeouts = 0;

typedef struct writer_data_s {
    unsigned magic;
#define WRITER_DATA_MAGIC 0xd8eef137
    unsigned status;  /* exit status */
    wrt_state_e state;
} writer_data_t;

static writer_data_t wrt_data;
    
static unsigned run, reopen = 0;

static int
set_fdset(void)
{
    errno = 0;
    fd = fileno(fo);
    if (fd == -1)
        return errno;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    return 0;
}

static int
open_log(void)
{
    if (EMPTY(config.output_file))
        fo = stdout;
    else if ((fo = fopen(config.output_file, config.append ? "a" : "w"))
              == NULL)
        return errno;

    if (set_fdset() != 0)
        return errno;
    
    if (obuf != NULL)
        free(obuf);
    obuf = (char *) malloc(config.output_bufsiz);
    if (obuf == NULL)
        return errno;
    
    if (setvbuf(fo, obuf, _IOFBF, config.output_bufsiz) != 0)
        return errno;
    
    return 0;
}

static inline void
wrt_return_freelist(void)
{
    DATA_Return_Freetx(&wrt_freelist, wrt_nfree);
    LOG_Log(LOG_DEBUG, "Writer: returned %u to free list", wrt_nfree);
    wrt_nfree = 0;
    assert(VSTAILQ_EMPTY(&wrt_freelist));
    if (RDR_Waiting()) {
        AZ(pthread_mutex_lock(&data_ready_lock));
        AZ(pthread_cond_signal(&data_ready_cond));
        AZ(pthread_mutex_unlock(&data_ready_lock));
    }
}

static inline void
wrt_write(tx_t *tx)
{
    int errnum;
    
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_DONE);

    AZ(pthread_mutex_lock(&reopen_lock));
    if (reopen && fo != stdout) {
        if (fflush(fo) != 0)
            LOG_Log(LOG_ALERT, "Cannot flush to %s, DATA DISCARDED: %s",
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
        
    VSB_clear(os);
    FMT_Format(tx, os);
    VSB_finish(os);

    if (timeout != NULL)
        to = config.output_timeout;
    if ((errnum = select(fd + 1, NULL, &set, NULL, timeout)) == -1) {
        LOG_Log(LOG_ALERT,
            "Error waiting for ready output %d (%s), DATA DISCARDED: %s",
            errno, strerror(errno), VSB_data(os));
        errors++;
        if (set_fdset() != 0) {
            LOG_Log(LOG_ALERT,
                "Cannot reset fd set after select() error, exiting: %s",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    else if (errnum == 0) {
        LOG_Log(LOG_ALERT,
            "Timeout waiting for ready output, DATA DISCARDED: %s",
            VSB_data(os));
        timeouts++;
        if (set_fdset() != 0) {
            LOG_Log(LOG_ALERT, "Cannot reset fd set after timeout, exiting: %s",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    else if (errnum != 1)
        WRONG("More than one ready file descriptor for output");
    else if (!FD_ISSET(fd, &set))
        WRONG("Wrong file descriptor found ready for output");
    else if (fprintf(fo, "%s", VSB_data(os)) < 0) {
        LOG_Log(LOG_ALERT, "Output error %d (%s), DATA DISCARDED: %s",
            errno, strerror(errno), VSB_data(os));
        errors++;
    }
    else {
        writes++;
        bytes += VSB_len(os);
    }
    MON_StatsUpdate(STATS_WRITTEN);

    /* clean up */
    DATA_Clear_Tx(tx);
    VSTAILQ_INSERT_TAIL(&wrt_freelist, tx, freelist);
    wrt_nfree++;

    if (global_nfree_tx < (config.max_data >> 1) || RDR_Waiting())
        wrt_return_freelist();
}

static void
*wrt_main(void *arg)
{
    writer_data_t *wrt = (writer_data_t *) arg;
    tx_t *tx;

    LOG_Log0(LOG_INFO, "Writer thread starting");
    CHECK_OBJ_NOTNULL(wrt, WRITER_DATA_MAGIC);
    wrt->state = WRT_INITIALIZING;

    VSTAILQ_INIT(&wrt_freelist);
    wrt_nfree = 0;

    wrt->state = WRT_RUNNING;
    
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
            LOG_Log(LOG_ALERT, "Output flush failed, error %d (%s)",
                errno, strerror(errno));
            errors++;
        }
	if (wrt_nfree > 0)
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
        LOG_Log(LOG_ALERT, "Output flush failed, error %d (%s)",
            errno, strerror(errno));
        errors++;
    }

    wrt->status = EXIT_SUCCESS;
    LOG_Log0(LOG_INFO, "Writer thread exiting");
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

    /* XXX: fixed size? */
    os = VSB_new_auto();

    if (config.output_timeout.tv_sec != 0
        || config.output_timeout.tv_usec != 0) {
        to = config.output_timeout;
        timeout = &to;
    }

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
    if (!run) return;
    
    LOG_Log(LOG_INFO,
        "Writer (%s): seen=%lu writes=%lu bytes=%lu errors=%lu timeouts=%lu"
        " waits=%lu free=%u",
        statename[wrt_data.state], deqs, writes, bytes, errors, timeouts, waits,
        wrt_nfree);
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
WRT_Shutdown(void)
{
    /* WRT_Halt() must always be called first */
    AZ(run);
    fclose(fo);
    free(obuf);
    VSB_delete(os);
    AZ(pthread_mutex_destroy(&reopen_lock));
}

#ifdef TEST_DRIVER

#include "minunit.h"

int tests_run = 0;
static char errmsg[BUFSIZ];

#define THRESHOLD 1000

int
RDR_Waiting(void)
{
    return 0;
}

void
RDR_Stats(void)
{}

static char
*test_timeout(void)
{
    logline_t ll;
    
    printf("... testing write timeouts\n");

    strcpy(config.cformat, "");
    MAZ(FMT_Init(&errmsg[0]));

    strcpy(config.log_file, "-");
    MAZ(LOG_Open("test_writer"));

    config.output_timeout.tv_sec = 1;
    config.output_timeout.tv_usec = 0;

    MAZ(WRT_Init());

    VSTAILQ_INIT(&wrt_freelist);
    MASSERT(VSTAILQ_EMPTY(&wrt_freelist));

    for (int i = 0; i < THRESHOLD; i++) {
        ll.magic = LOGLINE_MAGIC;
        ll.state = DATA_DONE;
        ll.spec = VSL_S_CLIENT;
        ll.rx_headers = NULL;
        ll.tx_headers = NULL;
        ll.vcl_log = NULL;
        ll.vcl_call = NULL;

        wrt_write(&ll);
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

#endif
