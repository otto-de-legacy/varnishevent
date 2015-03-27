/*-
 * Copyright (c) 2013 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013 Otto Gmbh & Co KG
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

#include <syslog.h>
#include <pthread.h>
#include <errno.h>

#include "varnishevent.h"

#include "vas.h"

static int run = 0;

static pthread_t monitor;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

static void
log_output(void)
{
    LOG_Log(LOG_INFO, "Data table: len=%u open=%u done=%u load=%.2f occ_hi=%u "
        "global_free=%u", config.max_data, data_open, data_done,
        100.0 * (data_open + data_done) / config.max_data,
        data_occ_hi, global_nfree_tx);

    RDR_Stats();

    WRT_Stats();

    SPSCQ_Stats();
}

static void
monitor_cleanup(void *arg)
{
    (void) arg;

    log_output();
    LOG_Log0(LOG_INFO, "Monitoring thread exiting");
}

static void *
monitor_main(void *arg)
{
    LOG_Log(LOG_INFO, "Monitor thread running every %u secs",
        config.monitor_interval);
    run = 1;

    pthread_cleanup_push(monitor_cleanup, arg);

    while (run) {
#if 0
        TIM_sleep(config.monitor_interval);
#endif
        log_output();
    }

    pthread_cleanup_pop(0);
    LOG_Log0(LOG_INFO, "Monitoring thread exiting");
    pthread_exit((void *) NULL);
}

void
MON_Output(void)
{
    log_output();
}

void
MON_Shutdown(void)
{
    if (run) {
        run = 0;
        AZ(pthread_cancel(monitor));
        AZ(pthread_join(monitor, NULL));
    }
    AZ(pthread_mutex_destroy(&stats_lock));
}

void
MON_Start(void)
{
    AZ(pthread_create(&monitor, NULL, monitor_main, NULL));
}

void
MON_StatsUpdate(stats_update_t update)
{
    AZ(pthread_mutex_lock(&stats_lock));
    switch(update) {
        
    case STATS_WRITTEN:
        data_done--;
        break;
        
    case STATS_DONE:
        data_done++;
        break;
        
    default:
        /* Unreachable */
        AN(NULL);
    }
    AZ(pthread_mutex_unlock(&stats_lock));
}
