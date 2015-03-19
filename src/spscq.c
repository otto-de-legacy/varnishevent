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
#include "vqueue.h"
#include "vas.h"

static volatile unsigned long enqs = 0, deqs = 0, occ_hi = 0;
VSTAILQ_HEAD(spscq_s, tx_t);
struct spscq_s spscq_head = VSTAILQ_HEAD_INITIALIZER(spscq_head);
struct spscq_s deq_head = VSTAILQ_HEAD_INITIALIZER(deq_head);

static pthread_mutex_t spscq_lock = PTHREAD_MUTEX_INITIALIZER;

void
SPSCQ_Enq(tx_t *ptr)
{
    AZ(pthread_mutex_lock(&spscq_lock));
    assert(enqs - deqs < config.max_data);
    enqs++;
    if (enqs - deqs > occ_hi)
        occ_hi = enqs - deqs;
    VSTAILQ_INSERT_TAIL(&spscq_head, ptr, spscq);
    AZ(pthread_mutex_unlock(&spscq_lock));
}

tx_t
*SPSCQ_Deq(void)
{
    void *ptr;

    if (VSTAILQ_EMPTY(&deq_head)) {
        AZ(pthread_mutex_lock(&spscq_lock));
        VSTAILQ_CONCAT(&deq_head, &spscq_head);    
        AZ(pthread_mutex_unlock(&spscq_lock));
    }
    if (VSTAILQ_EMPTY(&deq_head))
        return NULL;
    ptr = VSTAILQ_FIRST(&deq_head);
    VSTAILQ_REMOVE_HEAD(&deq_head, spscq);
    deqs++;
    return ptr;
}

void
SPSCQ_Stats(void)
{
    unsigned len = enqs - deqs;
    
    LOG_Log(LOG_INFO, "Queue: max=%u len=%u load=%.2f occ_hi=%u",
        config.max_data, len, 100.0 * len / config.max_data, occ_hi);
}

void
SPSCQ_Shutdown(void)
{
    AZ(pthread_mutex_destroy(&spscq_lock));
}
