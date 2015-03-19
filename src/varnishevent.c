/*-
 * Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2015 Otto Gmbh & Co KG
 * All rights reserved
 *
 * Author: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 *
 * Portions adapted from varnishncsa.c from the Varnish project
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * Author: Anders Berg <andersb@vgnett.no>
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 * Author: Tollef Fog Heen <tfheen@varnish-software.com>
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
 * Obtain log data from the shared memory log and output single-line
 * events to an output stream. By default just like varnishncsa, but:
 *
 * - output lines may correspond to both client and backend transactions
 * - also events on the pseudo fd 0, such as backend health checks, may be
 *   logged
 * - output formats are defined for client, backend and "zero" events
 * - some additional formatting tags are available
 * - the internal architecture is designed to ensure that the VSL-reading
 *   process keeps pace with varnishd writing to VSL under heavy loads
 */

#include "config.h"

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <stdint.h>
#include <errno.h>

#include "vsb.h"
#if 0
#include "vpf.h"
#endif
#include "vqueue.h"

#include "vapi/vsl.h"
#include "vre.h"
#include "miniobj.h"
#include "vas.h"
#include "vcs.h"

#include "varnishevent.h"

#define DEFAULT_CONFIG "/etc/varnishevent.conf"

#define DISPATCH_CONTINUE 0
#define DISPATCH_TERMINATE 7

typedef enum {
    FD_EMPTY = 0,
    FD_OPEN
} fd_state_e;

typedef struct fd_t {
    unsigned magic;
#define FD_MAGIC 0xa06b2960
    logline_t *ll;
    fd_state_e state;
    double t;
    VTAILQ_ENTRY(fd_t) insert_list;
} fd_t;

static fd_t *fd_tbl;

VTAILQ_HEAD(insert_head_s, fd_t);
static struct insert_head_s insert_head = VTAILQ_HEAD_INITIALIZER(insert_head);

static unsigned open = 0, occ_hi = 0, len_hi = 0;

static unsigned long seen = 0, submitted = 0, not_logged = 0,
    waits = 0, fd_overflows = 0, len_overflows = 0,
    hdr_overflows = 0, expired = 0, spec_mismatches = 0, wrong_tags = 0;

/* Hack, because we cannot have #ifdef in the macro definition SIGDISP */
#define _UNDEFINED(SIG) ((#SIG)[0] == 0)
#define UNDEFINED(SIG) _UNDEFINED(SIG)

#define SIGDISP(SIG, action)						\
    do { if (UNDEFINED(SIG)) break;					\
        if (sigaction((SIG), (&action), NULL) != 0)			\
            LOG_Log(LOG_ALERT,						\
                "Cannot install handler for " #SIG ": %s",		\
                strerror(errno));					\
    } while(0)

static struct sigaction dump_action, terminate_action, reopen_action,
    stacktrace_action, ignore_action;

static volatile sig_atomic_t reopen = 0, term = 0;

struct VSL_data *vsl;

static int m_flag = 0;
#if 0
static int cb_flag = 0;
static int z_flag = 0;
#endif

/* Local freelist */
static struct freehead_s reader_freelist = 
    VSTAILQ_HEAD_INITIALIZER(reader_freelist);
static unsigned rdr_free = 0;

static struct txhead_s rdr_tx_freelist = 
    VSTAILQ_HEAD_INITIALIZER(rdr_tx_freelist);
static unsigned rdr_tx_free = 0;

static int waiting = 0;

static char cli_config_filename[BUFSIZ] = "";

int
RDR_Waiting(void)
{
    return waiting;
}

void
RDR_Stats(void)
{
    LOG_Log(LOG_INFO, "Reader (%s): fd_max=%u seen=%lu open=%u load=%.2f "
        "submitted=%lu not_logged=%lu occ_hi=%u waits=%lu expired=%lu free=%u "
        "len_hi=%u fd_overflows=%lu len_overflows=%lu hdr_overflows=%lu "
        "spec_mismatches=%lu wrong_tags=%lu",
        waiting ? "waiting" : "running", config.max_fd, seen, open,
        100.0 * open / config.max_fd, submitted, not_logged, occ_hi, waits,
        expired, rdr_free, len_hi, fd_overflows, len_overflows, hdr_overflows,
        spec_mismatches, wrong_tags);
}

static inline void
signal_spscq_ready(void)
{
    if (WRT_Waiting()) {
        AZ(pthread_mutex_lock(&spscq_ready_lock));
        AZ(pthread_cond_signal(&spscq_ready_cond));
        AZ(pthread_mutex_unlock(&spscq_ready_lock));
    }
}

#if 0
static inline logline_t
*take(void)
{
    struct logline_t *data;

    while (VSTAILQ_EMPTY(&reader_freelist)) {
        rdr_free = DATA_Take_Freelist(&reader_freelist);
        if (VSTAILQ_EMPTY(&reader_freelist)) {
            AZ(rdr_free);
            signal_spscq_ready();
            LOG_Log0(LOG_DEBUG, "Reader: waiting for free list");
            waiting = 1;
            AZ(pthread_mutex_lock(&data_ready_lock));
            if (!WRT_Waiting()) {
                waits++;
                AZ(pthread_cond_wait(&data_ready_cond, &data_ready_lock));
            }
            waiting = 0;
            AZ(pthread_mutex_unlock(&data_ready_lock));
            rdr_free = DATA_Take_Freelist(&reader_freelist);
            LOG_Log(LOG_DEBUG, "Reader: took %u from free list", rdr_free);
        }
    }
    data = VSTAILQ_FIRST(&reader_freelist);
    VSTAILQ_REMOVE_HEAD(&reader_freelist, freelist);
    rdr_free--;
    return (data);
}
#endif

static inline tx_t
*take_tx(void)
{
    struct tx_t *tx;
    while (VSTAILQ_EMPTY(&rdr_tx_freelist)) {
        rdr_tx_free = DATA_Take_Freelist(&rdr_tx_freelist);
        if (VSTAILQ_EMPTY(&rdr_tx_freelist)) {
            AZ(rdr_tx_free);
            signal_spscq_ready();
            LOG_Log0(LOG_DEBUG, "Reader: waiting for free list");
            waiting = 1;
            AZ(pthread_mutex_lock(&data_ready_lock));
            if (!WRT_Waiting()) {
                waits++;
                AZ(pthread_cond_wait(&data_ready_cond, &data_ready_lock));
            }
            waiting = 0;
            AZ(pthread_mutex_unlock(&data_ready_lock));
            rdr_tx_free = DATA_Take_Freelist(&rdr_tx_freelist);
            LOG_Log(LOG_DEBUG, "Reader: took %u txen from free list",
                    rdr_tx_free);
        }
    }
    tx = VSTAILQ_FIRST(&rdr_tx_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_tx_freelist, freelist);
    rdr_tx_free--;
    return (tx);
}

static inline void
take_chunks(linehead_t *lines, unsigned nchunks)
{
    (void) lines;
    (void) nchunks;
}

static inline void
submit(tx_t *tx)
{
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_DONE);
    
#if 0
    assert(lp->state == DATA_DONE);
    data_open--;
    if ((m_flag && !VSL_Matched(vd, lp->bitmap))
        || (lp->spec && !(lp->spec & cb_flag))) {
        not_logged++;
        DATA_Clear_Logline(lp);
        rdr_free++;
        VSTAILQ_INSERT_TAIL(&reader_freelist, lp, freelist);
        return;
    }
    SPSCQ_Enq((void *) lp);
#endif
    signal_spscq_ready();
    MON_StatsUpdate(STATS_DONE);
    submitted++;
}

static inline void
fd_free(fd_t *entry)
{
    CHECK_OBJ_NOTNULL(entry, FD_MAGIC);
    VTAILQ_REMOVE(&insert_head, entry, insert_list);
    entry->state = FD_EMPTY;
    entry->ll = NULL;
    open--;
}

static int
event(struct VSL_data *_vsl, struct VSL_transaction * const pt[], void *priv)
{
    struct tx_t *tx = NULL;
    struct VSL_transaction *t;
    int status = DISPATCH_CONTINUE;

    (void) priv;

    if (term)
        return DISPATCH_TERMINATE;

    if (pt[0] == NULL)
        return reopen;

    /* XXX: assert length(pt) == 1? */
    for (t = pt[0]; t != NULL; t = *++pt) {
        tx = take_tx();
        CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
        assert(tx->state == TX_EMPTY);
        assert(!VSTAILQ_EMPTY(tx->lines));

        switch(t->type) {
        case VSL_t_req:
            tx->spec = 'c';
            break;
        case VSL_t_bereq:
            tx->spec = 'b';
            break;
        case VSL_t_raw:
            tx->spec = '-';
            break;
        default:
            WRONG("Unexpected transaction type");
        }
            
        LOG_Log(LOG_DEBUG, "Tx: [%u %c]", t->vxid, tx->spec);

        logline_t *line = VSTAILQ_FIRST(tx->lines);
        while (1) {
            int len;

            status = VSL_Next(t->c);
            if (status <= 0)
                break;
            if (!VSL_Match(_vsl, t->c))
                continue;

            len = VSL_LEN(t->c->rec.ptr);
            LOG_Log(LOG_DEBUG, "Line: [%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                VSL_CDATA(t->c->rec.ptr));

            if (line == NULL) {
                /* XXX: increment counter */
#if 0
                line = VSTAILQ_LAST(tx->lines, logline_t, linelist);
                take_lines(tx->lines);
                line = VSTAILQ_NEXT(line, linelist);
#endif
            }
            CHECK_OBJ_NOTNULL(line, LOGLINE_MAGIC);
            assert(line->state == DATA_EMPTY);

            line->tag = VSL_TAG(t->c->rec.ptr);
            line->len = len;
            if (len != 0) {
                /* Copy the payload into chunks */
                AN(line->chunks);
                assert(!VSTAILQ_EMPTY(line->chunks));

                int nchunks = (len + config.chunk_size - 1) / config.chunk_size;
                if (nchunks > 1)
                    /* XXX: increment counter */
                    take_chunks(tx->lines, nchunks);

                int n = len;
                chunk_t *chunk = VSTAILQ_FIRST(line->chunks);
                const char *p = (const char *) VSL_CDATA(t->c->rec.ptr);
                while (n > 0) {
                    CHECK_OBJ_NOTNULL(chunk, CHUNK_MAGIC);
                    int cp = n;
                    if (cp > config.chunk_size)
                        cp = config.chunk_size;
                    memcpy(chunk->data, p, cp);
                    p += cp;
                    n -= cp;
                    chunk = VSTAILQ_NEXT(chunk, chunklist);
                }
            }
            line->state = DATA_DONE;
            line = VSTAILQ_NEXT(line, linelist);
        }
    }
    seen++;
    data_done++;
    if (data_done > data_occ_hi)
        data_occ_hi = data_done;
    submit(tx);
    
    return reopen;
}

/*--------------------------------------------------------------------*/

static void
sigreopen(int sig)
{
    LOG_Log(LOG_WARNING, "Received signal %d (%s), reopening output",
        sig, strsignal(sig));
    reopen = 1;
}

static void
dump(int sig)
{
    (void) sig;
    CONF_Dump();
    DATA_Dump();
}

static void
terminate(int sig)
{
    (void) sig;
    term = 1;
}

static vas_f assert_fail __attribute__((__noreturn__));

static void
assert_fail(const char *func, const char *file, int line, const char *cond,
    int err, enum vas_e err_e)
{
    (void) err_e;
    
    LOG_Log(LOG_ALERT, "Condition (%s) failed in %s(), %s line %d",
        cond, func, file, line);
    if (err)
        LOG_Log(LOG_ALERT, "errno = %d (%s)", err, strerror(err));
    abort();
}

/*--------------------------------------------------------------------*/

static void
read_default_config(void) {
    if (access(DEFAULT_CONFIG, F_OK) == 0) {
        if (access(DEFAULT_CONFIG, R_OK) != 0) {
            perror(DEFAULT_CONFIG);
            exit(EXIT_FAILURE);
        }
        printf("Reading config from %s\n", DEFAULT_CONFIG);
        if (CONF_ReadFile(DEFAULT_CONFIG) != 0)
            exit(EXIT_FAILURE);
    }
}

static void
usage(void)
{

    fprintf(stderr,
        "usage: varnishevent [-aDVg] [-G configfile] [-P pidfile] "
        "[-w outputfile]\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    int c, errnum, finite = 0, a_flag = 0, g_flag = 0, format_flag = 0;
#if 0
    int D_flag = 0;
    const char *P_arg = NULL;
#endif
    const char *w_arg = NULL;
    char scratch[BUFSIZ];
#if 0
    struct vpf_fh *pfh = NULL;
#endif

    vsl = VSL_New();

    CONF_Init();
    read_default_config();

    while ((c = getopt(argc, argv, "aDP:Vw:fF:gG:")) != -1) {
        switch (c) {
        case 'a':
            a_flag = 1;
            break;
        case 'f':
            if (format_flag) {
                fprintf(stderr, "-f and -F can not be combined\n");
                exit(1);
            }
            strcpy(config.cformat, ALT_CFORMAT);
            format_flag = 1;
            break;
        case 'F':
            if (format_flag) {
                fprintf(stderr, "-f and -F can not be combined\n");
                exit(1);
            }
            format_flag = 1;
            strcpy(config.cformat, optarg);
            break;
#if 0
        case 'D':
            D_flag = 1;
            break;
        case 'P':
            P_arg = optarg;
            break;
#endif
        case 'V':
            VCS_Message("varnishevent");
            exit(0);
        case 'w':
            w_arg = optarg;
            break;
        case 'g':
            g_flag = 1;
            break;
        case 'G':
            strcpy(cli_config_filename, optarg);
            break;
        case 'b':
        case 'i':
        case 'I':
        case 'c':
            fprintf(stderr, "-%c is not valid for varnishevent\n", c);
            exit(1);
            break;
        case 'm':
            m_flag = 1; /* Fall through */
        default:
            if (c == 'r') {
                finite = 1;
                strcpy(config.varnish_bindump, optarg);
            }
            if (VSL_Arg(vsl, c, optarg) > 0)
                break;
            usage();
        }
    }

    if (! EMPTY(cli_config_filename)) {
        printf("Reading config from %s\n", cli_config_filename);
        if (CONF_ReadFile(cli_config_filename) != 0) {
            fprintf(stderr, "Error reading config from %s\n",
                cli_config_filename);
            exit(EXIT_FAILURE);
        }
    }

    /* XXX: set this up properly, possible for reading bin logs */
    /* XXX: should do this after opening syslog, to log errors */
    struct VSM_data *vd = VSM_New();
    struct VSL_cursor *cursor = VSL_CursorVSM(vsl, vd, 0);
    if (cursor == NULL) {
        fprintf(stderr, "Cannot open log: %s\n", VSL_Error(vsl));
        exit(1);
    }

    /* XXX: set up the query to filter the log contents narrowly for
       the output format */
    struct VSLQ *vslq;
    vslq = VSLQ_New(vsl, &cursor, VSL_g_vxid, "");
    if (vslq == NULL) {
        fprintf(stderr, "Cannot init log query: %s\n", VSL_Error(vsl));
        exit(1);
    }

#if 0
    if (P_arg && (pfh = VPF_Open(P_arg, 0644, NULL)) == NULL) {
        perror(P_arg);
        exit(1);
    }

    if (D_flag && varnish_daemon(0, 0) == -1) {
        perror("daemon()");
        if (pfh != NULL)
            VPF_Remove(pfh);
        exit(1);
    }
#endif    

    terminate_action.sa_handler = terminate;
    AZ(sigemptyset(&terminate_action.sa_mask));
    terminate_action.sa_flags &= ~SA_RESTART;

    dump_action.sa_handler = dump;
    AZ(sigemptyset(&dump_action.sa_mask));
    dump_action.sa_flags |= SA_RESTART;

    reopen_action.sa_handler = sigreopen;
    AZ(sigemptyset(&reopen_action.sa_mask));
    reopen_action.sa_flags |= SA_RESTART;

#if 0
    stacktrace_action.sa_handler = HNDL_Abort;
#endif

    ignore_action.sa_handler = SIG_IGN;
    default_action.sa_handler = SIG_DFL;

#if 0
    HNDL_Init(argv[0]);
#endif

    /* Install signal handlers */
#include "signals.h"

#if 0
    if (pfh != NULL)
        VPF_Write(pfh);
#endif
    
    if (w_arg)
        strcpy(config.output_file, w_arg);
    if (!EMPTY(config.output_file))
        SIGDISP(SIGHUP, reopen_action);
    else
        SIGDISP(SIGHUP, ignore_action);
    if (a_flag)
        config.append = 1;

    if (LOG_Open(config.syslog_ident) != 0) {
        exit(EXIT_FAILURE);
    }
    if (g_flag)
        LOG_SetLevel(LOG_DEBUG);

    LOG_Log(LOG_INFO, "initializing (%s)", VCS_version);

    VAS_Fail = assert_fail;

#if 0
    if (FMT_Init(scratch) != 0) {
        LOG_Log(LOG_ALERT, "Error in output formats: %s", scratch);
        exit(EXIT_FAILURE);
    }
#endif

    if (!EMPTY(config.varnish_bindump))
        LOG_Log(LOG_INFO, "Reading from file: %s", config.varnish_bindump);
    else {
        strcpy(scratch, VSM_Name(vd));
        if (EMPTY(scratch))
            LOG_Log0(LOG_INFO, "Reading default varnish instance");
        else
            LOG_Log(LOG_INFO, "Reading varnish instance %s", scratch);
    }

#if 0
    strcpy(scratch, FMT_Get_i_Arg());
#endif
    if (EMPTY(scratch)) {
        LOG_Log0(LOG_ALERT, "Not configured to read any log data, exiting");
        exit(EXIT_FAILURE);
    }
    assert(VSL_Arg(vsl, 'i', scratch) > 0);
    LOG_Log(LOG_INFO, "Reading SHM tags: %s", scratch);

#if 0    
    if (!EMPTY(config.cformat))
        cb_flag |= VSL_S_CLIENT;
    if (!EMPTY(config.bformat))
        cb_flag |= VSL_S_BACKEND;
    if (!EMPTY(config.zformat))
        z_flag = 1;
#endif

    if ((errnum = DATA_Init()) != 0) {
        LOG_Log(LOG_ALERT, "Cannot init data table: %s\n",
                strerror(errnum));
        exit(EXIT_FAILURE);
    }

    fd_tbl = (fd_t *) calloc(config.max_fd, sizeof(fd_t));
    if (fd_tbl == NULL) {
        LOG_Log(LOG_ALERT, "Cannot init fd table: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    for (int k = 0; k < config.max_fd; k++) {
        fd_tbl[k].magic = FD_MAGIC;
        fd_tbl[k].ll = NULL;
        fd_tbl[k].state = FD_EMPTY;
    }

    AZ(pthread_cond_init(&data_ready_cond, NULL));
    AZ(pthread_mutex_init(&data_ready_lock, NULL));
    AZ(pthread_cond_init(&spscq_ready_cond, NULL));
    AZ(pthread_mutex_init(&spscq_ready_lock, NULL));

    if (config.monitor_interval > 0)
        MON_Start();
    else
        LOG_Log0(LOG_INFO, "Monitoring thread not running");

    if ((errnum = WRT_Init()) != 0) {
        LOG_Log(LOG_ALERT, "Cannot init writer thread: %s\n", strerror(errnum));
        exit(EXIT_FAILURE);
    }

    rdr_free = DATA_Take_Freelist(&rdr_tx_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_tx_freelist));
    assert(rdr_free == config.max_data);
    
    WRT_Start();
    /* XXX: configure wrt_waits and sleep interval? */
    int wrt_waits = 0;
    while (!WRT_Running()) {
        if (wrt_waits++ > 10) {
            LOG_Log0(LOG_ALERT, "Writer thread not running, giving up");
            exit(EXIT_FAILURE);
        }
#if 0
        TIM_sleep(1);
#endif
    }

    /* Main loop */
    term = 0;
    /* XXX: TERM not noticed until request received */
    while (VSLQ_Dispatch(vslq, event, NULL) >= 0)
        if (term || finite)
            break;
        else if (reopen) {
            WRT_Reopen();
            reopen = 0;
        }
        else
            LOG_Log0(LOG_WARNING, "Log read interrupted, continuing");

    if (term)
        LOG_Log0(LOG_INFO, "Termination signal received");
    else if (!finite)
        LOG_Log0(LOG_WARNING, "Varnish log closed");
    
    WRT_Halt();
    SPSCQ_Shutdown();
    MON_Shutdown();
#if 0
    FMT_Shutdown();
#endif
    AZ(pthread_cond_destroy(&data_ready_cond));
    AZ(pthread_mutex_destroy(&data_ready_lock));
    AZ(pthread_cond_destroy(&spscq_ready_cond));
    AZ(pthread_mutex_destroy(&spscq_ready_lock));
    LOG_Log0(LOG_INFO, "Exiting");
    LOG_Close();

    exit(EXIT_SUCCESS);
}
