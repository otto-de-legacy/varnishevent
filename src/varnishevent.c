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

static unsigned open = 0, occ_hi = 0, len_hi = 0;

static unsigned long seen = 0, submitted = 0, len_overflows = 0, no_free_tx = 0,
    no_free_rec = 0, no_free_chunk = 0;

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

/* Local freelists */
static chunkhead_t rdr_chunk_freelist
    = VSTAILQ_HEAD_INITIALIZER(rdr_chunk_freelist);
static unsigned rdr_chunk_free = 0;

static linehead_t rdr_rec_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_rec_freelist);
static unsigned rdr_rec_free = 0;

static txhead_t rdr_tx_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_tx_freelist);
static unsigned rdr_tx_free = 0;

static int waiting = 0;

static char cli_config_filename[BUFSIZ] = "";

static char tx_type_name[VSL_t__MAX];

int
RDR_Waiting(void)
{
    return waiting;
}

void
RDR_Stats(void)
{
    LOG_Log(LOG_INFO, "Reader (%s): seen=%lu submitted=%lu occ_hi=%u "
        "free_tx=%u free_rec=%u free_chunk=%u len_hi=%u len_overflows=%lu",
        waiting ? "waiting" : "running", seen, open, submitted, occ_hi,
        rdr_tx_free, rdr_rec_free, rdr_chunk_free, len_hi, len_overflows);
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

static inline chunk_t
*take_chunk(void)
{
    chunk_t *chunk;

    if (VSTAILQ_EMPTY(&rdr_chunk_freelist)) {
        signal_spscq_ready();
        rdr_chunk_free = DATA_Take_Freechunk(&rdr_chunk_freelist);
        if (VSTAILQ_EMPTY(&rdr_chunk_freelist))
            return NULL;
    }
    chunk = VSTAILQ_FIRST(&rdr_chunk_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_chunk_freelist, freelist);
    rdr_chunk_free--;

    return (chunk);
}

static inline logline_t
*take_rec(void)
{
    logline_t *rec;

    if (VSTAILQ_EMPTY(&rdr_rec_freelist)) {
        signal_spscq_ready();
        rdr_rec_free = DATA_Take_Freeline(&rdr_rec_freelist);
        if (VSTAILQ_EMPTY(&rdr_rec_freelist))
            return NULL;
    }
    rec = VSTAILQ_FIRST(&rdr_rec_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_rec_freelist, freelist);
    rdr_rec_free--;

    return (rec);
}

static inline tx_t
*take_tx(void)
{
    tx_t *tx;

    if (VSTAILQ_EMPTY(&rdr_tx_freelist)) {
        signal_spscq_ready();
        rdr_tx_free = DATA_Take_Freetx(&rdr_tx_freelist);
        if (VSTAILQ_EMPTY(&rdr_tx_freelist))
            return NULL;
    }
    tx = VSTAILQ_FIRST(&rdr_tx_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_tx_freelist, freelist);
    rdr_tx_free--;

    return (tx);
}

static inline void
submit(tx_t *tx)
{
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_DONE);
    SPSCQ_Enq(tx);
    signal_spscq_ready();
    MON_StatsUpdate(STATS_DONE);
    submitted++;
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
 
    for (t = pt[0]; t != NULL; t = *++pt) {
        assert(t->type == VSL_t_req || t->type == VSL_t_bereq
               || t->type == VSL_t_raw);
            
        tx = take_tx();
        if (tx == NULL) {
            no_free_tx++;
            LOG_Log(LOG_DEBUG, "Freelist exhausted, tx DISCARDED: [%u %c]",
                t->vxid, tx_type_name[tx->type]);
            continue;
        }
        CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
        assert(tx->state == TX_EMPTY);
        assert(VSTAILQ_EMPTY(&tx->lines));
        tx->type = t->type;
        tx->vxid = t->vxid;

        LOG_Log(LOG_DEBUG, "Tx: [%u %c]", tx->vxid, tx_type_name[tx->type]);

        while (1) {
            int len;
            logline_t *rec;

            status = VSL_Next(t->c);
            if (status <= 0)
                break;
            if (!VSL_Match(_vsl, t->c))
                continue;

            len = VSL_LEN(t->c->rec.ptr);
            LOG_Log(LOG_DEBUG, "Line: [%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                VSL_CDATA(t->c->rec.ptr));

            rec = take_rec();
            if (rec == NULL) {
                no_free_rec++;
                LOG_Log(LOG_DEBUG, "Freelist exhausted, line DISCARDED: "
                    "[%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                    VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                    VSL_CDATA(t->c->rec.ptr));
                continue;
            }
            CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
            assert(rec->state == DATA_EMPTY);

            rec->tag = VSL_TAG(t->c->rec.ptr);
            rec->len = len;
            if (len != 0) {
                chunk_t *chunk;

                /* Copy the payload into chunks */
                assert(VSTAILQ_EMPTY(&rec->chunks));
                int nchunk = (len + config.chunk_size - 1) / config.chunk_size;
                for (int i = 0; i < nchunk; i++) {
                    chunk = take_chunk();
                    if (chunk == NULL) {
                        no_free_chunk++;
                        LOG_Log(LOG_DEBUG,
                            "Freelist exhausted, payload TRUNCATED: "
                            "[%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                            VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                            VSL_CDATA(t->c->rec.ptr));
                        break;
                    }
                    VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
                }

                int n = len;
                chunk = VSTAILQ_FIRST(&rec->chunks);
                const char *p = (const char *) VSL_CDATA(t->c->rec.ptr);
                while (n > 0 && chunk != NULL) {
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
            rec->state = DATA_DONE;
        }
    }
    tx->state = TX_DONE;
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

    if (FMT_Init(scratch) != 0) {
        LOG_Log(LOG_ALERT, "Error in output formats: %s", scratch);
        exit(EXIT_FAILURE);
    }

    if (!EMPTY(config.varnish_bindump))
        LOG_Log(LOG_INFO, "Reading from file: %s", config.varnish_bindump);
    else {
        strcpy(scratch, VSM_Name(vd));
        if (EMPTY(scratch))
            LOG_Log0(LOG_INFO, "Reading default varnish instance");
        else
            LOG_Log(LOG_INFO, "Reading varnish instance %s", scratch);
    }

    strcpy(scratch, FMT_Get_i_Arg());
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

    rdr_tx_free = DATA_Take_Freetx(&rdr_tx_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_tx_freelist));
    assert(rdr_tx_free == config.max_data);
    rdr_rec_free = DATA_Take_Freeline(&rdr_rec_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_rec_freelist));
    rdr_chunk_free = DATA_Take_Freechunk(&rdr_chunk_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_chunk_freelist));

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

    for (int i = 0; i < VSL_t__MAX; i++)
        tx_type_name[i] = 'X';
    tx_type_name[VSL_t_req] = 'c';
    tx_type_name[VSL_t_bereq] = 'b';
    tx_type_name[VSL_t_raw] = '-';

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
    FMT_Fini();
    AZ(pthread_cond_destroy(&data_ready_cond));
    AZ(pthread_mutex_destroy(&data_ready_lock));
    AZ(pthread_cond_destroy(&spscq_ready_cond));
    AZ(pthread_mutex_destroy(&spscq_ready_lock));
    LOG_Log0(LOG_INFO, "Exiting");
    LOG_Close();

    exit(EXIT_SUCCESS);
}
