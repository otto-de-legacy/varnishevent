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
#include "vtim.h"

#define DEFAULT_CONFIG "/etc/varnishevent.conf"

#define DISPATCH_EOL 0
#define DISPATCH_RETURN_OK 0
#define DISPATCH_CONTINUE 1
#define DISPATCH_EOF -1
#define DISPATCH_CLOSED -2
#define DISPATCH_OVERRUN -3
#define DISPATCH_IOERR -4
#define DISPATCH_TERMINATE 10
#define DISPATCH_REOPEN 11

static unsigned len_hi = 0;

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

/* Local freelists */
static chunkhead_t rdr_chunk_freelist
    = VSTAILQ_HEAD_INITIALIZER(rdr_chunk_freelist);
static unsigned rdr_chunk_free = 0;

static linehead_t rdr_rec_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_rec_freelist);
static unsigned rdr_rec_free = 0;

static txhead_t rdr_tx_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_tx_freelist);
static unsigned rdr_tx_free = 0;

static char cli_config_filename[BUFSIZ] = "";

static int tx_type_log[VSL_t__MAX], debug = 0;
static char tx_type_name[VSL_t__MAX];

void
RDR_Stats(void)
{
    LOG_Log(LOG_INFO, "Reader: seen=%lu submitted=%lu free_tx=%u free_rec=%u "
            "free_chunk=%u no_free_tx=%lu no_free_rec=%lu no_free_chunk=%lu "
            "len_hi=%u len_overflows=%lu",
            seen, submitted, rdr_tx_free, rdr_rec_free, rdr_chunk_free,
            no_free_tx, no_free_rec, no_free_chunk, len_hi, len_overflows);
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
        if (debug)
            LOG_Log(LOG_DEBUG, "Reader: took %u free chunks", rdr_chunk_free);
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
        if (debug)
            LOG_Log(LOG_DEBUG, "Reader: took %u free records", rdr_rec_free);
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
        if (debug)
            LOG_Log(LOG_DEBUG, "Reader: took %u free tx", rdr_tx_free);
    }
    tx = VSTAILQ_FIRST(&rdr_tx_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_tx_freelist, freelist);
    rdr_tx_free--;

    return (tx);
}

static inline void
take_free(void)
{
    rdr_tx_free += DATA_Take_Freetx(&rdr_tx_freelist);
    rdr_rec_free += DATA_Take_Freeline(&rdr_rec_freelist);
    rdr_chunk_free += DATA_Take_Freechunk(&rdr_chunk_freelist);
}

static inline void
submit(tx_t *tx)
{
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_DONE);
    SPSCQ_Enq(tx);
    signal_spscq_ready();
    submitted++;
}

static int
event(struct VSL_data *vsl, struct VSL_transaction * const pt[], void *priv)
{
    int status = DISPATCH_RETURN_OK;
    unsigned nrec = 0, total_chunks = 0;
    (void) priv;

    if (term)
        return DISPATCH_TERMINATE;

    for (struct VSL_transaction *t = pt[0]; t != NULL; t = *++pt) {
        struct tx_t *tx;

        if (!tx_type_log[t->type])
            continue;
            
        if (debug)
            LOG_Log(LOG_DEBUG, "Tx: [%u %c]", t->vxid, tx_type_name[t->type]);

        tx = take_tx();
        if (tx == NULL) {
            no_free_tx++;
            LOG_Log(LOG_DEBUG, "Freelist exhausted, tx DISCARDED: [%u %c]",
                    t->vxid, tx_type_name[t->type]);
            continue;
        }
        CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
        assert(tx->state == TX_EMPTY);
        assert(VSTAILQ_EMPTY(&tx->lines));
        tx->type = t->type;
        tx->vxid = t->vxid;
        if (tx->type == VSL_t_raw)
            tx->t = VTIM_real();

        while ((status = VSL_Next(t->c)) > 0) {
            int len, n, nchunk;
            logline_t *rec;
            chunk_t *chunk;
            const char *p;

            if (!VSL_Match(vsl, t->c))
                continue;

            len = VSL_LEN(t->c->rec.ptr);
            if (debug)
                LOG_Log(LOG_DEBUG, "Line: [%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                        VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                        VSL_CDATA(t->c->rec.ptr));

            rec = take_rec();
            if (rec == NULL) {
                no_free_rec++;
                LOG_Log(LOG_DEBUG, "Freelist exhausted, record DISCARDED: "
                        "[%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                        VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                        VSL_CDATA(t->c->rec.ptr));
                continue;
            }
            CHECK_OBJ_NOTNULL(rec, LOGLINE_MAGIC);
            assert(rec->state == DATA_EMPTY);
            assert(VSTAILQ_EMPTY(&rec->chunks));

            rec->tag = VSL_TAG(t->c->rec.ptr);
            n = len;
            if (len > len_hi)
                len_hi = len;
            if (len > config.max_reclen) {
                n = config.max_reclen;
                len_overflows++;
            }
            rec->len = n;

            /* Copy the payload into chunks */
            p = (const char *) VSL_CDATA(t->c->rec.ptr);
            nchunk = (n + config.chunk_size - 1) / config.chunk_size;
            for (int i = 0; i < nchunk; i++) {
                assert(n > 0);
                chunk = take_chunk();
                if (chunk == NULL) {
                    no_free_chunk++;
                    LOG_Log(LOG_DEBUG,
                            "Freelist exhausted, payload TRUNCATED: "
                            "[%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                            VSL_tags[VSL_TAG(t->c->rec.ptr)], len,
                            VSL_CDATA(t->c->rec.ptr));
                    continue;
                }
                CHECK_OBJ(chunk, CHUNK_MAGIC);
                assert(chunk->state == DATA_EMPTY);
                VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
                int cp = n;
                if (cp > config.chunk_size)
                    cp = config.chunk_size;
                memcpy(chunk->data, p, cp);
                chunk->state = DATA_DONE;
                p += cp;
                n -= cp;
                total_chunks++;
            }
            rec->state = DATA_DONE;
            VSTAILQ_INSERT_TAIL(&tx->lines, rec, linelist);
            nrec++;
        }

        if (nrec == 0) {
            VSTAILQ_INSERT_HEAD(&rdr_tx_freelist, tx, freelist);
            continue;
        }

        tx->state = TX_DONE;
        seen++;
        MON_StatsUpdate(STATS_DONE, nrec, total_chunks);
        if (tx_occ > tx_occ_hi)
            tx_occ_hi = tx_occ;
        if (rec_occ > rec_occ_hi)
            rec_occ_hi = rec_occ;
        if (chunk_occ > chunk_occ_hi)
            chunk_occ_hi = chunk_occ;
        submit(tx);
    }
    
    if (!reopen)
        return status;
    return DISPATCH_REOPEN;
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
    int c, errnum, status, a_flag = 0, v_flag = 0, d_flag = 0, D_flag = 0;
#if 0
    const char *P_arg = NULL;
#endif
    char *w_arg = NULL, *q_arg = NULL, *g_arg = NULL;
    char scratch[BUFSIZ];
#if 0
    struct vpf_fh *pfh = NULL;
#endif
    struct VSL_data *vsl;
    struct VSLQ *vslq;
    struct VSM_data *vsm;
    struct VSL_cursor *cursor;
    enum VSL_grouping_e grouping = VSL_g_vxid;

    vsl = VSL_New();

    CONF_Init();
    read_default_config();

    while ((c = getopt(argc, argv, "adDvP:Vw:F:g:f:q:r:")) != -1) {
        switch (c) {
        case 'a':
            a_flag = 1;
            break;
        case 'd':
            d_flag = 1;
            break;
        case 'F':
            strcpy(config.cformat, optarg);
            break;
        case 'D':
#ifdef HAVE_DAEMON
            D_flag = 1;
#else
            fprintf(stderr, "-D not supported");
            exit(EXIT_FAILURE);
#endif
            break;
#if 0
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
        case 'v':
            v_flag = 1;
            break;
        case 'g':
            REPLACE(g_arg, optarg);
            break;
        case 'f':
            strcpy(cli_config_filename, optarg);
            break;
        case 'q':
            REPLACE(q_arg, optarg);
            break;
        case 'r':
            strcpy(config.varnish_bindump, optarg);
            break;
        default:
            if ((errnum = VSL_Arg(vsl, c, optarg)) <= 0) {
                if (errnum == -1)
                    fprintf(stderr, "-%c: %s\n", c, VSL_Error(vsl));
                else
                    fprintf(stderr, "unknown option -%c\n", c);
                usage();
            }
            break;
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

#if 0
    if (P_arg && (pfh = VPF_Open(P_arg, 0644, NULL)) == NULL) {
        perror(P_arg);
        exit(1);
    }
#endif

#ifdef HAVE_DAEMON
    if (D_flag && daemon(0, 0) == -1) {
        perror("daemon()");
#if 0
        if (pfh != NULL)
            VPF_Remove(pfh);
#endif
        exit(1);
    }
#endif

    if (LOG_Open(config.syslog_ident) != 0) {
        exit(EXIT_FAILURE);
    }
    if (v_flag) {
        debug = 1;
        LOG_SetLevel(LOG_DEBUG);
    }

    LOG_Log(LOG_INFO, "initializing (%s)", VCS_version);

    /* XXX: also set grouping in config file */
    if (g_arg != NULL) {
        grouping = VSLQ_Name2Grouping(g_arg, -1);
        if (grouping == -1 || grouping == -2) {
            LOG_Log(LOG_CRIT, "Unknown grouping: %s", g_arg);
            exit(EXIT_FAILURE);
        }
        switch(grouping) {
        case VSL_g_session:
            LOG_Log0(LOG_CRIT, "Session grouping not permitted");
            exit(EXIT_FAILURE);
        case VSL_g_raw:
            if (!EMPTY(config.cformat) || !EMPTY(config.bformat)) {
                /* XXX: this can be allowed with multi-threaded readers */
                LOG_Log0(LOG_CRIT, "Raw grouping cannot be used with client "
                         "or backend logging");
                exit(EXIT_FAILURE);
            }
            break;
        case VSL_g_vxid:
        case VSL_g_request:
            break;
        default:
            WRONG("Unknown grouping");
        }
    }

    if (!EMPTY(config.rformat)) {
        if (!EMPTY(config.cformat) || !EMPTY(config.bformat)) {
            /* XXX: this can be allowed with multi-threaded readers */
            LOG_Log0(LOG_CRIT, "Raw logging cannot be combined with client "
                     "or backend logging");
            exit(EXIT_FAILURE);
        }
        grouping = VSL_g_raw;
    }

    if (EMPTY(config.varnish_bindump)) {
        unsigned options = VSL_COPT_BATCH;
        vsm = VSM_New();
        AN(vsm);
        if (VSM_Open(vsm) < 0) {
            LOG_Log(LOG_CRIT, "Cannot attach to shared memory for instance %s: "
                    "%s", VSM_Name(vsm), VSM_Error(vsm));
            exit(EXIT_FAILURE);
        }
        if (!d_flag)
            options |= VSL_COPT_TAIL;
        cursor = VSL_CursorVSM(vsl, vsm, options);
    }
    else
        cursor = VSL_CursorFile(vsl, config.varnish_bindump, 0);
    if (cursor == NULL) {
        LOG_Log(LOG_CRIT, "Cannot open log: %s\n", VSL_Error(vsl));
        exit(EXIT_FAILURE);
    }
    vslq = VSLQ_New(vsl, &cursor, grouping, q_arg);
    if (vslq == NULL) {
        LOG_Log(LOG_CRIT, "Cannot init log query: %s\n", VSL_Error(vsl));
        exit(EXIT_FAILURE);
    }

    terminate_action.sa_handler = terminate;
    AZ(sigemptyset(&terminate_action.sa_mask));
    terminate_action.sa_flags &= ~SA_RESTART;

    dump_action.sa_handler = dump;
    AZ(sigemptyset(&dump_action.sa_mask));
    dump_action.sa_flags |= SA_RESTART;

    reopen_action.sa_handler = sigreopen;
    AZ(sigemptyset(&reopen_action.sa_mask));
    reopen_action.sa_flags |= SA_RESTART;

    stacktrace_action.sa_handler = HNDL_Abort;

    ignore_action.sa_handler = SIG_IGN;
    default_action.sa_handler = SIG_DFL;

    HNDL_Init(argv[0]);

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

    VAS_Fail = assert_fail;

    if (FMT_Init(scratch) != 0) {
        LOG_Log(LOG_ALERT, "Error in output formats: %s", scratch);
        exit(EXIT_FAILURE);
    }

    if (!EMPTY(config.varnish_bindump))
        LOG_Log(LOG_INFO, "Reading from file: %s", config.varnish_bindump);
    else {
        strcpy(scratch, VSM_Name(vsm));
        if (EMPTY(scratch))
            LOG_Log0(LOG_INFO, "Reading default varnish instance");
        else
            LOG_Log(LOG_INFO, "Reading varnish instance %s", scratch);
    }

    char **include_args = FMT_Get_I_Args();
    if (include_args == 0) {
        LOG_Log0(LOG_CRIT, "Not configured to read any data, exiting");
        exit(EXIT_FAILURE);
    }
    assert(VSL_Arg(vsl, 'C', NULL) > 0);
    for (int i = 0; include_args[i] != NULL; i++) {
        assert(VSL_Arg(vsl, 'I', include_args[i]) > 0);
        LOG_Log(LOG_INFO, "Include filter: %s", include_args[i]);
    }

    if (!EMPTY(config.cformat) && EMPTY(config.bformat))
        assert(VSL_Arg(vsl, 'c', scratch) > 0);
    else if (!EMPTY(config.bformat) && EMPTY(config.cformat))
        assert(VSL_Arg(vsl, 'b', scratch) > 0);

    if ((errnum = DATA_Init()) != 0) {
        LOG_Log(LOG_ALERT, "Cannot init data tables: %s\n",
                strerror(errnum));
        exit(EXIT_FAILURE);
    }

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

    for (int i = 0; i < VSL_t__MAX; i++) {
        tx_type_log[i] = 0;
        tx_type_name[i] = 'X';
    }
    if (!EMPTY(config.cformat))
        tx_type_log[VSL_t_req] = 1;
    if (!EMPTY(config.bformat))
        tx_type_log[VSL_t_bereq] = 1;
    if (!EMPTY(config.rformat))
        tx_type_log[VSL_t_raw] = 1;
    tx_type_name[VSL_t_req] = 'c';
    tx_type_name[VSL_t_bereq] = 'b';
    tx_type_name[VSL_t_raw] = '-';

    WRT_Start();
    /* XXX: configure wrt_waits and sleep interval? */
    int wrt_waits = 0;
    while (!WRT_Running()) {
        if (wrt_waits++ > 10) {
            LOG_Log0(LOG_ALERT, "Writer thread not running, giving up");
            exit(EXIT_FAILURE);
        }
        VTIM_sleep(1);
    }

    /* Main loop */
    term = 0;
    while (!term) {
        status = VSLQ_Dispatch(vslq, event, NULL);
        switch(status) {
        case DISPATCH_CONTINUE:
            continue;
        case DISPATCH_REOPEN:
            take_free();
            LOG_Log0(LOG_INFO, "Signal received to re-open output");
            WRT_Reopen();
            reopen = 0;
            continue;
        case DISPATCH_EOL:
            take_free();
            VTIM_sleep(config.idle_pause);
            continue;
        case DISPATCH_TERMINATE:
            assert(term == 1);
            LOG_Log0(LOG_INFO, "Termination signal received, will flush"
                     "pending transactions and exit");
            break;
        case DISPATCH_EOF:
            term = 1;
            LOG_Log0(LOG_INFO, "Reached end of file, will exit");
            break;
        /* XXX: for the rest of these, try to flush, re-acquire the log and
           continue. */
        case DISPATCH_CLOSED:
            term = 1;
            LOG_Log0(LOG_ERR, "Log was closed or abandoned, will exit");
            break;
        case DISPATCH_OVERRUN:
            term = 1;
            LOG_Log0(LOG_ERR, "Log reads were overrun, will exit");
            break;
        case DISPATCH_IOERR:
            term = 1;
            LOG_Log(LOG_ERR,
                    "IO error reading the log, will exit: %s (errno = %d)",
                    strerror(errno), errno);
            break;
        default:
            WRONG("Unknown return status from dispatcher");
        }
    }

    if (status == DISPATCH_TERMINATE)
        VSLQ_Flush(vslq, event, NULL);

    WRT_Halt();
    WRT_Fini();
    SPSCQ_Shutdown();
    MON_Shutdown();
    FMT_Fini();
    AZ(pthread_cond_destroy(&spscq_ready_cond));
    AZ(pthread_mutex_destroy(&spscq_ready_lock));
    LOG_Log0(LOG_INFO, "Exiting");
    LOG_Close();

    exit(EXIT_SUCCESS);
}
