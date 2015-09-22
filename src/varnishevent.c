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
#include "vqueue.h"
#include "vapi/vsl.h"
#include "vre.h"
#include "miniobj.h"
#include "vas.h"
#include "vdef.h"

#include "varnishevent.h"
#include "vtim.h"
#include "vpf.h"
#include "vcs_version.h"
#include "vmb.h"

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
#define DISPATCH_FLUSH 12

#define MAX_IDLE_PAUSE 0.01

const char *version = PACKAGE_TARNAME "-" PACKAGE_VERSION " revision "  \
    VCS_Version " branch " VCS_Branch;

static unsigned len_hi = 0, closed = 0, overrun = 0, ioerr = 0, reacquire = 0,
    tx_thresh, rec_thresh, chunk_thresh, waiting = 0;

static unsigned long seen = 0, submitted = 0, len_overflows = 0, no_free_tx = 0,
    no_free_rec = 0, no_free_chunk = 0, eol = 0, waits = 0;

/* Hack, because we cannot have #ifdef in the macro definition SIGDISP */
#define _UNDEFINED(SIG) ((#SIG)[0] == 0)
#define UNDEFINED(SIG) _UNDEFINED(SIG)

#define SIGDISP(SIG, action)						\
    do { if (UNDEFINED(SIG)) break;					\
        if (sigaction((SIG), (&action), NULL) != 0)			\
            LOG_Log(LOG_ERR,						\
                "Cannot install handler for " #SIG ": %s",		\
                strerror(errno));					\
    } while(0)

static struct sigaction dump_action, terminate_action, reopen_action,
    stacktrace_action, ignore_action, flush_action;

static volatile sig_atomic_t reopen = 0, term = 0, flush = 0;

/* Local freelists */
static chunkhead_t rdr_chunk_freelist
    = VSTAILQ_HEAD_INITIALIZER(rdr_chunk_freelist);
static unsigned rdr_chunk_free = 0;

static rechead_t rdr_rec_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_rec_freelist);
static unsigned rdr_rec_free = 0;

static txhead_t rdr_tx_freelist = VSTAILQ_HEAD_INITIALIZER(rdr_tx_freelist);
static unsigned rdr_tx_free = 0;

static int tx_type_log[VSL_t__MAX], debug = 0;
static char tx_type_name[VSL_t__MAX];
static const char *statename[] = { "running", "waiting" };

static double idle_pause = MAX_IDLE_PAUSE;

void
RDR_Stats(void)
{
    LOG_Log(LOG_INFO, "Reader (%s): seen=%lu submitted=%lu free_tx=%u "
            "free_rec=%u free_chunk=%u no_free_tx=%lu no_free_rec=%lu "
            "no_free_chunk=%lu len_hi=%u len_overflows=%lu eol=%lu "
            "idle_pause=%.06f waits=%lu closed=%u overrun=%u ioerr=%u "
            "reacquire=%u",
            statename[waiting], seen, submitted, rdr_tx_free, rdr_rec_free,
            rdr_chunk_free, no_free_tx, no_free_rec, no_free_chunk, len_hi,
            len_overflows, eol, idle_pause, waits, closed, overrun, ioerr,
            reacquire);
}

int
RDR_Depleted(void)
{
    return (rdr_tx_free < tx_thresh) || (rdr_rec_free < rec_thresh)
        || (rdr_chunk_free < chunk_thresh);
}

int
RDR_Waiting(void)
{
    return waiting;
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

static void
data_wait(void)
{
    assert(config.reader_timeout > 0.);
    if (!WRT_Waiting()) {
        struct timespec ts;
        int ret;

        AZ(pthread_mutex_lock(&data_ready_lock));
        waits++;
        waiting = 1;
        ts = VTIM_timespec(VTIM_real() + config.reader_timeout);
        ret = pthread_cond_timedwait(&data_ready_cond, &data_ready_lock, &ts);
        assert(ret == 0 || ret == ETIMEDOUT);
        waiting = 0;
        AZ(pthread_mutex_unlock(&data_ready_lock));
    }
}

static inline chunk_t
*take_chunk(void)
{
    chunk_t *chunk;

    if (VSTAILQ_EMPTY(&rdr_chunk_freelist)) {
        signal_spscq_ready();
        rdr_chunk_free = DATA_Take_Freechunk(&rdr_chunk_freelist);
        if (VSTAILQ_EMPTY(&rdr_chunk_freelist)) {
            if (config.reader_timeout <= 0.)
                return NULL;
            data_wait();
            rdr_chunk_free = DATA_Take_Freechunk(&rdr_chunk_freelist);
            if (VSTAILQ_EMPTY(&rdr_chunk_freelist))
                return NULL;
        }
        if (debug)
            LOG_Log(LOG_DEBUG, "Reader: took %u free chunks", rdr_chunk_free);
    }
    chunk = VSTAILQ_FIRST(&rdr_chunk_freelist);
    VSTAILQ_REMOVE_HEAD(&rdr_chunk_freelist, freelist);
    rdr_chunk_free--;

    return (chunk);
}

static inline rec_t
*take_rec(void)
{
    rec_t *rec;

    if (VSTAILQ_EMPTY(&rdr_rec_freelist)) {
        signal_spscq_ready();
        rdr_rec_free = DATA_Take_Freerec(&rdr_rec_freelist);
        if (VSTAILQ_EMPTY(&rdr_rec_freelist)) {
            if (config.reader_timeout <= 0.)
                return NULL;
            data_wait();
            rdr_rec_free = DATA_Take_Freerec(&rdr_rec_freelist);
            if (VSTAILQ_EMPTY(&rdr_rec_freelist))
                return NULL;
        }
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
        if (VSTAILQ_EMPTY(&rdr_tx_freelist)) {
            if (config.reader_timeout <= 0.)
                return NULL;
            data_wait();
            rdr_tx_free = DATA_Take_Freetx(&rdr_tx_freelist);
            if (VSTAILQ_EMPTY(&rdr_tx_freelist))
                return NULL;
        }
        if (debug)
            LOG_Log(LOG_DEBUG, "Reader: took %u free tx", rdr_tx_free);
    }
    tx = VSTAILQ_FIRST(&rdr_tx_freelist);
    assert(tx->state == TX_FREE);
    VSTAILQ_REMOVE_HEAD(&rdr_tx_freelist, freelist);
    tx->state = TX_OPEN;
    rdr_tx_free--;

    return (tx);
}

static void
take_free(void)
{
    rdr_tx_free += DATA_Take_Freetx(&rdr_tx_freelist);
    rdr_rec_free += DATA_Take_Freerec(&rdr_rec_freelist);
    rdr_chunk_free += DATA_Take_Freechunk(&rdr_chunk_freelist);
}

static inline void
submit(tx_t *tx)
{
    CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
    assert(tx->state == TX_DONE);
    tx->state = TX_SUBMITTED;
    VWMB();
    SPSCQ_Enq(tx);
    signal_spscq_ready();
    submitted++;
}

static int
event(struct VSL_data *vsl, struct VSL_transaction * const pt[], void *priv)
{
    int status = DISPATCH_RETURN_OK;
    unsigned nrec = 0, total_chunks = 0;
    (void) vsl;
    (void) priv;

    for (struct VSL_transaction *t = pt[0]; t != NULL; t = *++pt) {
        struct tx_t *tx;

        if (!tx_type_log[t->type])
            continue;
            
        if (debug)
            LOG_Log(LOG_DEBUG, "Tx: [%u %c]", t->vxid, tx_type_name[t->type]);

        seen++;
        tx = take_tx();
        if (tx == NULL) {
            no_free_tx++;
            LOG_Log(LOG_DEBUG, "Freelist exhausted, tx DISCARDED: [%u %c]",
                    t->vxid, tx_type_name[t->type]);
            continue;
        }
        CHECK_OBJ_NOTNULL(tx, TX_MAGIC);
        assert(tx->state == TX_OPEN);
        assert(tx->disp == DISP_NONE);
        AN(tx->recs);
        tx->type = t->type;
        tx->vxid = t->vxid;
        tx->pvxid = t->vxid_parent;
        if (tx->type == VSL_t_raw)
            tx->t = VTIM_real();

        while ((status = VSL_Next(t->c)) > 0) {
            enum VSL_tag_e tag;
            int idx, hdr_idx, len, n, nchunk;
            rec_t *rec, **rp;
            chunk_t *chunk;
            const char *p;

            if ((idx = tag2idx[VSL_TAG(t->c->rec.ptr)]) == -1)
                continue;
            tag = VSL_TAG(t->c->rec.ptr);
            p = (const char *) VSL_CDATA(t->c->rec.ptr);
            len = VSL_LEN(t->c->rec.ptr);

            switch(tag) {
            case SLT_VCL_call:
            case SLT_VCL_return:
                if (tx->disp != DISP_NONE)
                    continue;
                if (strncasecmp("hit", p, len) == 0)
                    tx->disp = DISP_HIT;
                else if (strncasecmp("miss", p, len) == 0)
                    tx->disp = DISP_MISS;
                else if (strncasecmp("pass", p, len) == 0)
                    tx->disp = DISP_PASS;
                else if (strncasecmp("error", p, len) == 0)
                    tx->disp = DISP_ERROR;
                else if (strncasecmp("pipe", p, len) == 0)
                    tx->disp = DISP_PIPE;
                if (debug && tx->disp != DISP_NONE)
                    LOG_Log(LOG_DEBUG, "Record: [%u %s %.*s]",
                            VSL_ID(t->c->rec.ptr), VSL_tags[tag], len, p);
                continue;
            default:
                break;
            }

            CHECK_OBJ_NOTNULL(tx->recs[idx], REC_NODE_MAGIC);
            if (tx->recs[idx]->rec != NULL)
                continue;
            if (tx->recs[idx]->hdrs != NULL) {
                hdr_idx = HDR_FindIdx(hdr_trie[tag], p);
                if (hdr_idx == -1)
                    continue;
                if (tx->recs[idx]->hdrs[hdr_idx] != NULL)
                    continue;
                rp = &tx->recs[idx]->hdrs[hdr_idx];
            }
            else
                rp = &tx->recs[idx]->rec;

            if (debug)
                LOG_Log(LOG_DEBUG, "Record: [%u %s %.*s]",
                        VSL_ID(t->c->rec.ptr), VSL_tags[tag], len, p);

            rec = take_rec();
            if (rec == NULL) {
                no_free_rec++;
                LOG_Log(LOG_DEBUG, "Freelist exhausted, record DISCARDED: "
                        "[%u %s %.*s]", VSL_ID(t->c->rec.ptr), VSL_tags[tag],
                        len, p);
                continue;
            }
            CHECK_OBJ_NOTNULL(rec, RECORD_MAGIC);
            assert(!OCCUPIED(rec));
            assert(VSTAILQ_EMPTY(&rec->chunks));
            *rp = rec;

            rec->tag = tag;
            n = len;
            if (len > len_hi)
                len_hi = len;
            if (len > config.max_reclen) {
                n = config.max_reclen;
                len_overflows++;
            }
            rec->len = n;

            /* Copy the payload into chunks */
            nchunk = (n + config.chunk_size - 1) / config.chunk_size;
            for (int i = 0; i < nchunk; i++) {
                assert(n > 0);
                chunk = take_chunk();
                if (chunk == NULL) {
                    no_free_chunk++;
                    LOG_Log(LOG_DEBUG,
                            "Freelist exhausted, payload TRUNCATED: "
                            "[%u %s %.*s]", VSL_ID(t->c->rec.ptr),
                            VSL_tags[tag], len, p);
                    continue;
                }
                CHECK_OBJ(chunk, CHUNK_MAGIC);
                assert(!OCCUPIED(chunk));
                VSTAILQ_INSERT_TAIL(&rec->chunks, chunk, chunklist);
                int cp = n;
                if (cp > config.chunk_size)
                    cp = config.chunk_size;
                memcpy(chunk->data, p, cp);
                chunk->occupied = 1;
                p += cp;
                n -= cp;
                total_chunks++;
            }
            rec->occupied = 1;
            nrec++;
        }

        if (nrec == 0) {
            tx->state = TX_FREE;
            tx->type = VSL_t_unknown;
            tx->vxid = -1;
            tx->pvxid = -1;
            tx->t = 0.;
            VSTAILQ_INSERT_HEAD(&rdr_tx_freelist, tx, freelist);
            continue;
        }

        assert(tx->state == TX_OPEN);
        tx->state = TX_DONE;
        MON_StatsUpdate(STATS_DONE, nrec, total_chunks);
        if (tx_occ > tx_occ_hi)
            tx_occ_hi = tx_occ;
        if (rec_occ > rec_occ_hi)
            rec_occ_hi = rec_occ;
        if (chunk_occ > chunk_occ_hi)
            chunk_occ_hi = chunk_occ;
        submit(tx);
    }

    if (term)
        return DISPATCH_TERMINATE;
    if (flush)
        return DISPATCH_FLUSH;
    if (!reopen)
        return status;
    return DISPATCH_REOPEN;
}

/*--------------------------------------------------------------------*/

static void
sigreopen(int sig)
{
    LOG_Log(LOG_NOTICE, "Received signal %d (%s), reopening output",
            sig, strsignal(sig));
    reopen = 1;
}

static void
dump(int sig)
{
    LOG_Log(LOG_NOTICE, "Received signal %d (%s), "
            "dumping config and data table", sig, strsignal(sig));
    CONF_Dump();
    DATA_Dump();
}

static void
terminate(int sig)
{
    term = 1;
    flush = 1;
    LOG_Log(LOG_NOTICE, "Received signal %d (%s), terminating",
            sig, strsignal(sig));
}

static void
sigflush(int sig)
{
    flush = 1;
    LOG_Log(LOG_NOTICE, "Received signal %d (%s), "
            "flushing pending transactions", sig, strsignal(sig));
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
usage(int status)
{
    fprintf(stderr,
            "usage: varnishevent [-adDhvV] [-f configfile] [-F format]\n"
            "                    [-g grouping] [-L txlimit] [-n name] \n"
            "                    [-N vsmfile] [-P pidfile] [-q query] \n"
            "                    [-r binlog] [-T txtimeout] [-w outputfile]\n");
    exit(status);
}

int
main(int argc, char *argv[])
{
    int c, errnum, status, a_flag = 0, v_flag = 0, d_flag = 0, D_flag = 0;
    char *P_arg = NULL, *w_arg = NULL, *q_arg = NULL, *g_arg = NULL,
        *n_arg = NULL, *N_arg = NULL, scratch[BUFSIZ];
    char cli_config_filename[PATH_MAX + 1] = "";
    struct vpf_fh *pfh = NULL;
    struct VSL_data *vsl;
    struct VSLQ *vslq;
    struct VSM_data *vsm = NULL;
    struct VSL_cursor *cursor;
    enum VSL_grouping_e grouping = VSL_g_vxid;
    unsigned long last_seen = 0;
    double last_t;

    vsl = VSL_New();

    CONF_Init();
    read_default_config();

    while ((c = getopt(argc, argv, "adDhvVP:w:F:g:f:q:r:n:N:L:T:")) != -1) {
        switch (c) {
        case 'a':
            a_flag = 1;
            break;
        case 'd':
            d_flag = 1;
            break;
        case 'F':
            VSB_clear(config.cformat);
            VSB_cpy(config.cformat, optarg);
            VSB_finish(config.cformat);
            break;
        case 'D':
#ifdef HAVE_DAEMON
            D_flag = 1;
#else
            fprintf(stderr, "-D not supported");
            exit(EXIT_FAILURE);
#endif
            break;
        case 'P':
            REPLACE(P_arg, optarg);
            break;
        case 'V':
            fprintf(stderr, "varnishevent (%s)\n", version);
            fprintf(stderr, "Copyright (c) 2012-2015 UPLEX Nils Goroll "
                    "Systemoptimierung\n");
            fprintf(stderr, "Copyright (c) 2012-2015 Otto Gmbh & Co KG\n");
            fprintf(stderr, "Portions adapted from Varnish:\n");
            fprintf(stderr, "Copyright (c) 2006 Verdens Gang AS\n");
            fprintf(stderr, "Copyright (c) 2006-2015 Varnish Software AS\n");
            exit(EXIT_SUCCESS);
        case 'w':
            REPLACE(w_arg, optarg);
            break;
        case 'v':
            v_flag = 1;
            break;
        case 'g':
            REPLACE(g_arg, optarg);
            break;
        case 'f':
            if (strlen(optarg) > PATH_MAX) {
                fprintf(stderr, "-f: path length exceeds max %d\n", PATH_MAX);
                usage(EXIT_FAILURE);
            }
            bprintf(cli_config_filename, "%s", optarg);
            break;
        case 'q':
            REPLACE(q_arg, optarg);
            break;
        case 'n':
            REPLACE(n_arg, optarg);
            break;
        case 'N':
            REPLACE(N_arg, optarg);
            d_flag = 1;
            break;
        case 'r':
            bprintf(config.varnish_bindump, "%s", optarg);
            break;
        case 'L':
        case 'T':
            if ((errnum = VSL_Arg(vsl, c, optarg)) < 0) {
                fprintf(stderr, "%s\n", VSL_Error(vsl));
                usage(EXIT_FAILURE);
            }
            /* XXX: VSL_Arg doesn't check this */
            if (c == 'L' && atoi(optarg) == 0) {
                fprintf(stderr, "-L: Range error\n");
                usage(EXIT_FAILURE);
            }
            AN(errnum);
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        default:
            usage(EXIT_FAILURE);
        }
    }

    if (n_arg && N_arg) {
        fprintf(stderr, "Cannot have both -n and -N options\n");
        usage(EXIT_FAILURE);
    }

    if (! EMPTY(cli_config_filename)) {
        printf("Reading config from %s\n", cli_config_filename);
        if (CONF_ReadFile(cli_config_filename) != 0) {
            fprintf(stderr, "Error reading config from %s\n",
                cli_config_filename);
            exit(EXIT_FAILURE);
        }
    }

    if (!EMPTY(config.varnish_bindump) && (n_arg || N_arg)) {
        fprintf(stderr, "Cannot specify -r/varnish.bindump together with -n "
                " or -N\n");
        usage(EXIT_FAILURE);
    }

    if (P_arg && (pfh = VPF_Open(P_arg, 0644, NULL)) == NULL) {
        perror(P_arg);
        exit(EXIT_FAILURE);
    }

#ifdef HAVE_DAEMON
    if (D_flag && daemon(0, 0) == -1) {
        perror("daemon()");
        exit(EXIT_FAILURE);
    }
#endif

    if (LOG_Open(VSB_data(config.syslog_ident)) != 0) {
        exit(EXIT_FAILURE);
    }
    if (v_flag) {
        debug = 1;
        LOG_SetLevel(LOG_DEBUG);
    }

    LOG_Log(LOG_NOTICE, "initializing (%s)", version);

    if (pfh != NULL) {
        errno = 0;
        if (VPF_Write(pfh) != 0) {
            LOG_Log(LOG_CRIT, "Cannot write pid file %s, exiting: %s", P_arg,
                    strerror(errno));
            exit(EXIT_FAILURE);
        }
        errno = 0;
    }
    
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
            if (!VSB_EMPTY(config.cformat) || !VSB_EMPTY(config.bformat)) {
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

    if (!VSB_EMPTY(config.rformat)) {
        if (!VSB_EMPTY(config.cformat) || !VSB_EMPTY(config.bformat)) {
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
        if (n_arg && VSM_n_Arg(vsm, n_arg) <= 0) {
            LOG_Log(LOG_CRIT, "-n %s: %s\n", n_arg, VSM_Error(vsm));
            exit(EXIT_FAILURE);
        }
        else if (N_arg && VSM_N_Arg(vsm, N_arg) <= 0) {
            LOG_Log(LOG_CRIT, "-N %s: %s\n", n_arg, VSM_Error(vsm));
            exit(EXIT_FAILURE);
        }
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

    flush_action.sa_handler = sigflush;
    AZ(sigemptyset(&flush_action.sa_mask));
    flush_action.sa_flags |= SA_RESTART;

    stacktrace_action.sa_handler = HNDL_Abort;

    ignore_action.sa_handler = SIG_IGN;
    default_action.sa_handler = SIG_DFL;

    HNDL_Init(argv[0]);

    /* Install signal handlers */
#include "signals.h"

    if (w_arg)
        bprintf(config.output_file, "%s", w_arg);
    if (!EMPTY(config.output_file))
        SIGDISP(SIGHUP, reopen_action);
    else
        SIGDISP(SIGHUP, ignore_action);
    if (a_flag)
        config.append = 1;

    VAS_Fail = assert_fail;

    if (FMT_Init(scratch) != 0) {
        LOG_Log(LOG_CRIT, "Error in output formats: %s", scratch);
        exit(EXIT_FAILURE);
    }

    if (!EMPTY(config.varnish_bindump))
        LOG_Log(LOG_INFO, "Reading from file: %s", config.varnish_bindump);
    else {
        if (EMPTY(VSM_Name(vsm)))
            LOG_Log0(LOG_INFO, "Reading default varnish instance");
        else
            LOG_Log(LOG_INFO, "Reading varnish instance %s", VSM_Name(vsm));
    }

    if (!VSB_EMPTY(config.cformat) && VSB_EMPTY(config.bformat))
        assert(VSL_Arg(vsl, 'c', scratch) > 0);
    else if (!VSB_EMPTY(config.bformat) && VSB_EMPTY(config.cformat))
        assert(VSL_Arg(vsl, 'b', scratch) > 0);

    for (int i = 0; i < MAX_VSL_TAG; i++) {
        int idx = tag2idx[i];
        if (idx == -1)
            continue;
        if (hdr_trie[i] == NULL)
            LOG_Log(LOG_INFO, "Reading tag %s", VSL_tags[i]);
        else {
            struct vsb *hdrs = VSB_new_auto();
            HDR_List(hdr_trie[i], hdrs);
            VSB_finish(hdrs);
            LOG_Log(LOG_INFO, "Reading tags %s with headers: %s", VSL_tags[i],
                    VSB_data(hdrs));
            VSB_delete(hdrs);
        }
    }

    if ((errnum = DATA_Init()) != 0) {
        LOG_Log(LOG_CRIT, "Cannot init data tables: %s\n",
                strerror(errnum));
        exit(EXIT_FAILURE);
    }

    AZ(pthread_cond_init(&spscq_ready_cond, NULL));
    AZ(pthread_mutex_init(&spscq_ready_lock, NULL));
    AZ(pthread_cond_init(&data_ready_cond, NULL));
    AZ(pthread_mutex_init(&data_ready_lock, NULL));

    if (config.monitor_interval > 0)
        MON_Start();
    else
        LOG_Log0(LOG_INFO, "Monitoring thread not running");

    if ((errnum = WRT_Init()) != 0) {
        LOG_Log(LOG_CRIT, "Cannot init writer thread: %s\n", strerror(errnum));
        exit(EXIT_FAILURE);
    }

    rdr_tx_free = DATA_Take_Freetx(&rdr_tx_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_tx_freelist));
    assert(rdr_tx_free == config.max_data);
    rdr_rec_free = DATA_Take_Freerec(&rdr_rec_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_rec_freelist));
    rdr_chunk_free = DATA_Take_Freechunk(&rdr_chunk_freelist);
    assert(!VSTAILQ_EMPTY(&rdr_chunk_freelist));

    tx_thresh = config.max_data >> 1;
    rec_thresh = nrecords >> 1;
    chunk_thresh = nchunks >> 1;

    for (int i = 0; i < VSL_t__MAX; i++) {
        tx_type_log[i] = 0;
        tx_type_name[i] = 'X';
    }
    if (!VSB_EMPTY(config.cformat))
        tx_type_log[VSL_t_req] = 1;
    if (!VSB_EMPTY(config.bformat))
        tx_type_log[VSL_t_bereq] = 1;
    if (!VSB_EMPTY(config.rformat))
        tx_type_log[VSL_t_raw] = 1;
    tx_type_name[VSL_t_req] = 'c';
    tx_type_name[VSL_t_bereq] = 'b';
    tx_type_name[VSL_t_raw] = '-';

    WRT_Start();
    /* XXX: configure wrt_waits and sleep interval? */
    int wrt_waits = 0;
    while (!WRT_Running()) {
        if (wrt_waits++ > 10) {
            LOG_Log0(LOG_CRIT, "Writer thread not running, giving up");
            exit(EXIT_FAILURE);
        }
        VTIM_sleep(1);
    }

    /* Main loop */
    term = 0;
    last_t = VTIM_mono();
    status = DISPATCH_CONTINUE;
    while (!term) {
        status = VSLQ_Dispatch(vslq, event, NULL);
        switch(status) {
        case DISPATCH_CONTINUE:
            continue;
        case DISPATCH_REOPEN:
            take_free();
            WRT_Reopen();
            reopen = 0;
            continue;
        case DISPATCH_EOL:
            take_free();
            eol++;
            /* re-adjust idle pause every 1024 seen txn */
            if ((seen & (~0L << 10)) > (last_seen & (~0L << 10))) {
                double t = VTIM_mono();
                idle_pause = (t - last_t) / (double) (seen - last_seen);
                last_seen = seen;
                if (idle_pause > MAX_IDLE_PAUSE)
                    idle_pause = MAX_IDLE_PAUSE;
                if (idle_pause < 1e-6)
                    idle_pause = 1e-6;
                last_t = t;
            }
            VTIM_sleep(idle_pause);
            if (!flush)
                continue;
            break;
        case DISPATCH_TERMINATE:
            AN(term);
            AN(flush);
            break;
        case DISPATCH_FLUSH:
            AN(flush);
            break;
        case DISPATCH_EOF:
            term = 1;
            LOG_Log0(LOG_NOTICE, "Reached end of file");
            break;
        case DISPATCH_CLOSED:
            flush = 1;
            closed++;
            LOG_Log0(LOG_ERR, "Log was closed or abandoned");
            break;
        case DISPATCH_OVERRUN:
            flush = 1;
            overrun++;
            LOG_Log0(LOG_ERR, "Log reads were overrun");
            break;
        case DISPATCH_IOERR:
            flush = 1;
            ioerr++;
            LOG_Log(LOG_ERR,
                    "IO error reading the log: %s (errno = %d)",
                    strerror(errno), errno);
            break;
        default:
            WRONG("Unknown return status from dispatcher");
        }
        if (flush) {
            LOG_Log0(LOG_NOTICE, "Flushing transactions");
            take_free();
            VSLQ_Flush(vslq, event, NULL);
            flush = 0;
            if (status == DISPATCH_FLUSH || status == DISPATCH_EOL)
                continue;
            VSLQ_Delete(&vslq);
            AZ(vslq);
            if (!term && EMPTY(config.varnish_bindump)) {
                /* cf. VUT_Main() in Varnish vut.c */
                LOG_Log0(LOG_NOTICE, "Attempting to reacquire the log");
                while (!term && vslq == NULL) {
                    AN(vsm);
                    VTIM_sleep(0.1);
                    if (VSM_Open(vsm)) {
                        VSM_ResetError(vsm);
                        continue;
                    }
                    cursor = VSL_CursorVSM(vsl, vsm,
                                           VSL_COPT_TAIL | VSL_COPT_BATCH);
                    if (cursor == NULL) {
                        VSL_ResetError(vsl);
                        VSM_Close(vsm);
                        continue;
                    }
                    vslq = VSLQ_New(vsl, &cursor, grouping, q_arg);
                    AZ(cursor);
                }
                if (vslq != NULL) {
                    reacquire++;
                    LOG_Log0(LOG_NOTICE, "Log reacquired");
                }
            }
        }
    }

    if (term && status != DISPATCH_EOF && flush && vslq != NULL) {
        LOG_Log0(LOG_NOTICE, "Flushing transactions");
        take_free();
        while (VSLQ_Flush(vslq, event, NULL) != DISPATCH_RETURN_OK)
            ;
    }

    WRT_Halt();
    WRT_Fini();
    SPSCQ_Shutdown();
    MON_Shutdown();
    FMT_Fini();
    AZ(pthread_cond_destroy(&spscq_ready_cond));
    AZ(pthread_mutex_destroy(&spscq_ready_lock));
    AZ(pthread_cond_destroy(&data_ready_cond));
    AZ(pthread_mutex_destroy(&data_ready_lock));
    if (pfh != NULL) {
        errno = 0;
        if (VPF_Remove(pfh) != 0)
            LOG_Log(LOG_ERR, "Could not remove pid file %s: %s", P_arg,
                    strerror(errno));
    }
    LOG_Log0(LOG_NOTICE, "Exiting");
    LOG_Close();

    exit(EXIT_SUCCESS);
}
