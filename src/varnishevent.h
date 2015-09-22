/*-
 * Copyright (c) 2013-2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013-2015 Otto Gmbh & Co KG
 * All rights reserved.
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

#ifndef VARNISHEVENT_H_INCLUDED
#define VARNISHEVENT_H_INCLUDED

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>

#include "hdrtrie.h"

#include "vapi/vsl.h"
#include "vqueue.h"
#include "vsb.h"

#define C(txtype) ((txtype) == VSL_t_req)
#define B(txtype) ((txtype) == VSL_t_bereq)
#define R(txtype) ((txtype) == VSL_t_raw)

#define EMPTY(s) (s[0] == '\0')
#define VSB_EMPTY(vsb) (VSB_len((vsb)) == 0)

/* Defaults from Varnish 4.0.3 */
#define DEFAULT_MAX_RECLEN 255	/* shm_reclen */
#define DEFAULT_MAX_HEADERS 64	/* http_max_hdr */

#define DEFAULT_MAX_VCL_CALL 10

#define DEFAULT_CHUNK_SIZE 64
#define DEFAULT_MAX_DATA 4096
#define DEFAULT_PID_FILE "/var/run/varnishevent.pid"

#define MAX_VSL_TAG SLT__MAX

#define DEFAULT_CFORMAT \
    "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\""

struct sigaction default_action;

int tag2idx[MAX_VSL_TAG];
int max_idx;

typedef struct chunk_t {
    unsigned magic;
#define CHUNK_MAGIC 0x676e0d19
    unsigned occupied;
    char *data;
    VSTAILQ_ENTRY(chunk_t) freelist;
    VSTAILQ_ENTRY(chunk_t) chunklist;
} chunk_t;

typedef VSTAILQ_HEAD(chunkhead_s, chunk_t) chunkhead_t;

chunk_t *chunks;
unsigned nchunks;                                          

typedef struct rec_t {
    unsigned magic;
#define RECORD_MAGIC 0xf427a374
    unsigned len;
    unsigned occupied;
    enum VSL_tag_e tag;
    chunkhead_t chunks;
    VSTAILQ_ENTRY(rec_t) freelist;
} rec_t;

rec_t *records;
unsigned nrecords;

typedef VSTAILQ_HEAD(rechead_s, rec_t) rechead_t;

typedef struct rec_node_t {
    unsigned magic;
#define REC_NODE_MAGIC 0x92d4933d
    rec_t *rec;
    rec_t **hdrs;
} rec_node_t;

rec_node_t *rec_nodes;

enum tx_state_e {
    TX_FREE,
    TX_OPEN,
    TX_DONE,
    TX_SUBMITTED,
    TX_FORMATTING,
    TX_WRITTEN
};

enum tx_disp_e {
    DISP_NONE = 0,
    DISP_HIT,
    DISP_MISS,
    DISP_PASS,
    DISP_PIPE,
    DISP_ERROR
};

typedef struct tx_t {
    unsigned magic;
#define TX_MAGIC 0xff463e42
    int32_t vxid;
    int32_t pvxid;
    enum VSL_transaction_e type;
    enum tx_state_e state;
    enum tx_disp_e disp;
    double t;
    rec_node_t **recs;
    VSTAILQ_ENTRY(tx_t) freelist;
    VSTAILQ_ENTRY(tx_t) spscq;
} tx_t;

tx_t *txn;

typedef VSTAILQ_HEAD(txhead_s, tx_t) txhead_t;

#define OCCUPIED(p) ((p)->occupied == 1)

unsigned tx_occ, rec_occ, chunk_occ, tx_occ_hi, rec_occ_hi, chunk_occ_hi,
    global_nfree_tx, global_nfree_rec, global_nfree_chunk;

struct hdrt_node *hdr_trie[MAX_VSL_TAG];

/* Writer (consumer) waits for this condition when the SPSC queue is empty.
   Reader (producer) signals the condition after enqueue. */
pthread_cond_t  spscq_ready_cond;
pthread_mutex_t spscq_ready_lock;

/* Reader waits for this condition if any of the freelists are exhausted.
   Writer signals the condition when it returns freelists. */
pthread_cond_t  data_ready_cond;
pthread_mutex_t data_ready_lock;

struct config {
    char	log_file[PATH_MAX + 1];

    char	output_file[PATH_MAX + 1];
    unsigned	append;
    double	output_timeout;
    double	reader_timeout;

    /* VSL 'r' argument */
    char	varnish_bindump[PATH_MAX + 1];

    /* rformat is for raw transactions */
    struct vsb	*cformat;
    struct vsb	*bformat;
    struct vsb	*rformat;

    int         syslog_facility;
    char	syslog_facility_name[sizeof("LOCAL0")];
    struct vsb	*syslog_ident;
    unsigned    monitor_interval;
    
    /* varnishd param shm_reclen */
    unsigned	max_reclen;

    unsigned	chunk_size;

    unsigned	max_vcl_call;

    unsigned	max_data;    

    size_t	output_bufsiz;
} config;

/* varnishevent.c */
void RDR_Stats(void);
int RDR_Depleted(void);
int RDR_Waiting(void);

/* config.c */
void CONF_Init(void);
int CONF_Add(const char *lval, const char *rval);
int CONF_ReadFile(const char *file);
void CONF_Dump(void);

/* log.c */

typedef void log_log_t(int level, const char *msg, ...);
typedef void log_setlevel_t(int level);
typedef void log_close_t(void);

struct logconf {
    log_log_t           *log;
    log_setlevel_t      *setlevel;
    log_close_t         *close;
    FILE                *out;
    int                 level;
} logconf;

int LOG_Open(const char *progname);
/* XXX: __VA_ARGS__ can't be empty ... */
#define LOG_Log0(level, msg) logconf.log(level, msg)
#define LOG_Log(level, msg, ...) logconf.log(level, msg, __VA_ARGS__)
#define LOG_SetLevel(level) logconf.setlevel(level)
#define LOG_Close() logconf.close()

/* data.c */
int DATA_Init(void);
void DATA_Clear_Tx(tx_t * const tx, txhead_t * const freetx,
                   rechead_t * const freerec, chunkhead_t * const freechunk,
                   unsigned * restrict const nfree_tx,
                   unsigned * restrict const nfree_rec,
                   unsigned * restrict const nfree_chunk);
unsigned DATA_Take_Freetx(struct txhead_s *dst);
unsigned DATA_Take_Freerec(struct rechead_s *dst);
unsigned DATA_Take_Freechunk(struct chunkhead_s *dst);
void DATA_Return_Freetx(struct txhead_s *returned, unsigned nreturned);
void DATA_Return_Freerec(struct rechead_s *returned, unsigned nreturned);
void DATA_Return_Freechunk(struct chunkhead_s *returned, unsigned nreturned);
void DATA_Dump(void);

/* writer.c */
int WRT_Init(void);
void WRT_Start(void);
void WRT_Stats(void);
int WRT_Running(void);
int WRT_Waiting(void);
void WRT_Reopen(void);
void WRT_Halt(void);
void WRT_Fini(void);

/* spscq.c */
void SPSCQ_Enq(tx_t *ptr);
tx_t *SPSCQ_Deq(void);
unsigned SPSCQ_Len(void);
void SPSCQ_Stats(void);
void SPSCQ_Shutdown(void);

/* monitor.c */
typedef enum {
    /* Transaction read */
    STATS_DONE,
    /* Transaction written */
    STATS_WRITTEN,
} stats_update_t;

void MON_Start(void);
void MON_Shutdown(void);
void MON_StatsUpdate(stats_update_t update, unsigned nrec, unsigned nchunk);
void MON_Output(void);

/* format.c */
int FMT_Init(char *err);
int FMT_GetMaxIdx(void);
int FMT_Estimate_RecsPerTx(void);
char *FMT_Format(tx_t *tx);
void FMT_Fini(void);

/* handler.c */
void HNDL_Init(const char *a0);
void HNDL_Abort(int sig);

#endif
