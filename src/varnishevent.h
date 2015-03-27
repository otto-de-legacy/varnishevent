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

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>

#include "vapi/vsl.h"
#include "vqueue.h"
#include "vsb.h"

#define C(spec) ((spec) & VSL_S_CLIENT)
#define B(spec) ((spec) & VSL_S_BACKEND)
#define Z(spec) ((spec) == 0)

/* Defaults from Varnish 3.0.3 */
#define DEFAULT_MAX_RECLEN 255	/* shm_reclen */
#define DEFAULT_MAX_HEADERS 64	/* http_max_hdr */

#define DEFAULT_CHUNK_SIZE 64
#define DEFAULT_MAX_FD 1024
#define DEFAULT_MAX_DATA 4096
#define DEFAULT_PID_FILE "/var/run/varnishevent.pid"

#define DEFAULT_HOUSEKEEP_INTERVAL 10
#define DEFAULT_TTL 120

#define MAX_VSL_TAG SLT__MAX

#define DEFAULT_CFORMAT \
    "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\""
#define ALT_CFORMAT \
  "%{X-Forwarded-For}i %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\""

struct sigaction default_action;
    
typedef enum {
    DATA_EMPTY = 0,
    DATA_DONE,
} data_state_e;

typedef enum {
    TX_EMPTY = 0,
    TX_DONE,
} tx_state_e;

typedef struct {
    unsigned magic;
#define RECORD_MAGIC 0xdf4399b1
    char *data;
    unsigned len;
} record_t;

typedef struct {
    record_t *record;
    unsigned nrec;
} hdr_t;

typedef struct chunk_t {
    unsigned magic;
#define CHUNK_MAGIC 0x676e0d19
    data_state_e state;
    char *data;
    VSTAILQ_ENTRY(chunk_t) freelist;
    VSTAILQ_ENTRY(chunk_t) chunklist;
} chunk_t;

typedef VSTAILQ_HEAD(chunkhead_s, chunk_t) chunkhead_t;

chunk_t *chunks;

typedef struct logline_t {
    unsigned magic;
#define LOGLINE_MAGIC 0xf427a374
    enum VSL_tag_e tag;
    data_state_e state;
    chunkhead_t chunks;
    unsigned len;
    VSTAILQ_ENTRY(logline_t) freelist;
    VSTAILQ_ENTRY(logline_t) linelist;
} logline_t;

logline_t *lines;

typedef VSTAILQ_HEAD(linehead_s, logline_t) linehead_t;

typedef struct tx_t {
    unsigned magic;
#define TX_MAGIC 0xff463e42
    tx_state_e state;
    int32_t vxid;
    enum VSL_transaction_e type;
    linehead_t lines;
    VSTAILQ_ENTRY(tx_t) freelist;
    VSTAILQ_ENTRY(tx_t) spscq;
} tx_t;

tx_t *txn;

typedef VSTAILQ_HEAD(txhead_s, tx_t) txhead_t;

unsigned data_open;
unsigned data_done;
unsigned data_occ_hi;

int tag2idx[MAX_VSL_TAG];
enum VSL_tag_e idx2tag[MAX_VSL_TAG];

VSTAILQ_HEAD(freehead_s, logline_t);

unsigned global_nfree_tx, global_nfree_line, global_nfree_chunk;

/* Reader waits for this condition when the freelist is exhausted.
   Writer signals the condition after returning space to the freelist. */
pthread_cond_t  data_ready_cond;
pthread_mutex_t data_ready_lock;

/* Writer (consumer) waits for this condition when the SPSC queue is empty.
   Reader (producer) signals the condition after enqueue. */
pthread_cond_t  spscq_ready_cond;
pthread_mutex_t spscq_ready_lock;

struct config {
    char        pid_file[BUFSIZ];
    
    /* VSL 'n' argument */
    char        varnish_name[BUFSIZ];
    
    char        log_file[BUFSIZ];

    char	output_file[PATH_MAX];
    unsigned	append;
    struct timeval output_timeout;
    
    /* VSL 'r' argument */
    char        varnish_bindump[BUFSIZ];

    /* zformat is for fd 0 (neither 'c' nor 'b') */
    /* XXX: better if these weren't limited to fixed buffer sizes, but the
     * length of a configurable string is limited by the length of lines
     * read by CONF_ReadFile(), currently BUFSIZ
     */
    char	cformat[BUFSIZ];
    char	bformat[BUFSIZ];
    char	zformat[BUFSIZ];
    
    int         syslog_facility;
    char        syslog_facility_name[BUFSIZ];
    char	syslog_ident[BUFSIZ];
    unsigned    monitor_interval;
    
    /* varnishd param shm_reclen */
    unsigned	max_reclen;

    unsigned	chunk_size;

    /* varnishd param http_max_hdr */
    unsigned	max_headers;

    unsigned	max_vcl_log;
    unsigned	max_vcl_call;

    unsigned	max_fd;
    unsigned	max_data;    

    unsigned	housekeep_interval;
    unsigned	ttl;
    
    size_t	output_bufsiz;
    
    char        user_name[BUFSIZ];
    uid_t       uid;
    gid_t       gid;
} config;

/* varnishevent.c */
int RDR_Waiting(void);
void RDR_Stats(void);

/* config.c */
void CONF_Init(void);
int CONF_Add(const char *lval, const char *rval);
int CONF_ReadFile(const char *file);
void CONF_Dump(void);

/* log.c */
#define EMPTY(s) (s[0] == '\0')

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
void DATA_Clear_Logline(tx_t *tx);
unsigned DATA_Take_Freetx(struct txhead_s *dst);
unsigned DATA_Take_Freeline(struct linehead_s *dst);
unsigned DATA_Take_Freechunk(struct chunkhead_s *dst);
void DATA_Return_Freelist(struct txhead_s *returned, unsigned nreturned);
void DATA_Dump(void);

/* writer.c */
int WRT_Init(void);
void WRT_Start(void);
void WRT_Stats(void);
int WRT_Running(void);
int WRT_Waiting(void);
void WRT_Reopen(void);
void WRT_Halt(void);
void WRT_Shutdown(void);

/* spscq.c */
void SPSCQ_Enq(tx_t *ptr);
tx_t *SPSCQ_Deq(void);
unsigned SPSCQ_Len(void);
void SPSCQ_Stats(void);
void SPSCQ_Shutdown(void);

/* monitor.c */
typedef enum {
    /* "Ending" VSL tag seen */
    STATS_DONE,
    /* Log line written */
    STATS_WRITTEN,
} stats_update_t;

void MON_Start(void);
void MON_Shutdown(void);
void MON_StatsUpdate(stats_update_t update);
void MON_Output(void);

#if 0
/* format.c */
int FMT_Init(char *err);
char *FMT_Get_i_Arg(void);
int FMT_Get_nTags(void);
int FMT_Read_Hdr(enum VSL_tag_e tag);
void FMT_Format(logline_t *ll, struct vsb *os);
void FMT_Shutdown(void);

/* handler.c */
void HNDL_Init(const char *a0);
void HNDL_Abort(int sig);
#endif
