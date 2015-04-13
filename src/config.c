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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>

#include "varnishevent.h"

#include "vas.h"

#define DEFAULT_USER "nobody"

static const int facilitynum[8] =
    { LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5,
      LOG_LOCAL6, LOG_LOCAL7 };

static int
conf_getFacility(const char *facility) {
    int localnum;
    
    if (strcasecmp(facility, "USER") == 0)
        return LOG_USER;
    if (strlen(facility) != 6
        || strncasecmp(facility, "LOCAL", 5) != 0
        || !isdigit(facility[5]))
        return(-1);
    localnum = atoi(&facility[5]);
    if (localnum > 7)
        return(-1);
    return(facilitynum[localnum]);
}

static int
conf_getUnsignedInt(const char *rval, unsigned *i)
{
    long n;
    char *p;

    errno = 0;
    n = strtoul(rval, &p, 10);
    if (errno)
        return(errno);
    if (strlen(p) != 0)
        return(EINVAL);
    if (n < 0 || n > UINT_MAX)
        return(ERANGE);
    *i = (unsigned int) n;
    return(0);
}

#define confString(name,fld)         \
    if (strcmp(lval, (name)) == 0) { \
        strcpy((config.fld), rval);  \
        return(0);                   \
    }

/* XXX: need confNonNegative for chunk.size */

#define confUnsigned(name,fld)                   \
    if (strcmp(lval, name) == 0) {               \
        unsigned int i;                          \
        int err = conf_getUnsignedInt(rval, &i); \
        if (err != 0)                            \
            return err;                          \
        config.fld = i;                          \
        return(0);                               \
    }

int
CONF_Add(const char *lval, const char *rval)
{
    int ret;
    
    confString("pid.file", pid_file);
    confString("varnish.name", varnish_name);
    confString("log.file", log_file);
    confString("varnish.bindump", varnish_bindump);
    confString("cformat", cformat);
    confString("bformat", bformat);
    confString("rformat", rformat);
    confString("output.file", output_file);
    confString("syslog.ident", syslog_ident);
    
    confUnsigned("max.reclen", max_reclen);
    confUnsigned("max.headers", max_headers);
    confUnsigned("max.vcl_log", max_vcl_log);
    confUnsigned("max.vcl_call", max_vcl_call);
    confUnsigned("max.timestamp", max_vcl_call);
    confUnsigned("max.fd", max_fd);
    confUnsigned("max.data", max_data);
    confUnsigned("monitor.interval", monitor_interval);
    confUnsigned("output.bufsiz", output_bufsiz);
    confUnsigned("housekeep.interval", housekeep_interval);
    confUnsigned("ttl", ttl);
    confUnsigned("append", append);

    if (strcmp(lval, "syslog.facility") == 0) {
        if ((ret = conf_getFacility(rval)) < 0)
            return EINVAL;
        config.syslog_facility = ret;
        strcpy(config.syslog_facility_name, rval);
        char *p = &config.syslog_facility_name[0];
        do { *p = toupper(*p); } while (*++p);
        return(0);
    }

    if (strcmp(lval, "user") == 0) {
        struct passwd *pw;
        
        pw = getpwnam(rval);
        if (pw == NULL)
            return(EINVAL);
        strcpy(config.user_name, pw->pw_name);
        config.uid = pw->pw_uid;
        config.gid = pw->pw_gid;
        return(0);
    }

    if (strcmp(lval, "output.timeout") == 0) {
        char *p;
        errno = 0;
        double to = strtod(rval, &p);
        if (errno == ERANGE)
            return errno;
        if (p[0] != '\0' || to < 0 || isnan(to) || !finite(to))
            return EINVAL;
        config.output_timeout.tv_sec = trunc(to);
        config.output_timeout.tv_usec = (int)(1e6 * (to - trunc(to)));
        return(0);
    }

    return EINVAL;
}

static int
conf_ParseLine(char *ptr, char **lval, char **rval)
{
    char *endlval;
    
    *lval = ptr;
    while(*++ptr && !isspace(*ptr) && *ptr != '=')
        ;
    if (*ptr == '\0')
        return(1);
    endlval = ptr;
    while(isspace(*ptr) && *++ptr)
        ;
    if (ptr == '\0' || *ptr != '=')
        return(1);
    while(*++ptr && isspace(*ptr))
        ;
    if (ptr == '\0')
        return(1);
    *endlval = '\0';
    *rval = ptr;
    return(0);
}

void
CONF_Init(void)
{
    struct passwd *pw;

    strcpy(config.pid_file, DEFAULT_PID_FILE);
    strcpy(config.cformat, DEFAULT_CFORMAT);
    strcpy(config.syslog_ident, "varnishevent");
    config.bformat[0] = '\0';
    config.rformat[0] = '\0';
    config.varnish_name[0] = '\0';
    config.log_file[0] = '\0';
    config.varnish_bindump[0] = '\0';
    config.syslog_facility = LOG_LOCAL0;
    strcpy(config.syslog_facility_name, "LOCAL0");
    config.monitor_interval = 30;
    config.output_bufsiz = BUFSIZ;

    config.max_reclen = DEFAULT_MAX_RECLEN;
    config.max_headers = DEFAULT_MAX_HEADERS;
    config.max_vcl_log = DEFAULT_MAX_VCL_LOG;
    config.max_vcl_call = DEFAULT_MAX_VCL_CALL;
    config.max_timestamp = DEFAULT_MAX_TIMESTAMP;
    config.max_fd = DEFAULT_MAX_FD;
    config.max_data = DEFAULT_MAX_DATA;
    config.chunk_size = DEFAULT_CHUNK_SIZE;
    config.housekeep_interval = DEFAULT_HOUSEKEEP_INTERVAL;
    config.ttl = DEFAULT_TTL;

    /* Default is stdout */
    config.output_file[0] = '\0';
    config.append = 0;
    config.output_timeout.tv_sec = 0;
    config.output_timeout.tv_usec = 0;
    
    pw = getpwnam(DEFAULT_USER);
    if (pw == NULL)
        pw = getpwuid(getuid());
    AN(pw);
    strcpy(config.user_name, pw->pw_name);
    config.uid = pw->pw_uid;
    config.gid = pw->pw_gid;
}

int
CONF_ReadFile(const char *file) {
    FILE *in;
    char line[BUFSIZ];
    int linenum = 0;

    in = fopen(file, "r");
    if (in == NULL) {
        perror(file);
        return(-1);
    }
    
    while (fgets(line, BUFSIZ, in) != NULL) {
        char orig[BUFSIZ];
        
        linenum++;
        char *comment = strchr(line, '#');
        if (comment != NULL)
            *comment = '\0';
        if (strlen(line) == 0)
            continue;
    
        char *ptr = line + strlen(line) - 1;
        while (ptr != line && isspace(*ptr))
            --ptr;
        ptr[isspace(*ptr) ? 0 : 1] = '\0';
        if (strlen(line) == 0)
            continue;

        ptr = line;
        while (isspace(*ptr) && *++ptr)
            ;
        strcpy(orig, ptr);
        char *lval, *rval;
        if (conf_ParseLine(ptr, &lval, &rval) != 0) {
            fprintf(stderr, "Cannot parse %s line %d: '%s'\n", file, linenum,
                    orig);
            return(-1);
        }

        int ret;
        if ((ret = CONF_Add((const char *) lval, (const char *) rval)) != 0) {
            fprintf(stderr, "Error in %s line %d (%s): '%s'\n", file, linenum,
                strerror(ret), orig);
            return(-1);
        }
    }
    fclose(in);
    return(0);
}

#define confdump(str,val) \
    LOG_Log(LOG_INFO, "config: " str, (val))

void
CONF_Dump(void)
{
    confdump("pid.file = %s", config.pid_file);
    confdump("varnish.name = %s", config.varnish_name);
    confdump("log.file = %s",
        strcmp(config.log_file,"-") == 0 ? "stdout" : config.log_file);
    confdump("varnish.bindump = %s", config.varnish_bindump);
    confdump("output.file = %s",
        EMPTY(config.output_file) ? "stdout" : config.output_file);
    confdump("append = %u", config.append);
    confdump("output.timeout = %f",
        config.output_timeout.tv_sec
        + (double) config.output_timeout.tv_usec / 1e-6);
    confdump("cformat = %s", config.cformat);
    confdump("bformat = %s", config.bformat);
    confdump("rformat = %s", config.rformat);
    confdump("syslog.facility = %s", config.syslog_facility_name);
    confdump("syslog.ident = %s", config.syslog_ident);
    confdump("monitor.interval = %u", config.monitor_interval);
    confdump("max.reclen = %u", config.max_reclen);
    confdump("max.headers = %u", config.max_headers);
    confdump("max.vcl_log = %u", config.max_vcl_log);
    confdump("max.vcl_call = %u", config.max_vcl_call);
    confdump("max.timestamp = %u", config.max_timestamp);
    confdump("max.fd = %u", config.max_fd);
    confdump("max.data = %u", config.max_data);
    confdump("housekeep.interval = %u", config.housekeep_interval);
    confdump("ttl = %u", config.ttl);
    confdump("output.bufsiz = %u", config.output_bufsiz);
    confdump("user = %s", config.user_name);
}
