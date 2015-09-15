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

#include "config.h"

#include "varnishevent.h"

#include "vas.h"
#include "vdef.h"

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

static int
conf_getDouble(const char *rval, double *d)
{
    char *p;
    errno = 0;
    double x = strtod(rval, &p);
    if (errno == ERANGE)
        return errno;
    if (p[0] != '\0' || x < 0 || isnan(x) || !finite(x))
        return EINVAL;
    *d = x;
    return 0;
}

/* For char fields with fixed-size buffers */
#define confString(name,fld)                    \
    if (strcmp(lval, (name)) == 0) {            \
        if (strlen(rval) > sizeof(config.fld))  \
            return EINVAL;                      \
        bprintf((config.fld), "%s", rval);      \
        return(0);                              \
    }

#define confVSB(name,fld)                       \
    if (strcmp(lval, (name)) == 0) {            \
        VSB_clear(config.fld);                  \
        VSB_cpy(config.fld, rval);              \
        VSB_finish(config.fld);                 \
        return(0);                              \
    }

/* XXX: need confNonNegative? */

#define confUnsigned(name,fld)                   \
    if (strcmp(lval, name) == 0) {               \
        unsigned int i;                          \
        int err = conf_getUnsignedInt(rval, &i); \
        if (err != 0)                            \
            return err;                          \
        config.fld = i;                          \
        return(0);                               \
    }

#define confDouble(name,fld)                    \
    if (strcmp(lval, name) == 0) {              \
        double d;                               \
        int err = conf_getDouble(rval, &d);     \
        if (err != 0)                           \
            return err;                         \
        config.fld = d;                         \
        return(0);                              \
    }

int
CONF_Add(const char *lval, const char *rval)
{
    int ret;
    
    confString("log.file", log_file);
    confString("output.file", output_file);
    confString("varnish.bindump", varnish_bindump);

    confVSB("cformat", cformat);
    confVSB("bformat", bformat);
    confVSB("rformat", rformat);
    confVSB("syslog.ident", syslog_ident);

    confUnsigned("max.reclen", max_reclen);
    confUnsigned("max.vcl_call", max_vcl_call);
    confUnsigned("chunk_size", chunk_size);
    confUnsigned("max.data", max_data);
    confUnsigned("monitor.interval", monitor_interval);
    confUnsigned("output.bufsiz", output_bufsiz);
    confUnsigned("append", append);

    confDouble("output.timeout", output_timeout);
    confDouble("reader.timeout", reader_timeout);

    if (strcmp(lval, "syslog.facility") == 0) {
        if ((ret = conf_getFacility(rval)) < 0)
            return EINVAL;
        config.syslog_facility = ret;
        bprintf(config.syslog_facility_name, "%s", rval);
        char *p = &config.syslog_facility_name[0];
        do { *p = toupper(*p); } while (*++p);
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
    config.log_file[0] = '\0';
    /* Default is stdout */
    config.output_file[0] = '\0';
    config.varnish_bindump[0] = '\0';
    bprintf(config.syslog_facility_name, "%s", "LOCAL0");

    config.cformat = VSB_new_auto();
    VSB_cpy(config.cformat, DEFAULT_CFORMAT);
    VSB_finish(config.cformat);
    config.bformat = VSB_new_auto();
    VSB_finish(config.bformat);
    config.rformat = VSB_new_auto();
    VSB_finish(config.rformat);
    config.syslog_ident = VSB_new_auto();
    VSB_cpy(config.syslog_ident, "varnishevent");
    VSB_finish(config.syslog_ident);

    config.syslog_facility = LOG_LOCAL0;

    config.monitor_interval = 30;
    config.output_bufsiz = BUFSIZ;

    config.max_reclen = DEFAULT_MAX_RECLEN;
    config.max_vcl_call = DEFAULT_MAX_VCL_CALL;
    config.max_data = DEFAULT_MAX_DATA;
    config.chunk_size = DEFAULT_CHUNK_SIZE;

    config.append = 0;
    config.output_timeout = 0.;
    config.reader_timeout = 0.;
}

static int
conf_get_line(char *line, FILE *in)
{
#ifdef HAVE_GETLINE
    size_t n = BUFSIZ;
    errno = 0;
    return (getline(&line, &n, in));
#else
    if (fgets(line, BUFSIZ, in) == NULL)
        return -1;
    return 0;
#endif
}

int
CONF_ReadFile(const char *file) {
    FILE *in;
    char *line;
    int linenum = 0;
    struct vsb *orig;

    in = fopen(file, "r");
    if (in == NULL) {
        perror(file);
        return(-1);
    }

    line = (char *) malloc(BUFSIZ);
    AN(line);
    orig = VSB_new_auto();
    while (conf_get_line(line, in) != -1) {
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

        VSB_clear(orig);
        VSB_cpy(orig, ptr);
        VSB_finish(orig);

        char *lval, *rval;
        if (conf_ParseLine(ptr, &lval, &rval) != 0) {
            fprintf(stderr, "Cannot parse %s line %d: '%s'\n", file, linenum,
                    VSB_data(orig));
            return(-1);
        }

        int ret;
        if ((ret = CONF_Add((const char *) lval, (const char *) rval)) != 0) {
            fprintf(stderr, "Error in %s line %d (%s): '%s'\n", file, linenum,
                    strerror(ret), VSB_data(orig));
            return(-1);
        }
    }
    int ret = 0;
    if (ferror(in)) {
        fprintf(stderr, "Error reading file %s (errno %d: %s)\n", file, errno,
                strerror(errno));
        ret = -1;
    }
    errno = 0;
    if (fclose(in) != 0) {
        fprintf(stderr, "Error closing file %s: %s)\n", file,  strerror(errno));
        ret = -1;
    }
    free(line);
    return(ret);
}

#define confdump(str,val) \
    LOG_Log(LOG_INFO, "config: " str, (val))

void
CONF_Dump(void)
{
    confdump("log.file = %s",
             strcmp(config.log_file,"-") == 0 ? "stdout" : config.log_file);
    confdump("varnish.bindump = %s", config.varnish_bindump);
    confdump("output.file = %s",
             EMPTY(config.output_file) ? "stdout" : config.output_file);
    confdump("append = %u", config.append);
    confdump("output.timeout = %f", config.output_timeout);
    confdump("reader.timeout = %f", config.reader_timeout);
    confdump("cformat = %s", VSB_data(config.cformat));
    confdump("bformat = %s", VSB_data(config.bformat));
    confdump("rformat = %s", VSB_data(config.rformat));
    confdump("syslog.facility = %s", config.syslog_facility_name);
    confdump("syslog.ident = %s", VSB_data(config.syslog_ident));
    confdump("monitor.interval = %u", config.monitor_interval);
    confdump("max.reclen = %u", config.max_reclen);
    confdump("max.vcl_call = %u", config.max_vcl_call);
    confdump("max.data = %u", config.max_data);
    confdump("chunk.size = %u", config.chunk_size);
    confdump("output.bufsiz = %u", config.output_bufsiz);
}
