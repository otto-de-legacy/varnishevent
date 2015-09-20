/*-
 * Copyright (c) 2013-2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2013-2015 Otto Gmbh & Co KG
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

#include <time.h>
#include <sys/types.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>

#include "strfTIM.h"

#include "vas.h"

/*
 * cf. vtim.c/VTIM:timespec in libvarnish
 */
static struct timeval
double2timeval(double t)
{
    struct timeval tv;

    tv.tv_sec = (time_t)trunc(t);
    tv.tv_usec = (int)(1e6 * (t - tv.tv_sec));
    return (tv);
}

size_t
strfTIM(char *s, size_t max, const char *fmt, struct tm *tm, unsigned usec)
{
        const char *p;
        char newfmt[max], *f = newfmt;
        size_t n, len = 0;

        assert(usec < 1000000);
        for (p = fmt; *p; p++) {
                if (*p != '%') {
                        len++;
                        if (len > max)
                            return 0;
                        *f++ = *p;
                        continue;
                }
                p++;
                if (*p != 'i') {
                        len += 2;
                        if (len > max)
                            return 0;
                        *f++ = '%';
                        *f++ = *p;
                        continue;
                }
                len += 6;
                if (len > max)
                    return 0;
                sprintf(f, "%06u", usec);
                f += 6;
        }
        if (len + 1 > max)
            return 0;
        *f = '\0';

        n = strftime(s, max, newfmt, tm);
        return n;
}

#define strfTIM_tz(tz)                                          \
size_t                                                          \
strfTIM##tz(char *s, size_t max, const char *fmt, double t)     \
{                                                               \
        struct timeval tim = double2timeval(t);                 \
        struct tm tm;                                           \
                                                                \
        AN(tz##time_r((time_t *) &tim.tv_sec, &tm));            \
        return(strfTIM(s, max, fmt, &tm, tim.tv_usec));         \
}

strfTIM_tz(local)
strfTIM_tz(gm)
