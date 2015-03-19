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

#include <time.h>

#include "strfTIM.h"

#include "vsb.h"
#include "libvarnish.h"

size_t
strfTIM(char *s, size_t max, const char *fmt, struct tm *tm, long nsec)
{
        struct vsb *vsb = VSB_new(NULL, NULL, max, VSB_FIXEDLEN);
        const char *p;
        size_t n;

        for (p = fmt; *p; p++) {
                if (*p != '%') {
                        VSB_putc(vsb, *p);
                        continue;
                }
                p++;
                if (*p == '%') {
                        VSB_cat(vsb, "%%");
                        continue;
                }
                if (*p != 'N') {
                        VSB_putc(vsb, '%');
                        VSB_putc(vsb, *p);
                        continue;
                }

                VSB_printf(vsb, "%09ld", nsec);
        }
        VSB_finish(vsb);

        if (VSB_error(vsb)) {
                VSB_delete(vsb);
                return 0;
        }

        n = strftime(s, max, VSB_data(vsb), tm);
        VSB_delete(vsb);
        return n;
}

#define strfTIM_tz(tz)                                          \
size_t                                                          \
strfTIM##tz(char *s, size_t max, const char *fmt, double t)     \
{                                                               \
        struct timespec tim = TIM_timespec(t);                  \
        struct tm tm;                                           \
                                                                \
        AN(tz##time_r((time_t *) &tim.tv_sec, &tm));            \
        return(strfTIM(s, max, fmt, &tm, tim.tv_nsec));         \
}

strfTIM_tz(local)
strfTIM_tz(gm)
