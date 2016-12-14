/*-
 * Copyright (c) 2012 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2012 Otto Gmbh & Co KG
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
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "minunit.h"

#include "../strfTIM.h"

int tests_run = 0;

static char
*test_strfTIM_strftime(void)
{
    time_t now;
    struct tm *tm;
    char strftime_s[BUFSIZ], strfTIM_s[BUFSIZ];
    const char *fmt =
        "%a %A %b %B %c %C %d %D %e %F %g %G %h %H %I %J %m %M %n %p %r %R %S "\
        "%t %T %u %U %V %w %W %x %X %y %Y %z %Z %% %Ec %EC %Ex %EX %Ey %Ey "\
        "%Od %Oe %OH %OI %Om %OM %OS %Ou %OU %OV %Ow %OW %Oy";
    size_t strftime_n, strfTIM_n;

    printf("... testing strfTIM equivalence to strftime\n");

    time(&now);
    tm = localtime(&now);
    assert(tm != NULL);
    
    strftime_n = strftime(strftime_s, BUFSIZ, fmt, tm);
    strfTIM_n = strfTIM(strfTIM_s, BUFSIZ, fmt, tm, 0);

    VMASSERT(strfTIM_n == strftime_n, "strfTIM return value %zu (expected %zu)",
             strfTIM_n, strftime_n);

    VMASSERT(strcmp(strfTIM_s, strftime_s) == 0,
             "strfTIM result '%s' (expected '%s')", strfTIM_s, strftime_s);

    return NULL;
}

static char
*test_strfTIM_N(void)
{
    size_t n;
    time_t t = 1382804827;
    long usec = 112625;
    const char *exp = "2013-10-26-16:27:07.112625";
    char s[BUFSIZ];
    struct tm *tm;

    printf("... testing strfTIM %%i conversion specifier\n");

    tm = gmtime(&t);
    MAN(tm);
    
    n = strfTIM(s, BUFSIZ, "%F-%T.%i", tm, usec);
    VMASSERT(n == strlen(exp), "strfTIM return value %zu (expected %zu)", n,
             strlen(exp));

    VMASSERT(strcmp(s, exp) == 0, "strfTIM result '%s' (expected '%s')", s,
             exp);

    n = strfTIM(s, BUFSIZ, "%%i", tm, usec);
    VMASSERT(n == strlen("%i"), "strfTIM return value %zu (expected %zu)", n,
             strlen("%i"));

    VMASSERT(strcmp(s, "%i") == 0, "strfTIM result '%s' (expected '%s')", s,
             "%i");

    n = strfTIM(s, BUFSIZ, "%%%i", tm, usec);
    VMASSERT(n == strlen("%112625"), "strfTIM return value %zu (expected %zu)",
             n, strlen("%112625"));

    VMASSERT(strcmp(s, "%112625") == 0, "strfTIM result '%s' (expected '%s')",
             s, "%112625");

    return NULL;
}

static char
*test_strfTIMlocal(void)
{
    size_t n;
    time_t t = 1382804820;
    struct tm *tm;
    char s[BUFSIZ], exp[BUFSIZ];

    printf("... testing strfTIMlocal\n");

    n = strfTIMlocal(s, BUFSIZ, "%F-%T.%i", 1382804820.112625);
    tm = localtime(&t);
    MAN(tm);
    strftime(exp, BUFSIZ, "%F-%T.112625", tm);
    VMASSERT(n == strlen(exp), "strfTIMlocal return value %zu (expected %zu)",
             n, strlen(exp));

    /* Not accurate at the last decimal place, due to floating point
     * precision */
    s[n - 1] = exp[n - 1] = '\0';
    VMASSERT(strcmp(s, exp) == 0, "strfTIMlocal result '%s' (expected '%s')",
             s, exp);

    return NULL;
}

static char
*test_strfTIMgm(void)
{
    size_t n;
    char s[BUFSIZ], exp[BUFSIZ];

    printf("... testing strfTIMgm\n");

    n = strfTIMgm(s, BUFSIZ, "%F-%T.%i", 1382804820.112625);
    sprintf(exp, "2013-10-26-16:27:0%.6f", 0.112625);
    VMASSERT(n == strlen(exp), "strfTIMgm return value %zu (expected %zu)",
             n, strlen(exp));

    /* As above */
    s[n - 1] = exp[n - 1] = '\0';
    VMASSERT(strcmp(s, exp) == 0, "strfTIMgm result '%s' (expected '%s')",
             s, exp);

    return NULL;
}

static const char
*all_tests(void)
{
    mu_run_test(test_strfTIM_strftime);
    mu_run_test(test_strfTIM_N);
    mu_run_test(test_strfTIMlocal);
    mu_run_test(test_strfTIMgm);
    return NULL;
}

TEST_RUNNER
