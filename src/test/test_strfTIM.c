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
static char errmsg[BUFSIZ];

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

    sprintf(errmsg, "strfTIM incorrect return value %zu (expected %zu)",
        strfTIM_n, strftime_n);
    mu_assert(errmsg, strfTIM_n == strftime_n);

    sprintf(errmsg, "strfTIM incorrect result '%s' (expected '%s')", strfTIM_s,
        strftime_s);
    mu_assert(errmsg, strcmp(strfTIM_s, strftime_s) == 0);

    return NULL;
}

static char
*test_strfTIM_N(void)
{
    size_t n;
    time_t t = 1382804827;
    long nsec = 112625579;
    const char *exp = "2013-10-26-18:27:07.112625579";
    char s[BUFSIZ];
    struct tm *tm;

    printf("... testing strfTIM %%N conversion specifier\n");

    tm = localtime(&t);
    assert(tm != NULL);
    
    n = strfTIM(s, BUFSIZ, "%F-%T.%N", tm, nsec);
    sprintf(errmsg, "strfTIM incorrect return value %zu (expected %zu)", n,
        strlen(exp));
    mu_assert(errmsg, n == strlen(exp));

    sprintf(errmsg, "strfTIM incorrect result '%s' (expected '%s')", s, exp);
    mu_assert(errmsg, strcmp(s, exp) == 0);

    n = strfTIM(s, BUFSIZ, "%%N", tm, nsec);
    sprintf(errmsg, "strfTIM incorrect return value %zu (expected %zu)", n,
        strlen("%N"));
    mu_assert(errmsg, n == strlen("%N"));

    sprintf(errmsg, "strfTIM incorrect result '%s' (expected '%s')", s, "%N");
    mu_assert(errmsg, strcmp(s, "%N") == 0);

    n = strfTIM(s, BUFSIZ, "%%%N", tm, nsec);
    sprintf(errmsg, "strfTIM incorrect return value %zu (expected %zu)", n,
        strlen("%112625579"));
    mu_assert(errmsg, n == strlen("%112625579"));

    sprintf(errmsg, "strfTIM incorrect result '%s' (expected '%s')", s,
        "%112625579");
    mu_assert(errmsg, strcmp(s, "%112625579") == 0);

    return NULL;
}

static char
*test_strfTIMlocal(void)
{
    size_t n;
    char s[BUFSIZ], exp[BUFSIZ];

    printf("... testing strfTIMlocal\n");

    n = strfTIMlocal(s, BUFSIZ, "%F-%T.%N", 1382804820.112625579);
    sprintf(exp, "2013-10-26-18:27:0%.9f", 0.112625579);
    sprintf(errmsg, "strfTIMlocal incorrect return value %zu (expected %zu)",
        n, strlen(exp));
    mu_assert(errmsg, n == strlen(exp));

    /*
     * Don't require equality into the nanosecond range, because that gets
     * us into floating point precision issues. Just require equality in
     * the µsec range, by terminating the result string after six decimal
     * places.
     */
    s[strlen(s) - 3] = '\0';
    exp[strlen(exp) - 3] = '\0';
    sprintf(errmsg, "strfTIMlocal incorrect result '%s' (expected '%s')", s,
        exp);
    mu_assert(errmsg, strcmp(s, exp) == 0);

    return NULL;
}

static char
*test_strfTIMgm(void)
{
    size_t n;
    char s[BUFSIZ], exp[BUFSIZ];

    printf("... testing strfTIMgm\n");

    n = strfTIMgm(s, BUFSIZ, "%F-%T.%N", 1382804820.112625579);
    sprintf(exp, "2013-10-26-16:27:0%.9f", 0.112625579);
    sprintf(errmsg, "strfTIMgm incorrect return value %zu (expected %zu)",
        n, strlen(exp));
    mu_assert(errmsg, n == strlen(exp));

    /* As above */
    s[strlen(s) - 3] = '\0';
    exp[strlen(exp) - 3] = '\0';
    sprintf(errmsg, "strfTIMgm incorrect result '%s' (expected '%s')", s, exp);
    mu_assert(errmsg, strcmp(s, exp) == 0);

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
