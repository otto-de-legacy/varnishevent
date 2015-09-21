/*-
 * Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung
 * Copyright (c) 2015 Otto Gmbh & Co KG
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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hdrtrie.h"

#include "vas.h"
#include "miniobj.h"

static inline int
hdr_next(const char c)
{
    int n = toupper(c) - 32;
    if (c == '~')
        n = ':' - 32;
    return n;
}

int
HDR_FindIdx(struct hdrt_node *hdrt, const char *hdr)
{
    const char *h = hdr;
    char *s;
    int n;

    if (hdrt == NULL)
        return -1;
    while (*h && isspace(*h))
        h++;
    if (*h == '\0')
        return -1;
    while (1) {
        CHECK_OBJ(hdrt, HDRT_NODE_MAGIC);
        s = hdrt->str;
        while (*h && *s && (toupper(*h) == toupper(*s))) {
            h++;
            s++;
        }
        if (*s != '\0')
            return -1;
        n = hdr_next(*h);
        if (n < 0 || n >= 64)
            return -1;
        if (hdrt->next[n] == NULL)
            break;
        hdrt = hdrt->next[n];
        h++;
    }
    while (*h && isspace(*h))
        h++;
    if (*h != ':' || *h == '\0')
        return -1;
    return hdrt->idx;
}

struct hdrt_node *
HDR_InsertIdx(struct hdrt_node *hdrt, const char *hdr, int idx)
{
    const char *h = hdr;
    char *s;
    int n;

    if (hdrt == NULL) {
        ALLOC_OBJ(hdrt, HDRT_NODE_MAGIC);
        AN(hdrt);
        hdrt->str = strdup(hdr);
        hdrt->idx = idx;
        return hdrt;
    }

    CHECK_OBJ(hdrt, HDRT_NODE_MAGIC);
    s = hdrt->str;
    while (*h && *s && (toupper(*h) == toupper(*s))) {
        h++;
        s++;
    }
    if (*s == '\0' && *h == '\0')
        assert(hdrt->idx == idx);
    else if (*s == '\0') {
        n = hdr_next(*h);
        assert(n >= 0 && n < 64);
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++h, idx);
    }
    else if (*h == '\0') {
        n = hdr_next(*s);
        assert(n >= 0 && n < 64);
        *s = '\0';
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++s, hdrt->idx);
        hdrt->idx = idx;
    }
    else {
        n = hdr_next(*s);
        assert(n >= 0 && n < 64);
        *s = '\0';
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++s, hdrt->idx);
        n = hdr_next(*h);
        assert(n >= 0 && n < 64);
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++h, idx);
        hdrt->idx = -1;
    }
    
    return hdrt;
}

void
HDR_Fini(struct hdrt_node *hdrt)
{
    if (hdrt == NULL)
        return;

    free(hdrt->str);
    for (int i = 0; i < 64; i++)
        HDR_Fini(hdrt->next[i]);
    FREE_OBJ(hdrt);
}
