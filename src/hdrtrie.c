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
        CHECK_OBJ_NOTNULL(hdrt->next[n], HDRT_NODE_MAGIC);
    }
    else if (*h == '\0') {
        n = hdr_next(*s);
        assert(n >= 0 && n < 64);
        *s = '\0';
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++s, hdrt->idx);
        CHECK_OBJ_NOTNULL(hdrt->next[n], HDRT_NODE_MAGIC);
        hdrt->idx = idx;
    }
    else {
        /* XXX: this memcpy/memset stuff is ugly, better allocate the next
           table on the heap and just move pointers, which is also
           probably more cache-friendly. */
        struct hdrt_node *s_next[64];

        n = hdr_next(*s);
        assert(n >= 0 && n < 64);
        *s = '\0';
        memcpy(s_next, hdrt->next, 64 * sizeof(struct hdrt_next *));
        memset(hdrt->next, 0, 64 * sizeof(struct hdrt_next *));
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++s, hdrt->idx);
        CHECK_OBJ_NOTNULL(hdrt->next[n], HDRT_NODE_MAGIC);
        memcpy(hdrt->next[n]->next, s_next, 64 * sizeof(struct hdrt_next *));
        n = hdr_next(*h);
        assert(n >= 0 && n < 64);
        AZ(hdrt->next[n]);
        hdrt->next[n] = HDR_InsertIdx(hdrt->next[n], ++h, idx);
        CHECK_OBJ_NOTNULL(hdrt->next[n], HDRT_NODE_MAGIC);
        hdrt->idx = -1;
    }
    
    return hdrt;
}

int
HDR_N(struct hdrt_node *hdrt)
{
    int n = 0;

    if (hdrt == NULL)
        return 0;
    CHECK_OBJ(hdrt, HDRT_NODE_MAGIC);
    if (hdrt->idx >= 0)
        n++;
    for (int i = 0; i < 64; i++)
        if (hdrt->next[i] != NULL)
            n += HDR_N(hdrt->next[i]);
    return n;
}

static struct vsb *
vsb_dup(struct vsb *vsb)
{
    struct vsb *dup = VSB_new_auto();
    char *str;

    VSB_finish(vsb);
    str = strdup(VSB_data(vsb));
    VSB_cpy(dup, str);
    VSB_clear(vsb);
    VSB_cpy(vsb, str);
    free(str);
    return dup;
}

static void
hdr_traverse(struct hdrt_node *hdrt, struct vsb *sb, struct vsb *prefix)
{
    struct vsb *current;

    if (hdrt == NULL)
        return;
    CHECK_OBJ(hdrt, HDRT_NODE_MAGIC);
    AN(hdrt->str);
    current = vsb_dup(prefix);
    VSB_cat(current, hdrt->str);
    if (hdrt->idx >= 0) {
        struct vsb *word = vsb_dup(current);
        VSB_finish(word);
        VSB_cat(sb, VSB_data(word));
        VSB_cat(sb, ",");
        VSB_delete(word);
    }
    for (int i = 0; i < 64; i++)
        if (hdrt->next[i] != NULL) {
            struct vsb *next = vsb_dup(current);
            char c = i + 32;
            if (i + 32 == ':')
                c = '~';
            VSB_putc(next, tolower(c));
            hdr_traverse(hdrt->next[i], sb, next);
        }
    VSB_delete(current);
}

void
HDR_List(struct hdrt_node *hdrt, struct vsb *sb)
{
    struct vsb *p = VSB_new_auto();
    hdr_traverse(hdrt, sb, p);
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
