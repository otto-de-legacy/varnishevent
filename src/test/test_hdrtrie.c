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

#include <stdio.h>
#include <ctype.h>

#include "minunit.h"

#include "../hdrtrie.h"

int tests_run = 0;

static inline int
next_idx(char c)
{
    int n = toupper(c) - 32;
    if (c == '~')
        n = ':' - 32;
    return n;
}

static char
*test_HDR_FindIdx(void)
{
#define NODES 10
    struct hdrt_node hdrt[NODES];

    printf("... testing HDR_FindIdx()\n");

    for (int i = 0; i < NODES; i++) {
        hdrt[i].magic = HDRT_NODE_MAGIC;
        hdrt[i].next = calloc(64, sizeof(struct hdrt_node *));
    }

    hdrt[0].str = strdup("Foo");
    hdrt[0].idx = 4711;

    MASSERT(HDR_FindIdx(&hdrt[0], "Foo:") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo: bar") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo:bar") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo: bar baz") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "  Foo  : ") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "  fOO  : ") == 4711);

    MASSERT(HDR_FindIdx(&hdrt[0], "Bar:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "   Bar:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Fo:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Food:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo bar baz") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "   Foo   ") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "      ") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "") == -1);

    hdrt[0].str = strdup("Accept");
    hdrt[0].next[next_idx('-')] = &hdrt[1];

    hdrt[1].str = strdup("");
    hdrt[1].next[next_idx('C')] = &hdrt[2];
    hdrt[1].next[next_idx('E')] = &hdrt[3];
    hdrt[1].next[next_idx('L')] = &hdrt[4];
    hdrt[1].next[next_idx('D')] = &hdrt[5];
    hdrt[1].idx = -1;

    hdrt[2].str = strdup("harset");
    hdrt[2].idx = 1;

    hdrt[3].str = strdup("ncoding");
    hdrt[3].idx = 2;

    hdrt[4].str = strdup("anguage");
    hdrt[4].idx = 3;

    hdrt[5].str = strdup("atetime");
    hdrt[5].idx = 4;

    MASSERT(HDR_FindIdx(&hdrt[0], "Accept:") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Charset:") == 1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Encoding:") == 2);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Language:") == 3);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Datetime:") == 4);

    MASSERT(HDR_FindIdx(&hdrt[0], "accept:") == 4711);
    MASSERT(HDR_FindIdx(&hdrt[0], "accept-charset:") == 1);
    MASSERT(HDR_FindIdx(&hdrt[0], "accept-encoding:") == 2);
    MASSERT(HDR_FindIdx(&hdrt[0], "accept-language:") == 3);
    MASSERT(HDR_FindIdx(&hdrt[0], "accept-datetime:") == 4);

    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Foo:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Foo:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-CharsetFoo:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Accept-Charse:") == -1);

    hdrt[0].str = strdup("Content-");
    memset(hdrt[0].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[0].next[next_idx('D')] = &hdrt[1];
    hdrt[0].next[next_idx('E')] = &hdrt[2];
    hdrt[0].next[next_idx('L')] = &hdrt[3];
    hdrt[0].next[next_idx('M')] = &hdrt[4];
    hdrt[0].next[next_idx('R')] = &hdrt[5];
    hdrt[0].next[next_idx('T')] = &hdrt[6];
    hdrt[0].idx = -1;

    hdrt[1].str = strdup("isposition");
    memset(hdrt[1].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[1].idx = 1;

    hdrt[2].str = strdup("ncoding");
    memset(hdrt[2].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[2].idx = 2;

    hdrt[3].str = strdup("");
    memset(hdrt[3].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[3].next[next_idx('A')] = &hdrt[7];
    hdrt[3].next[next_idx('E')] = &hdrt[8];
    hdrt[3].next[next_idx('O')] = &hdrt[9];
    hdrt[3].idx = -1;

    hdrt[4].str = strdup("D5");
    memset(hdrt[4].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[4].idx = 3;

    hdrt[5].str = strdup("ange");
    memset(hdrt[5].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[5].idx = 4;

    hdrt[6].str = strdup("ype");
    hdrt[6].idx = 5;

    hdrt[7].str = strdup("nguage");
    hdrt[7].idx = 6;

    hdrt[8].str = strdup("ngth");
    hdrt[8].idx = 7;

    hdrt[9].str = strdup("cation");
    hdrt[9].idx = 8;

    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Disposition:") == 1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Encoding:") == 2);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Language:") == 6);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Length:") == 7);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Location:") == 8);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-MD5:") == 3);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Range:") == 4);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Type:") == 5);

    MASSERT(HDR_FindIdx(&hdrt[0], "Content-:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-L:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-La:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Le:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Lo:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "Content-Foo:") == -1);

    hdrt[0].str = strdup("X-");
    memset(hdrt[0].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[0].next[next_idx('C')] = &hdrt[1];
    hdrt[0].next[next_idx('F')] = &hdrt[2];
    hdrt[0].idx = -1;

    hdrt[1].str = strdup("srf-Token");
    memset(hdrt[1].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[1].idx = 1;

    hdrt[2].str = strdup("orwarded-");
    memset(hdrt[2].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[2].next[next_idx('F')] = &hdrt[3];
    hdrt[2].next[next_idx('H')] = &hdrt[4];
    hdrt[2].next[next_idx('P')] = &hdrt[5];
    hdrt[2].idx = -1;

    hdrt[3].str = strdup("or");
    memset(hdrt[3].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[3].idx = 2;

    hdrt[4].str = strdup("ost");
    memset(hdrt[4].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[4].idx = 3;

    hdrt[5].str = strdup("roto");
    memset(hdrt[5].next, 0, 64 * sizeof(struct hdrt_node *));
    hdrt[5].idx = 4;

    MASSERT(HDR_FindIdx(&hdrt[0], "X-Csrf-Token:") == 1);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-For:") == 2);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-Host:") == 3);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-Proto:") == 4);

    MASSERT(HDR_FindIdx(&hdrt[0], "X-:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-F:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-H:") == -1);
    MASSERT(HDR_FindIdx(&hdrt[0], "X-Forwarded-P:") == -1);

    return NULL;
}

static char
*test_HDR_InsertIdx(void)
{
#define NODES 10
#define SIZEOF_NEXTTBL (64 * sizeof(struct hdrt_node *))
    struct hdrt_node *hdrt, *hdrt2, *next;

    printf("... testing HDR_InsertIdx()\n");

    next = calloc(64, sizeof(next));
    MAN(next);

    hdrt = HDR_InsertIdx(NULL, "Foo", 4711);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt->str, "Foo") == 0);
    MASSERT(hdrt->idx == 4711);
    MASSERT(memcmp(hdrt->next, next, SIZEOF_NEXTTBL) == 0);
    MASSERT(HDR_FindIdx(hdrt, "Foo:") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "Foo: bar") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "Foo:bar") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "Foo: bar baz") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "  Foo  : ") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "  fOO  : ") == 4711);

    MASSERT(HDR_FindIdx(hdrt, "Bar:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "   Bar:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Fo:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Food:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Foo bar baz") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Foo") == -1);
    MASSERT(HDR_FindIdx(hdrt, "   Foo   ") == -1);
    MASSERT(HDR_FindIdx(hdrt, "      ") == -1);
    MASSERT(HDR_FindIdx(hdrt, "") == -1);

    hdrt = HDR_InsertIdx(hdrt, "Foo", 4711);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    MASSERT(HDR_FindIdx(hdrt, "Foo:") == 4711);

    hdrt = HDR_InsertIdx(hdrt, "Bar", 1147);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    MASSERT(*hdrt->str == '\0');
    MASSERT(hdrt->idx == -1);
    for (int i = 0; i < 64; i ++)
        if (i != next_idx('B') && i != next_idx('F'))
            MAZ(hdrt->next[i]);
    hdrt2 = hdrt->next[next_idx('B')];
    MCHECK_OBJ_NOTNULL(hdrt2, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt2->str, "ar") == 0);
    MASSERT(hdrt2->idx == 1147);
    MASSERT(memcmp(hdrt2->next, next, SIZEOF_NEXTTBL) == 0);
    hdrt2 = hdrt->next[next_idx('F')];
    MCHECK_OBJ_NOTNULL(hdrt2, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt2->str, "oo") == 0);
    MASSERT(hdrt2->idx == 4711);
    MASSERT(memcmp(hdrt2->next, next, SIZEOF_NEXTTBL) == 0);
    MASSERT(HDR_FindIdx(hdrt, "Foo:") == 4711);
    MASSERT(HDR_FindIdx(hdrt, "Bar:") == 1147);

    hdrt = HDR_InsertIdx(NULL, "Accept", 1);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Encoding", 2);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt->str, "Accept") == 0);
    MASSERT(hdrt->idx == 1);
    for (int i = 0; i < 64; i ++)
        if (i != next_idx('-'))
            MAZ(hdrt->next[i]);
    hdrt2 = hdrt->next[next_idx('-')];
    MCHECK_OBJ_NOTNULL(hdrt2, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt2->str, "Encoding") == 0);
    MASSERT(hdrt2->idx == 2);
    MASSERT(memcmp(hdrt2->next, next, SIZEOF_NEXTTBL) == 0);
    MASSERT(HDR_FindIdx(hdrt, "Accept:") == 1);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Encoding:") == 2);

    hdrt = HDR_InsertIdx(hdrt, "Accept-Charset", 3);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Language", 4);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Datetime", 5);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt->str, "Accept") == 0);
    MASSERT(hdrt->idx == 1);
    for (int i = 0; i < 64; i ++)
        if (i != next_idx('-'))
            MAZ(hdrt->next[i]);
    hdrt2 = hdrt->next[next_idx('-')];
    MCHECK_OBJ_NOTNULL(hdrt2, HDRT_NODE_MAGIC);
    MASSERT(*hdrt2->str == '\0');
    MASSERT(hdrt2->idx == -1);
    for (int i = 0; i < 64; i ++)
        if (i != next_idx('C') && i != next_idx('D') && i != next_idx('E')
            && i != next_idx('L'))
            MAZ(hdrt2->next[i]);
    MCHECK_OBJ_NOTNULL(hdrt2->next[next_idx('C')], HDRT_NODE_MAGIC);
    MCHECK_OBJ_NOTNULL(hdrt2->next[next_idx('D')], HDRT_NODE_MAGIC);
    MCHECK_OBJ_NOTNULL(hdrt2->next[next_idx('E')], HDRT_NODE_MAGIC);
    MCHECK_OBJ_NOTNULL(hdrt2->next[next_idx('L')], HDRT_NODE_MAGIC);
    MASSERT(strcmp(hdrt2->next[next_idx('C')]->str, "harset") == 0);
    MASSERT(hdrt2->next[next_idx('C')]->idx == 3);
    MASSERT(strcmp(hdrt2->next[next_idx('D')]->str, "atetime") == 0);
    MASSERT(hdrt2->next[next_idx('D')]->idx == 5);
    MASSERT(strcmp(hdrt2->next[next_idx('E')]->str, "ncoding") == 0);
    MASSERT(hdrt2->next[next_idx('E')]->idx == 2);
    MASSERT(strcmp(hdrt2->next[next_idx('L')]->str, "anguage") == 0);
    MASSERT(hdrt2->next[next_idx('L')]->idx == 4);
    MASSERT(HDR_FindIdx(hdrt, "Accept:") == 1);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Charset:") == 3);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Encoding:") == 2);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Language:") == 4);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Datetime:") == 5);

    hdrt = HDR_InsertIdx(NULL, "Accept-Encoding", 4711);
    hdrt = HDR_InsertIdx(hdrt, "Accept", 1147);
    MASSERT(HDR_FindIdx(hdrt, "Accept:") == 1147);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Charset:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Accept-Encoding:") == 4711);

    hdrt = HDR_InsertIdx(NULL, "Content-Disposition", 1);
    hdrt = HDR_InsertIdx(hdrt, "Content-Encoding", 2);
    hdrt = HDR_InsertIdx(hdrt, "Content-Language", 3);
    hdrt = HDR_InsertIdx(hdrt, "Content-Length", 4);
    hdrt = HDR_InsertIdx(hdrt, "Content-Location", 5);
    hdrt = HDR_InsertIdx(hdrt, "Content-MD5", 6);
    hdrt = HDR_InsertIdx(hdrt, "Content-Range", 7);
    hdrt = HDR_InsertIdx(hdrt, "Content-Type", 8);
    MASSERT(HDR_FindIdx(hdrt, "Content-Disposition:") == 1);
    MASSERT(HDR_FindIdx(hdrt, "Content-Encoding:") == 2);
    MASSERT(HDR_FindIdx(hdrt, "Content-Language:") == 3);
    MASSERT(HDR_FindIdx(hdrt, "Content-Length:") == 4);
    MASSERT(HDR_FindIdx(hdrt, "Content-Location:") == 5);
    MASSERT(HDR_FindIdx(hdrt, "Content-MD5:") == 6);
    MASSERT(HDR_FindIdx(hdrt, "Content-Range:") == 7);
    MASSERT(HDR_FindIdx(hdrt, "Content-Type:") == 8);

    MASSERT(HDR_FindIdx(hdrt, "Content-:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content-L:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content-La:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content-Le:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content-Lo:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "Content-Foo:") == -1);

    hdrt = HDR_InsertIdx(NULL, "X-Csrf-Token", 11);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-For", 12);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Host", 13);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Proto", 14);

    MASSERT(HDR_FindIdx(hdrt, "X-Csrf-Token:") == 11);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-For:") == 12);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-Host:") == 13);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-Proto:") == 14);

    MASSERT(HDR_FindIdx(hdrt, "X-:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-F:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-H:") == -1);
    MASSERT(HDR_FindIdx(hdrt, "X-Forwarded-P:") == -1);

    hdrt = HDR_InsertIdx(NULL, "Beresp", 0);
    hdrt = HDR_InsertIdx(hdrt, "BerespBody", 1);
    hdrt = HDR_InsertIdx(hdrt, "Bereq", 2);
    MASSERT(HDR_FindIdx(hdrt, "Beresp:") == 0);
    MASSERT(HDR_FindIdx(hdrt, "BerespBody:") == 1);
    MASSERT(HDR_FindIdx(hdrt, "Bereq:") == 2);

    return NULL;
}

static char
*test_HDR_N(void)
{
    struct hdrt_node *hdrt;

    printf("... testing HDR_N()\n");

    MAZ(HDR_N(NULL));

    hdrt = HDR_InsertIdx(NULL, "Foo", 4711);
    MASSERT(HDR_N(hdrt) == 1);

    hdrt = HDR_InsertIdx(NULL, "Accept-Encoding", 1);
    hdrt = HDR_InsertIdx(hdrt, "Accept", 2);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Charset", 3);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Language", 4);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Datetime", 5);
    MASSERT(HDR_N(hdrt) == 5);

    hdrt = HDR_InsertIdx(NULL, "Content-Disposition", 1);
    hdrt = HDR_InsertIdx(hdrt, "Content-Encoding", 2);
    hdrt = HDR_InsertIdx(hdrt, "Content-Language", 3);
    hdrt = HDR_InsertIdx(hdrt, "Content-Length", 4);
    hdrt = HDR_InsertIdx(hdrt, "Content-Location", 5);
    hdrt = HDR_InsertIdx(hdrt, "Content-MD5", 6);
    hdrt = HDR_InsertIdx(hdrt, "Content-Range", 7);
    hdrt = HDR_InsertIdx(hdrt, "Content-Type", 8);
    MASSERT(HDR_N(hdrt) == 8);

    hdrt = HDR_InsertIdx(NULL, "X-Csrf-Token", 1);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-For", 2);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Host", 3);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Proto", 4);
    MASSERT(HDR_N(hdrt) == 4);

    hdrt = HDR_InsertIdx(NULL, "Beresp", 0);
    hdrt = HDR_InsertIdx(hdrt, "BerespBody", 1);
    hdrt = HDR_InsertIdx(hdrt, "Bereq", 2);
    MASSERT(HDR_N(hdrt) == 3);

    return NULL;
}

static char
*test_HDR_List(void)
{
    struct hdrt_node *hdrt;
    struct vsb *sb = VSB_new_auto();

    printf("... testing HDR_List()\n");

    HDR_List(NULL, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(VSB_len(sb) == 0);

    VSB_clear(sb);
    hdrt = HDR_InsertIdx(NULL, "Foo", 4711);
    HDR_List(hdrt, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(strcasecmp(VSB_data(sb), "Foo,") == 0);

#define EXP "Accept,Accept-Charset,Accept-Datetime,Accept-Encoding," \
            "Accept-Language,"
    VSB_clear(sb);
    hdrt = HDR_InsertIdx(NULL, "Accept-Encoding", 1);
    hdrt = HDR_InsertIdx(hdrt, "Accept", 2);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Charset", 3);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Language", 4);
    hdrt = HDR_InsertIdx(hdrt, "Accept-Datetime", 5);
    HDR_List(hdrt, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(strcasecmp(VSB_data(sb), EXP) == 0);
#undef EXP

#define EXP "Content-Disposition,Content-Encoding,Content-Language," \
            "Content-Length,Content-Location,Content-MD5,Content-Range," \
            "Content-Type,"
    VSB_clear(sb);
    hdrt = HDR_InsertIdx(NULL, "Content-Disposition", 1);
    hdrt = HDR_InsertIdx(hdrt, "Content-Encoding", 2);
    hdrt = HDR_InsertIdx(hdrt, "Content-Language", 3);
    hdrt = HDR_InsertIdx(hdrt, "Content-Length", 4);
    hdrt = HDR_InsertIdx(hdrt, "Content-Location", 5);
    hdrt = HDR_InsertIdx(hdrt, "Content-MD5", 6);
    hdrt = HDR_InsertIdx(hdrt, "Content-Range", 7);
    hdrt = HDR_InsertIdx(hdrt, "Content-Type", 8);
    HDR_List(hdrt, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(strcasecmp(VSB_data(sb), EXP) == 0);
#undef EXP

#define EXP "X-Csrf-Token,X-Forwarded-For,X-Forwarded-Host,X-Forwarded-Proto,"
    VSB_clear(sb);
    hdrt = HDR_InsertIdx(NULL, "X-Csrf-Token", 1);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-For", 2);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Host", 3);
    hdrt = HDR_InsertIdx(hdrt, "X-Forwarded-Proto", 4);
    HDR_List(hdrt, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(strcasecmp(VSB_data(sb), EXP) == 0);
#undef EXP

#define EXP "Bereq,Beresp,BerespBody,"
    VSB_clear(sb);
    hdrt = HDR_InsertIdx(NULL, "Beresp", 0);
    hdrt = HDR_InsertIdx(hdrt, "BerespBody", 1);
    hdrt = HDR_InsertIdx(hdrt, "Bereq", 2);
    HDR_List(hdrt, sb);
    VSB_finish(sb);
    MASSERT(VSB_error(sb) == 0);
    MASSERT(strcasecmp(VSB_data(sb), EXP) == 0);
#undef EXP

    VSB_delete(sb);

    return NULL;
}

static char
*test_HDR_Fini(void)
{
    struct hdrt_node *hdrt;

    printf("... testing HDR_Fini()\n");

    hdrt = HDR_InsertIdx(NULL, "Content-Disposition", 1);
    hdrt = HDR_InsertIdx(hdrt, "Content-Encoding", 2);
    hdrt = HDR_InsertIdx(hdrt, "Content-Language", 3);
    hdrt = HDR_InsertIdx(hdrt, "Content-Length", 4);
    hdrt = HDR_InsertIdx(hdrt, "Content-Location", 5);
    hdrt = HDR_InsertIdx(hdrt, "Content-MD5", 6);
    hdrt = HDR_InsertIdx(hdrt, "Content-Range", 7);
    hdrt = HDR_InsertIdx(hdrt, "Content-Type", 8);
    MCHECK_OBJ_NOTNULL(hdrt, HDRT_NODE_MAGIC);

    HDR_Fini(hdrt);
    MASSERT(hdrt == NULL || hdrt->magic != HDRT_NODE_MAGIC);

    return NULL;
}

static const char
*all_tests(void)
{
    mu_run_test(test_HDR_FindIdx);
    mu_run_test(test_HDR_InsertIdx);
    mu_run_test(test_HDR_N);
    mu_run_test(test_HDR_List);
    mu_run_test(test_HDR_Fini);
    return NULL;
}

TEST_RUNNER
