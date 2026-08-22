/* $OpenBSD: expr.c,v 1.18 2010/09/07 19:58:09 marco Exp $ */
/*
 * Copyright (c) 2004 Marc Espie <espie@cvs.openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/cdefs.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include "mdef.h"
#include "extern.h"

int32_t end_result;
static const char *copy_toeval;
int yyerror(const char *msg);

typedef struct yy_buffer_state *YY_BUFFER_STATE;
extern YY_BUFFER_STATE yy_scan_string(const char *);
extern void yy_delete_buffer(YY_BUFFER_STATE);
extern int yyparse(void);

int
yyerror(const char *msg)
{
	fprintf(stderr, "m4: %s in expr %s\n", msg, copy_toeval);
	return 0;
}

int
expr(const char *toeval)
{
	YY_BUFFER_STATE buf;

	copy_toeval = toeval;
	buf = yy_scan_string(toeval);
	yyparse();
	yy_delete_buffer(buf);
	return end_result;
}
