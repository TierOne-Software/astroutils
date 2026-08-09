/*
 * fuzz_awkb.c — libFuzzer harness for awk's private regex engine
 * (src.freebsd/awk/b.c): reparse() (ERE parser, including {n,m}
 * repetition expansion, POSIX character classes and \x/\u escapes),
 * makedfa()/mkdfa() (DFA construction + LRU fatab cache), and the
 * matchers match()/pmatch()/nematch().  All reachable from any awk
 * program via /re/, ~, sub(), gsub(), split(FS), etc.
 *
 * Input layout: byte 0 = pattern length P; pattern = next P bytes;
 * subject = remaining bytes.  Both are copied into NUL-terminated
 * buffers before use.
 *
 * b.c is linked directly; its error paths call FATAL() (normally
 * exit(2) via lib.c).  Here FATAL() is a stub that longjmps back into
 * the harness, so syntax errors just end the current input.  The other
 * awk translation units are replaced by minimal stubs below (tostring,
 * op2/nodealloc/itonp/ptoi, adjbuf, u8_rune/u8_nextlen, and the few
 * globals b.c references).  Stubs are copied from the real awk sources
 * where the logic matters (utf-8 decoding, buffer growth).
 *
 * Leak checking should be disabled (-detect_leaks=0): a FATAL longjmp
 * abandons partially built parse trees/DFAs by design.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>

#include "awk.h"
#include "awkgram.tab.h"

static jmp_buf fuzz_fatal_jmp;

/* ---- globals normally defined in main.c ---- */
enum compile_states compile_time = RUNNING;	/* exercise the fatab LRU cache */
int	dbg = 0;
int	lineno = 1;
int	errorflag = 0;
size_t	awk_mb_cur_max = 4;	/* enable the utf-8 paths in b.c */

/* ---- error handling: FATAL (lib.c) becomes a longjmp ---- */
noreturn void
FATAL(const char *fmt, ...)
{
	(void)fmt;
	longjmp(fuzz_fatal_jmp, 1);
}

void
WARNING(const char *fmt, ...)
{
	(void)fmt;
}

/* ---- string/buffer helpers (tran.c / run.c), logic preserved ---- */
char *
tostring(const char *s)
{
	char *p = strdup(s);
	if (p == NULL)
		FATAL("out of space in tostring on %s", s);
	return p;
}

char *
tostringN(const char *s, size_t n)
{
	char *p = strndup(s, n);
	if (p == NULL)
		FATAL("out of space in tostringN");
	return p;
}

/* copied from run.c: buffer memory management */
int
adjbuf(char **pbuf, int *psiz, int minlen, int quantum, char **pbptr,
    const char *whatrtn)
{
	if (minlen > *psiz) {
		char *tbuf;
		int rminlen = quantum ? minlen % quantum : 0;
		int boff = pbptr ? *pbptr - *pbuf : 0;
		if (rminlen)
			minlen += quantum - rminlen;
		tbuf = (char *) realloc(*pbuf, minlen);
		if (tbuf == NULL) {
			if (whatrtn)
				FATAL("out of memory in %s", whatrtn);
			return 0;
		}
		*pbuf = tbuf;
		*psiz = minlen;
		if (pbptr)
			*pbptr = tbuf + boff;
	}
	return 1;
}

/* ---- parse-tree node constructors (parse.c), trimmed to what b.c uses ---- */
Node *
nodealloc(size_t n)
{
	Node *x;

	x = (Node *) malloc(sizeof(*x) + (n-1) * sizeof(x));
	if (x == NULL)
		FATAL("out of space in nodealloc");
	x->nnext = NULL;
	x->lineno = lineno;
	return x;
}

Node *
op2(int a, Node *b, Node *c)
{
	Node *x;

	x = nodealloc(2);
	x->nobj = a;
	x->narg[0] = b;
	x->narg[1] = c;
	x->ntype = NEXPR;
	return x;
}

int
ptoi(void *p)
{
	return (int) (long) p;
}

Node *
itonp(int i)
{
	return (Node *) (long) i;
}

/* ---- utf-8 decoding (run.c), copied verbatim so b.c sees real runes ---- */
static int
u8_isutf(const char *s)
{
	int n, ret;
	unsigned char c;

	c = s[0];
	if (c < 128 || awk_mb_cur_max == 1)
		return 1;

	n = strlen(s);
	if (n >= 2 && ((c>>5) & 0x7) == 0x6 && (s[1] & 0xC0) == 0x80) {
		ret = 2;
	} else if (n >= 3 && ((c>>4) & 0xF) == 0xE && (s[1] & 0xC0) == 0x80
			 && (s[2] & 0xC0) == 0x80) {
		ret = 3;
	} else if (n >= 4 && ((c>>3) & 0x1F) == 0x1E && (s[1] & 0xC0) == 0x80
			 && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
		ret = 4;
	} else {
		ret = 0;
	}
	return ret;
}

int
u8_rune(int *rune, const char *s)
{
	int n, ret;
	unsigned char c;

	c = s[0];
	if (c < 128 || awk_mb_cur_max == 1) {
		*rune = c;
		return 1;
	}

	n = strlen(s);
	if (n >= 2 && ((c>>5) & 0x7) == 0x6 && (s[1] & 0xC0) == 0x80) {
		*rune = ((c & 0x1F) << 6) | (s[1] & 0x3F);
		ret = 2;
	} else if (n >= 3 && ((c>>4) & 0xF) == 0xE && (s[1] & 0xC0) == 0x80
			  && (s[2] & 0xC0) == 0x80) {
		*rune = ((c & 0xF) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
		ret = 3;
	} else if (n >= 4 && ((c>>3) & 0x1F) == 0x1E && (s[1] & 0xC0) == 0x80
			  && (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
		*rune = ((c & 0x7) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
		ret = 4;
	} else {
		*rune = c;
		ret = 1;
	}
	return ret;
}

int
u8_nextlen(const char *s)
{
	int len;

	len = u8_isutf(s);
	if (len == 0)
		len = 1;
	return len;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > 8192)
		return 0;

	size_t plen = data[0];
	if (plen > size - 1)
		plen = size - 1;
	size_t slen = size - 1 - plen;

	char *pat = malloc(plen + 1);
	char *subj = malloc(slen + 1);
	if (pat == NULL || subj == NULL) {
		free(pat);
		free(subj);
		return 0;
	}
	memcpy(pat, data + 1, plen);
	pat[plen] = '\0';
	memcpy(subj, data + 1 + plen, slen);
	subj[slen] = '\0';

	if (setjmp(fuzz_fatal_jmp) != 0) {
		/* FATAL(): malformed regex (or "regex too big"); done */
		free(pat);
		free(subj);
		return 0;
	}

	/* DFA construction, both unanchored and anchored flavors */
	fa *dfa = makedfa(pat, false);
	fa *adfa = makedfa(pat, true);

	/* shortest, longest, and non-empty matchers over the subject */
	match(dfa, subj);
	pmatch(dfa, subj);
	nematch(dfa, subj);
	match(adfa, subj);
	nematch(adfa, subj);

	free(pat);
	free(subj);
	return 0;
}
