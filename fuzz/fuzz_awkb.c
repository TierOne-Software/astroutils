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
 *
 * KNOWN-BUG FILTERS (target bugs found by this harness, reported, NOT
 * fixed — inputs that would hit them are skipped here so fuzzing can
 * proceed past them):
 *  1. b.c:1449-1450 / 1202-1207 — a "{n,m}" repetition is expanded by
 *     replace_repeat(), which frees and replaces basestr without
 *     updating the static lastatom; a following repetition whose
 *     preceding token does not re-establish lastatom (start, '|',
 *     '(', '{', '}', '$', '^') computes atomlen = startreptok -
 *     lastatom from a NULL/stale/dangling pointer: negative or
 *     undersized `size` (b.c:1160-1173) then OOB memcpy
 *     (b.c:1184/1193).  Triggers: "{2,3}…", "x{1}{1,3}",
 *     "({1}){1,3}", "x{1}${2}".  Filter: skip "{<digit>" preceded by
 *     one of those tokens.
 *  2. b.c:1299 — a trailing lone backslash makes quoted() (b.c:372)
 *     consume the terminating NUL and advance prestr past the end of
 *     the pattern; the next relex()/u8_rune() reads out of bounds
 *     (b.c:1271).  Filter: skip patterns ending in an odd number of
 *     backslashes.
 *  3. b.c:1382-1383 / 1365-1366 — a pattern ending in "[=" or "[."
 *     with a character class open makes the equivalence-class/
 *     collating-symbol handling consume the terminating NUL and read
 *     past the end of the pattern buffer.
 *     Filter: skip patterns ending in "[=" or "[.".
 *  4. b.c:1464 — repetition bounds are accumulated into an int with
 *     no overflow check (`num = 10 * num + c - '0'`); a bound like
 *     {26666666666666666666} wraps, then replace_repeat() overflows
 *     `size` (b.c:1163/1170) and calls malloc with a negative/huge
 *     size (b.c:1174) or under-allocates and overflows buf in the
 *     copy loops (b.c:1184/1193).  Even without the wrap, large
 *     bounds are a CPU/memory DoS (DFA size is quadratic in the
 *     expansion).  Filter: skip bounds with >2 digits.
 *  5. b.c:473 — cclenter() keeps its class elements in a static
 *     buffer grown in 100*2^k steps with the growth check only
 *     before element writes; a class that expands to exactly a
 *     boundary count (e.g. 100 elements, "[^\\x17-z]") makes the
 *     terminating `*bp = 0` write one int past the buffer.
 *     Filter: emulate the expansion and skip boundary counts.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <setjmp.h>
#include <ctype.h>

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

/*
 * Emulate relex()'s class scan + cclenter()'s expansion for one "[...]"
 * at s, and return true if the expanded element count lands exactly on a
 * cclenter bufsz boundary (100, 200, 400, ...), which overruns the static
 * buffer by one int at b.c:473.  Approximates utf-8 runes as single bytes
 * and allows a +/-1 margin; good enough for a fuzz input filter.
 */
static int
class_hits_bufsz(const char *s, size_t n)
{
	static const struct { const char *name; int (*func)(int); } ccs[] = {
		{ "alnum", isalnum }, { "alpha", isalpha }, { "blank", NULL },
		{ "cntrl", iscntrl }, { "digit", isdigit }, { "graph", isgraph },
		{ "lower", islower }, { "print", isprint }, { "punct", ispunct },
		{ "space", isspace }, { "upper", isupper }, { "xdigit", isxdigit },
	};
	int elems[8192];
	long ne = 0;
	size_t i = 1;			/* skip '[' */
	int first = 1;

	if (i < n && s[i] == '^')
		i++;
	for (; i < n && ne < (long)(sizeof(elems)/sizeof(elems[0]) - 300); ) {
		int c = (unsigned char) s[i];

		if (c == '\0')
			break;
		if (c == ']' && !first)
			break;
		if (c == '\\' && i + 1 < n) {		/* quoted char */
			i++;
			c = (unsigned char) s[i];
			if (c >= '0' && c <= '7') {	/* \ddd octal */
				int v = 0, k = 0;
				while (k++ < 3 && i < n && s[i] >= '0' && s[i] <= '7')
					v = 8 * v + s[i++] - '0';
				i--;
				c = v;
			} else if (c == 'x') {		/* \xhh */
				int v = 0, k = 0;
				while (k++ < 2 && i + 1 < n && isxdigit((unsigned char) s[i + 1])) {
					char h = s[++i];
					v = 16 * v + (isdigit((unsigned char) h) ? h - '0' :
					    (h | 32) - 'a' + 10);
				}
				c = v;
			}
		} else if (c == '[' && i + 1 < n && s[i + 1] == ':') {	/* [[:name:]] */
			size_t k;
			for (k = 0; k < sizeof(ccs)/sizeof(ccs[0]); k++) {
				size_t nl = strlen(ccs[k].name);
				if (i + 2 + nl + 1 < n && strncmp(s + i + 2, ccs[k].name, nl) == 0 &&
				    s[i + 2 + nl] == ':' && s[i + 2 + nl + 1] == ']') {
					for (int ch = 1; ch < 256; ch++) {
						int m = ccs[k].func ? ccs[k].func(ch) :
						    (ch == ' ' || ch == '\t');
						if (m)
							elems[ne++] = ch;
					}
					i += 2 + nl + 2;
					break;
				}
			}
			if (k < sizeof(ccs)/sizeof(ccs[0])) {
				first = 0;
				continue;
			}
		}
		elems[ne++] = c;	/* literal or quoted char */
		i++;
		first = 0;
	}
	/* cclenter's range pass over the collected elements (k indexes the
	 * raw element array; ne tracks the logical expanded count) */
	long raw = ne;
	for (long k = 0; k < raw; k++) {
		if (elems[k] == '-' && k > 0 && k + 1 < raw && elems[k - 1] != 0) {
			int c1 = elems[k - 1], c2 = elems[k + 1];
			if (c1 > c2) {		/* empty range: removes previous */
				ne -= 3;
			} else {
				/* '-' and c2 become the expansion c1+1..c2 */
				ne += (c2 - c1) - 2;
			}
		}
	}
	for (long b = 100; b <= ne + 3 && b < (1 << 24); b *= 2)
		if (ne >= b - 3 && ne <= b + 3)
			return 1;
	return 0;
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

	/* use the effective C-string length, embedded NULs truncate */
	size_t elen = strlen(pat);

	/* known-bug filters 1+4: "{<digit>" repetition where lastatom is
	 * NULL/stale/dangling (b.c:1449): preceded by start, '|', '(',
	 * '{', '}', '$' or '^' */
	for (size_t i = 0; i + 1 < elen; i++) {
		if (pat[i] != '{' || pat[i + 1] < '0' || pat[i + 1] > '9')
			continue;
		if (i == 0 || strchr("|({}$^", pat[i - 1]) != NULL)
			goto out;
		/* known-bug filter 5: repetition bound with more than 2
		 * digits overflows the int arithmetic in relex/replace_repeat
		 * (b.c:1464, b.c:1163-1174) and nested bounds are a CPU DoS
		 * even below the overflow (DFA size is quadratic in the
		 * expansion) */
		for (size_t j = i + 1; j < elen && pat[j] != '}'; j++) {
			if (pat[j] == ',')
				continue;
			if (j - i > 3)	/* >2 digits in one number */
				goto out;
		}
	}
	/* known-bug filter 2: trailing lone backslash (b.c:1299/372) */
	if (elen > 0 && pat[elen - 1] == '\\') {
		size_t nbs = 0;
		while (nbs < elen && pat[elen - 1 - nbs] == '\\')
			nbs++;
		if (nbs % 2 == 1)
			goto out;
	}
	/* known-bug filter 3: pattern ending in "[=" or "[." with a class
	 * open (b.c:1362-1366/1379-1383): collate_char/equiv_char consumes
	 * the terminating NUL and *prestr reads past the buffer */
	if (elen >= 2 && pat[elen - 2] == '[' &&
	    (pat[elen - 1] == '=' || pat[elen - 1] == '.'))
		goto out;
	/* known-bug filter 6: class expanding to exactly 100*2^k elements
	 * overruns cclenter's static buffer at the terminator (b.c:473) */
	for (size_t i = 0; i < elen; i++) {
		if (pat[i] == '[' && (i == 0 || pat[i - 1] != '\\') &&
		    class_hits_bufsz(pat + i, elen - i))
			goto out;
	}

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

out:
	free(pat);
	free(subj);
	return 0;
}
