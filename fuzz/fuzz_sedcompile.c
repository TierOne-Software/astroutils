/*
 * fuzz_sedcompile.c — libFuzzer harness for sed(1)'s script compiler
 * (src.freebsd/sed/compile.c): compile_stream() parses untrusted -e/-f
 * scripts — addresses, s/// (compile_delimited, compile_subst,
 * compile_flags, compile_ccl), y/// (compile_tr), a/i/c text
 * (compile_text), labels and { } groups, plus the
 * fixuplabel()/uselabel() second pass.  When the script compiles
 * cleanly and cannot loop (no b/t command with a target), the
 * interpreter (process() in process.c) is also run over a small fixed
 * input, covering substitute()/regsub(), regexec_e(), do_tr(),
 * lputs() and cspace().
 *
 * The .c files are included directly (like fuzz_http.c) so the harness
 * can reach the compiler/interpreter statics and reset them between
 * inputs.  sed reports script errors via err()/errx()/exit(); these
 * are macro-redirected to a longjmp back into the harness (the
 * fuzz_patch.c pattern, done textually here).
 *
 * All malloc/calloc/realloc/strdup/free calls inside the sed sources
 * are macro-redirected to tracking wrappers so that every allocation
 * of a run — including partially built prog lists and label-hash
 * entries left behind by mid-compile errors — can be released on reset
 * without walking data structures whose shape depends on where the
 * error hit.  regcomp() is likewise wrapped so successfully compiled
 * regexes can be regfree()d.  misc.c is included before the allocation
 * macros on purpose: its strregerror() keeps one self-consistent
 * static buffer (oe) across runs.
 *
 * open()/fopen() are redirected to /dev/null (writes) or failure
 * (reads) so that w / s///w / r commands from fuzzed scripts cannot
 * touch the filesystem; fds handed out are tracked and closed on
 * reset.  aflag is forced so w files are never opened at compile time.
 *
 * cu_fgets()/mf_fgets()/lastline() are harness-local replacements for
 * the main.c originals: the compiler reads the fuzz input and the
 * interpreter reads a fixed 5-line input.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

/* defs.h/extern.h have no include guards; they come in via misc.c below. */

/* ---- error/exit interception -------------------------------------- */

static jmp_buf fuzz_jmp;

static void
fuzz_throw(void)
{

	longjmp(fuzz_jmp, 1);
}

/* ---- allocation tracking ------------------------------------------- */

#define FUZZ_MAX_ALLOCS	32768
#define FUZZ_MAX_RES	8192
#define FUZZ_MAX_FDS	4096

static void	*fuzz_allocs[FUZZ_MAX_ALLOCS];
static size_t	 fuzz_nallocs;
static regex_t	*fuzz_res[FUZZ_MAX_RES];
static size_t	  fuzz_nres;
static int	  fuzz_fds[FUZZ_MAX_FDS];
static size_t	  fuzz_nfds;

static void *
fuzz_malloc(size_t n)
{
	void *p = malloc(n);

	if (p != NULL && fuzz_nallocs < FUZZ_MAX_ALLOCS)
		fuzz_allocs[fuzz_nallocs++] = p;
	return (p);
}

static void *
fuzz_calloc(size_t nm, size_t n)
{
	void *p = calloc(nm, n);

	if (p != NULL && fuzz_nallocs < FUZZ_MAX_ALLOCS)
		fuzz_allocs[fuzz_nallocs++] = p;
	return (p);
}

static void *
fuzz_realloc(void *op, size_t n)
{
	void *p;
	size_t i;

	if (op == NULL)
		return (fuzz_malloc(n));
	p = realloc(op, n);
	if (p == NULL)
		return (NULL);
	for (i = 0; i < fuzz_nallocs; i++)
		if (fuzz_allocs[i] == op) {
			fuzz_allocs[i] = p;
			return (p);
		}
	if (fuzz_nallocs < FUZZ_MAX_ALLOCS)
		fuzz_allocs[fuzz_nallocs++] = p;
	return (p);
}

static char *
fuzz_strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = fuzz_malloc(n);

	if (p != NULL)
		memcpy(p, s, n);
	return (p);
}

static void
fuzz_free(void *p)
{
	size_t i;

	if (p == NULL)
		return;
	for (i = 0; i < fuzz_nallocs; i++)
		if (fuzz_allocs[i] == p) {
			free(p);
			fuzz_allocs[i] = NULL;
			return;
		}
	/*
	 * Not an allocation of the current epoch.  With the input size
	 * cap the table cannot overflow, so this should not happen;
	 * do nothing rather than risk a double free.
	 */
}

static int
fuzz_regcomp(regex_t *preg, const char *pattern, int cflags)
{
	const char *s;
	int r, run;

	/*
	 * Filter: glibc regcomp() blows up exponentially when an already
	 * quantified expression is followed by a long run of quantifiers
	 * (ERE "x*" + 12 pluses takes >10s to compile; a libc
	 * algorithmic-complexity DoS reachable via sed scripts, not a sed
	 * bug).  Reject patterns with a run of >= 5 quantifier chars
	 * (measured safe: 7 quantifiers compile in ~0.03s) so fuzzing
	 * can continue past this class.
	 */
	run = 0;
	for (s = pattern; *s != '\0'; s++) {
		if (*s == '\\' && (s[1] == '*' || s[1] == '+' || s[1] == '?'))
			s++;
		if (*s == '*' || *s == '+' || *s == '?') {
			if (++run >= 5)
				return (REG_BADPAT);
		} else
			run = 0;
	}

	r = regcomp(preg, pattern, cflags);

	if (r == 0 && fuzz_nres < FUZZ_MAX_RES)
		fuzz_res[fuzz_nres++] = preg;
	return (r);
}

static int
fuzz_open(const char *path, int flags, ...)
{
	int fd;

	(void)path;
	if ((flags & O_ACCMODE) == O_RDONLY) {
		errno = ENOENT;
		return (-1);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd >= 0 && fuzz_nfds < FUZZ_MAX_FDS)
		fuzz_fds[fuzz_nfds++] = fd;
	return (fd);
}

static FILE *
fuzz_fopen(const char *path, const char *mode)
{

	(void)path;
	(void)mode;
	errno = ENOENT;
	return (NULL);
}

#define err(...)		fuzz_throw()
#define errx(...)		fuzz_throw()
#define errc(...)		fuzz_throw()
#define warn(...)		((void)0)
#define warnx(...)		((void)0)
#define warnc(...)		((void)0)
#define exit(...)		fuzz_throw()

/* misc.c before the allocation macros: strregerror() keeps one
 * self-consistent static buffer across runs. */
#include "../src.freebsd/sed/misc.c"

#define malloc			fuzz_malloc
#define calloc			fuzz_calloc
#define realloc			fuzz_realloc
#define free			fuzz_free
#define strdup			fuzz_strdup
#define regcomp			fuzz_regcomp
#define open(...)		fuzz_open(__VA_ARGS__)
#define fopen(...)		fuzz_fopen(__VA_ARGS__)

#include "../src.freebsd/sed/compile.c"
#include "../src.freebsd/sed/process.c"

#undef malloc
#undef calloc
#undef realloc
#undef free
#undef strdup
#undef regcomp
#undef open
#undef fopen

/* ---- globals normally provided by main.c ---------------------------- */

FILE	*infile;			/* unused: mf_fgets is harness-local */
FILE	*outfile;
int	 aflag, eflag, nflag;
int	 rflags;
int	 quit;
const char *fname, *outfname;
const char *inplace;
u_long	 linenum;

/* ---- harness input plumbing ----------------------------------------- */

static const char	*fuzz_script;
static size_t		 fuzz_script_len, fuzz_script_pos;

char *
cu_fgets(char *buf, int n, int *more)
{
	size_t i;

	if (fuzz_script_pos >= fuzz_script_len) {
		if (more != NULL)
			*more = 0;
		return (NULL);
	}
	for (i = 0; i < (size_t)n - 1 && fuzz_script_pos < fuzz_script_len;) {
		char c = fuzz_script[fuzz_script_pos++];
		buf[i++] = c;
		if (c == '\n')
			break;
	}
	buf[i] = '\0';
	linenum++;
	if (more != NULL)
		*more = fuzz_script_pos < fuzz_script_len;
	return (buf);
}

static const char	 fuzz_input[] =
    "hello world\n"
    "foo bar 123\n"
    "HELLO hello HELLO\n"
    "foo foo foo\n"
    "last line\n";
static size_t		 fuzz_input_pos;

int
mf_fgets(SPACE *sp, enum e_spflag spflag)
{
	const char *start, *nl;
	size_t len;

	if (fuzz_input_pos >= sizeof(fuzz_input) - 1) {
		sp->len = 0;
		return (0);
	}
	start = fuzz_input + fuzz_input_pos;
	nl = strchr(start, '\n');
	len = nl != NULL ? (size_t)(nl - start) : strlen(start);
	fuzz_input_pos += nl != NULL ? len + 1 : len;
	sp->append_newline = 1;
	cspace(sp, start, len, spflag);
	linenum++;
	return (1);
}

int
lastline(void)
{

	return (fuzz_input_pos >= sizeof(fuzz_input) - 1);
}

/* ---- per-run state reset --------------------------------------------- */

static void
fuzz_reset(void)
{
	size_t i;

	for (i = 0; i < fuzz_nres; i++)
		regfree(fuzz_res[i]);
	fuzz_nres = 0;
	for (i = 0; i < fuzz_nallocs; i++)
		if (fuzz_allocs[i] != NULL)
			free(fuzz_allocs[i]);
	fuzz_nallocs = 0;
	for (i = 0; i < fuzz_nfds; i++)
		(void)close(fuzz_fds[i]);
	fuzz_nfds = 0;

	/* compile.c / process.c globals and statics (same TU) */
	prog = NULL;
	appends = NULL;
	appendnum = 0;
	match = NULL;
	maxnsub = 0;
	memset(labels, 0, sizeof(labels));
	memset(&HS, 0, sizeof(HS));
	memset(&PS, 0, sizeof(PS));
	memset(&SS, 0, sizeof(SS));
	memset(&YS, 0, sizeof(YS));
	appendx = 0;
	lastaddr = 0;
	sdone = 0;
	defpreg = NULL;
	quit = 0;
}

/*
 * Only b/t commands with a resolved target and the D command (which
 * restarts the cycle without reading input, e.g. the classic "G;D"
 * pattern-space growth loop) can make process() run forever; those are
 * script-level loops, not bugs.  Such scripts are still compiled, just
 * not interpreted.
 */
static int
list_can_loop(const struct s_command *cp, const struct s_command *end)
{

	for (; cp != NULL && cp != end; cp = cp->next) {
		if (cp->code == 'D')
			return (1);
		if ((cp->code == 'b' || cp->code == 't') && cp->u.c != NULL)
			return (1);
		if (cp->code == '{' && list_can_loop(cp->u.c, cp->next))
			return (1);
	}
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int initialized;

	if (!initialized) {
		outfile = fopen("/dev/null", "w");
		if (outfile == NULL)
			outfile = stdout;
		outfname = "fuzz-out";
		initialized = 1;
	}
	if (size < 2 || size > 4096)
		return (0);

	fuzz_script = (const char *)data + 1;
	fuzz_script_len = size - 1;
	fuzz_script_pos = 0;
	rflags = (data[0] & 1) != 0 ? REG_EXTENDED : 0;
	nflag = (data[0] & 2) != 0;
	aflag = 1;			/* defer w files (never opened) */
	inplace = NULL;
	linenum = 0;
	fname = "fuzz-script";

	if (setjmp(fuzz_jmp) == 0) {
		compile();
		if (!list_can_loop(prog, NULL)) {
			fuzz_input_pos = 0;
			linenum = 0;
			process();
		}
	}
	fuzz_reset();
	return (0);
}
