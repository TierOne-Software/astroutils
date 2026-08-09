/*
 * fuzz_grepdata.c — libFuzzer harness for grep's data path: fixed
 * patterns, fuzzed INPUT data, i.e. how untrusted data actually reaches
 * grep(1) when it filters a stream.
 *
 * The harness drives the same entry point grep's main() uses for stdin:
 * procfile("-") (src.freebsd/grep/util.c), with the fuzz input served on
 * fd 0 from a memfd.  This exercises the whole per-line pipeline:
 * grep_fgetln() buffering (src.freebsd/grep/file.c), binary detection,
 * procline()'s regexec loop and match bookkeeping, and the
 * printline()/printline_metadata() output paths.
 *
 * grep's main() is only option parsing; the search loop is re-callable
 * with fresh state (pc/mc are stack-local in procfile(), grep_close()
 * resets the file.c buffers), so no fork or longjmp is needed.  The
 * globals main() would set are initialized once/reset per input by the
 * harness instead; grep.c is linked with -Dmain= so its main() is out
 * of the way.
 *
 * The first input byte selects one of three fixed pattern configurations;
 * the remaining bytes are the searched data:
 *   set 0: plain ERE match (-E), REG_NOSUB
 *   set 1: -o/-n style: match offsets recorded, printline() splits
 *          the line around matches (REG_NOSUB cleared)
 *   set 2: -w word matching: exercises the wbegin/wend wide-char
 *          boundary checks in procline()
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "grep.h"

struct fuzz_set {
	const char	*patstr;	/* pattern source */
	struct pat	 pat;		/* filled in at init */
	regex_t		 rx;		/* compiled pattern */
	int		 cflags;	/* regcomp + procline flags */
	bool		 oflag;
	bool		 wflag;
	bool		 nflag;
};

static struct fuzz_set sets[] = {
	/* -E: nontrivial ERE, REG_NOSUB (no match recording) */
	{ "foo[0-9]{1,3}(bar|baz)+|qux[[:space:]]?[A-Z][a-z]+",
	  { NULL, 0 }, { 0 }, REG_EXTENDED | REG_NOSUB | REG_NEWLINE,
	  false, false, false },
	/* -E -o -n: offsets recorded, printline() walks pc->matches */
	{ "([[:alpha:]_][[:alnum:]_]*=[0-9]+)",
	  { NULL, 0 }, { 0 }, REG_EXTENDED | REG_NEWLINE,
	  true, false, true },
	/* -E -w: word-boundary checks (wbegin/wend wide-char scans) */
	{ "[a-z]+[0-9]",
	  { NULL, 0 }, { 0 }, REG_EXTENDED | REG_NEWLINE,
	  false, true, false },
};
#define NSETS (sizeof(sets) / sizeof(sets[0]))

static int fuzz_initialized;

static void
fuzz_init(void)
{
	char rebuf[RE_ERROR_BUF + 1];
	int devnull, rc;

	for (size_t i = 0; i < NSETS; i++) {
		sets[i].pat.pat = (char *)sets[i].patstr;
		sets[i].pat.len = strlen(sets[i].patstr);
		rc = regcomp(&sets[i].rx, sets[i].patstr, sets[i].cflags);
		if (rc != 0) {
			regerror(rc, &sets[i].rx, rebuf, sizeof(rebuf));
			fprintf(stderr, "fuzz_grepdata: regcomp: %s\n", rebuf);
			abort();
		}
	}

	initqueue();	/* Bflag == 0: queue unused */

	/* matches are printed to stdout; sink them */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0) {
		dup2(devnull, STDOUT_FILENO);
		if (devnull != STDOUT_FILENO)
			close(devnull);
	}

	fuzz_initialized = 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct fuzz_set *set;
	int fd;

	if (size < 2 || size > (1 << 20))
		return 0;
	if (!fuzz_initialized)
		fuzz_init();

	set = &sets[data[0] % NSETS];
	data++;
	size--;

	/* serve the input as stdin */
	fd = memfd_create("fuzz-grepdata", 0);
	if (fd < 0)
		return 0;
	if (write(fd, data, size) != (ssize_t)size) {
		close(fd);
		return 0;
	}
	lseek(fd, 0, SEEK_SET);
	/* memfd_create() may return fd 0 itself once grep_close() has
	 * closed the previous stdin; don't close it out from under us */
	dup2(fd, STDIN_FILENO);	/* grep_close() closes fd 0 when done */
	if (fd != STDIN_FILENO)
		close(fd);

	/* per-input global state (what grep's main() would have set) */
	grepbehave = GREP_EXTENDED;
	cflags = set->cflags;
	eflags = 0;
	r_pattern = (regex_t *)&set->rx;
	pattern = (struct pat *)&set->pat;
	patterns = 1;
	matchall = false;
	oflag = set->oflag;
	wflag = set->wflag;
	nflag = set->nflag;
	xflag = vflag = iflag = false;
	cflag = qflag = sflag = lflag = Lflag = false;
	bflag = Hflag = mflag = lbflag = nullflag = false;
	hflag = true;
	Aflag = Bflag = 0;
	mcount = mlimit = 0;
	fileeol = '\n';
	binbehave = BINFILE_TEXT;	/* -a: search binary data too */
	filebehave = FILE_STDIO;
	devbehave = DEV_READ;
	dirbehave = DIR_READ;
	linkbehave = LINK_SKIP;
	dexclude = dinclude = fexclude = finclude = false;
	fpatterns = dpatterns = 0;
	label = NULL;
	color = NULL;
	file_err = false;

	(void)procfile("-");

	return 0;
}
