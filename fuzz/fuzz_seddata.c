/*
 * fuzz_seddata.c — libFuzzer harness for sed's data path
 * (src.freebsd/sed/process.c): a fixed nontrivial script is compiled
 * once at startup and process() runs over the fuzzed input staged as
 * the input file.  This exercises applies() address matching (line /
 * regex range / $ / !), substitute() and regsub() with backreferences
 * and the g/n/p flags, do_tr() ('y'), lputs() ('l'), the hold-space
 * commands (h/H/G/x), multiline N/P/D, branching (: / t) and groups,
 * and the a/c text commands — all over attacker-controlled data,
 * including embedded NULs (regexec_e uses REG_STARTEND), high bytes,
 * missing trailing newlines, and very long lines.
 *
 * main.c is included directly so the harness can reach its static
 * compilation-unit and file lists (add_compunit/add_file/files/
 * fl_nextp); compile.c, process.c and misc.c are linked as separate
 * objects (defs.h has no include guard, so including more than one
 * sed .c here would not compile).  The single compile-at-init also
 * means compile.c's static label hash and process.c's static defpreg
 * never go stale, and the only per-input state to reset is the file
 * list, infile, quit, and the process.c range/hold state handled by
 * resetstate().  (mf_fgets REPLACEs the pattern space on every read
 * and flush_appends() zeroes appendx/sdone on the way out of every
 * process() run, including the exit(0) paths.)
 *
 * sed's process() calls exit(0) on 'q' and on 'n'/'N' at EOF; the
 * build rewrites exit() (-Dexit=fuzz_skip_exit) to a longjmp back into
 * the harness.  Built with -Dmain=sed_disabled_main so main.c's own
 * main() is out of the way.  The script deliberately avoids 'q', 'w',
 * 'r' and empty REs (which would errx/exit for real) and unbounded
 * backward branches: the only 't' loop uses a 'g' substitution whose
 * replacement cannot reintroduce the pattern, so the script terminates
 * on any input.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>

/* NOLINT: pull main.c in with its static linkage (the compunit and
 * file lists); it includes defs.h/extern.h itself */
#include "../src.freebsd/sed/main.c"

static jmp_buf fuzz_fatal_jmp;

/* replaces exit() inside the sed objects (-Dexit=fuzz_skip_exit) */
void
fuzz_skip_exit(int status)
{
	(void)status;
	longjmp(fuzz_fatal_jmp, 1);
}

/*
 * The fixed script (BRE, no -n).  Kept terminating and non-compounding
 * by construction: every substitution inside the 't top' loop consumes
 * its pattern ('o' -> '0') globally, so the branch is taken at most
 * once per cycle, and D shrinks the pattern space every cycle.  The
 * hold-space and append commands are pinned to single line numbers
 * (1h, 2G, $x, 2a): D's "goto top" re-runs the whole script once per
 * cycle without advancing linenum, so an unguarded H/G pair compounds
 * the hold space exponentially on multiline input (inherent sed
 * semantics — GNU sed behaves the same — but it makes inputs time out
 * instead of finding bugs).
 */
static const char fuzz_script[] =
	"s/foo/bar/g\n"
	"s/\\([a-zA-Z0-9]\\)\\1\\{2,\\}/[\\1\\1]/g\n"
	"y/abc/ABC/\n"
	"/x/l\n"
	"=\n"
	"1h\n"
	"2G\n"
	"$x\n"
	"/GAME/,/END/s/o/0/g\n"
	"/^ZZZ/c\\\n"
	"REPLACED-LINE\n"
	":top\n"
	"s/o/0/g\n"
	"t top\n"
	"$!{\n"
	"N\n"
	"P\n"
	"D\n"
	"}\n"
	"p\n"
	"2a\\\n"
	"---TRAILER---\n";

static int fuzz_initialized;
static int fuzz_fd = -1;
static char fuzz_tmppath[] = "/tmp/fuzz-seddata-XXXXXX";
static struct s_flist *fuzz_fl;	/* saved files-list head (longjmp-safe) */

static void
fuzz_init(void)
{
	fuzz_fd = mkstemp(fuzz_tmppath);
	if (fuzz_fd < 0)
		abort();
	/* sed writes results to stdout; sink them */
	if (freopen("/dev/null", "w", stdout) == NULL)
		abort();
	/* compile the fixed script once; valid by construction, so the
	 * errx paths in compile() are never taken */
	add_compunit(CU_STRING, (char *)fuzz_script);
	compile();
	fuzz_initialized = 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t off;

	/* cap at 4KB: the $!{N;P;D} multiline loop makes the run
	 * quadratic in input size, so large inputs only waste time */
	if (size == 0 || size > 4096)
		return 0;
	if (!fuzz_initialized)
		fuzz_init();

	/* stage the payload as the input file */
	if (ftruncate(fuzz_fd, 0) != 0 || lseek(fuzz_fd, 0, SEEK_SET) < 0)
		return 0;
	for (off = 0; off < size;) {
		ssize_t w = write(fuzz_fd, data + off, size - off);
		if (w <= 0)
			return 0;
		off += (size_t)w;
	}

	if (setjmp(fuzz_fatal_jmp) != 0) {
		/* exit(0) from 'n'/'N' at EOF: mf_fgets() already closed
		 * the input file; drop state and take the next input */
		infile = NULL;
		free(fuzz_fl);
		fuzz_fl = NULL;
		return 0;
	}

	quit = 0;
	nflag = 0;
	infile = NULL;			/* previous run's FILE is closed */
	files = NULL;
	fl_nextp = &files;
	add_file(fuzz_tmppath);
	fuzz_fl = files;
	resetstate();			/* range startlines + hold space */
	process();

	free(fuzz_fl);
	fuzz_fl = NULL;
	return 0;
}
