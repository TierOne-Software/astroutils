/*
 * fuzz_awkdata.c — libFuzzer harness for awk's data path: a FIXED awk
 * program is interpreted (src.freebsd/awk/run.c execute()/program())
 * over fuzzed input records, exercising lib.c record reading
 * (readrec/readcsvrec, regex RS via fnematch, paragraph mode), field
 * splitting (fldbld/refldbld: whitespace, single-char, regex, FS=""
 * char splitting, --csv quoted fields) and the run-time builtins the
 * program touches (regex ~//, match/substr/gsub/split, printf,
 * arithmetic/conversions).
 *
 * The program is parsed once at init with the same setup main() does
 * (makesymtab/recinit/syminit/arginit, lexprog + yyparse).  Per input,
 * byte 0 selects the program branch (the "mode" variable) and toggles
 * CSV record parsing; byte 1 selects FS/RS (whitespace, comma, tab,
 * colon, FS="", paragraph mode RS="").  The whole input is fed through
 * stdin via a temp file + freopen(), exactly like `awk prog file`.
 *
 * The interpreter is reused across inputs like one long-lived awk
 * process: symtab, parse tree, field table and record buffer persist;
 * the harness resets NR/FNR/FILENAME, the program's own variables and
 * getrec's infile/argno bookkeeping before each run.  awk's `exit`
 * statement is a jump cell handled inside program(), so no process exit
 * happens on the normal path.
 *
 * Fatal runtime errors (FATAL() in lib.c) end in exit(2); the build
 * rewrites exit() (-Dexit=fuzz_skip_exit) to a longjmp back into the
 * harness, which simply abandons the current input — the per-input
 * reset makes the next run clean again.  main.c's own main() is
 * renamed out of the way (-Dmain=awk_disabled_main).
 *
 * Leak checking should be disabled (-detect_leaks=0): a FATAL longjmp
 * abandons in-flight Cells by design.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <locale.h>
#include <setjmp.h>
#include <unistd.h>
#include <fcntl.h>

#include "awk.h"
#include "awkgram.tab.h"

/* globals from main.c / lib.c that awk.h does not export */
extern char	*cmdname;	/* main.c */
extern char	*lexprog;	/* main.c: program text for the lexer */
extern FILE	*yyin;		/* lex.c: program file (NULL w/ lexprog) */
extern FILE	*infile;	/* lib.c: current input file */
extern bool	innew;		/* lib.c: infile not yet read */
extern int	argno;		/* lib.c: current input argument number */

static jmp_buf fuzz_fatal_jmp;

/* replaces exit() inside the awk objects (-Dexit=fuzz_skip_exit) */
void
fuzz_skip_exit(int status)
{
	(void)status;
	longjmp(fuzz_fatal_jmp, 1);
}

/*
 * One fixed program; byte 0 % 3 picks the branch via "mode":
 *   0: field counting, regex match on $1, numeric coercion of $2
 *   1: split on commas, substr/index, gsub, array use
 *   2: match()/RSTART/RLENGTH, printf, mixed arithmetic
 */
static const char fuzz_prog[] =
	"{\n"
	"  if (mode == 0) {\n"
	"    c += NF\n"
	"    if ($1 ~ /x|ab+c/) m++\n"
	"    if (NF > 2) n += $2 + 0\n"
	"  } else if (mode == 1) {\n"
	"    k = split($0, arr, \",\")\n"
	"    s = substr($0, index($0, \":\"), 12)\n"
	"    gsub(/[0-9]+/, \"#\", s)\n"
	"    k += length(s) + length(arr[1])\n"
	"  } else {\n"
	"    if (match($0, /[a-z]+[0-9]*/)) {\n"
	"      r += RSTART + RLENGTH\n"
	"      u = substr($0, RSTART, RLENGTH)\n"
	"    }\n"
	"    printf \"%.4g|%s\\n\", $1 + length($0) * 0.5, substr($0, 1, 3)\n"
	"  }\n"
	"}\n"
	"END { print c + 0, m + 0, n + 0, k + 0, r + 0 }\n";

static const char *const fuzz_fsopts[] = { " ", ",", "\t", ":", "" };

static int fuzz_initialized;
static int fuzz_stdinited;	/* stdinit() done via first run() call */
static char fuzz_tmpl[] = "/tmp/fuzz-awkdata-XXXXXX";

/* program variables that must not carry over between inputs */
static const char *const fuzz_numvars[] = { "mode", "c", "m", "n", "k", "r" };
static const char *const fuzz_strvars[] = { "s", "u" };

static void
fuzz_reset(void)
{
	size_t i;

	/* getrec() bookkeeping (initgetrec() runs only on the 1st call) */
	argno = 1;
	infile = stdin;
	innew = true;

	setfval(nrloc, 0.0);
	setfval(fnrloc, 0.0);
	setsval(lookup("FILENAME", symtab), "");

	for (i = 0; i < sizeof(fuzz_numvars) / sizeof(fuzz_numvars[0]); i++)
		setfval(lookup(fuzz_numvars[i], symtab), 0.0);
	for (i = 0; i < sizeof(fuzz_strvars) / sizeof(fuzz_strvars[0]); i++)
		setsval(lookup(fuzz_strvars[i], symtab), "");
}

static void
fuzz_init(void)
{
	static char *fake_argv[] = { (char *)"awk", NULL };

	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
		setlocale(LC_CTYPE, "");
	setlocale(LC_NUMERIC, "C");
	awk_mb_cur_max = MB_CUR_MAX;

	cmdname = (char *)"fuzz_awkdata";
	srandom(1);
	safe = true;			/* skip envinit(), like main() */

	/* mirror main()'s setup, minus option parsing and envinit() */
	yyin = NULL;
	symtab = makesymtab(NSYMTAB/NSYMTAB);
	recinit(recsize);
	syminit();
	compile_time = COMPILING;
	arginit(1, fake_argv);
	lexprog = (char *)fuzz_prog;
	yyparse();
	if (errorflag != 0) {
		fprintf(stderr, "fuzz_awkdata: fixed program does not parse\n");
		abort();
	}
	compile_time = RUNNING;

	/* silence print/printf output */
	if (freopen("/dev/null", "w", stdout) == NULL) {
		fprintf(stderr, "fuzz_awkdata: cannot redirect stdout\n");
		abort();
	}

	if (mkstemp(fuzz_tmpl) < 0) {
		fprintf(stderr, "fuzz_awkdata: mkstemp failed\n");
		abort();
	}

	fuzz_initialized = 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned b0, b1;
	int fd;
	size_t off;

	if (size == 0 || size > (128 * 1024))
		return 0;
	if (!fuzz_initialized)
		fuzz_init();

	b0 = data[0];
	b1 = size > 1 ? data[1] : 0;

	/* feed the input as awk's stdin */
	fd = open(fuzz_tmpl, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return 0;
	for (off = 0; off < size; ) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) {
			close(fd);
			return 0;
		}
		off += (size_t)w;
	}
	close(fd);
	if (freopen(fuzz_tmpl, "r", stdin) == NULL)
		return 0;

	fuzz_reset();

	CSV = (b0 & 4) != 0;
	setfval(lookup("mode", symtab), (Awkfloat)(b0 % 3));
	if (!CSV) {
		/* csv mode ignores FS/RS, and setsval() on them warns */
		setsval(fsloc, fuzz_fsopts[b1 % 5]);
		setsval(rsloc, b1 % 6 == 5 ? "" : "\n");
	}

	if (setjmp(fuzz_fatal_jmp) != 0) {
		/* FATAL(): abandon this input; next input resets state */
		return 0;
	}

	if (!fuzz_stdinited) {
		run(winner);	/* does stdinit() + execute() + closeall() */
		fuzz_stdinited = 1;
	} else {
		execute(winner);
	}

	return 0;
}
