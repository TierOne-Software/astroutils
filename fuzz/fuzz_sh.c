/*
 * fuzz_sh.c — libFuzzer harness for dash's shell script parser
 * (src.freebsd/sh/parser.c and the lexer in input.c), i.e. the code
 * reached by `sh -n` on an untrusted script: readtoken() word lexing,
 * here-documents, quoting, command substitution, arithmetic
 * tokenization, and alias pushback.
 *
 * parsecmd() is driven in-process over each input with nflag set
 * (parse only; nothing is ever executed).  dash reports syntax errors
 * via error() -> exraise() -> longjmp(handler->loc); the harness
 * installs its own jmploc (the same mechanism main()'s cmdloop uses)
 * and resets parser/input/eval state plus the stack allocator before
 * the next input.
 *
 * Built with the sh sources and -Dmain=sh_disabled_main so main.c's
 * own main() is out of the way; the bltin sources (echo/kill/printf/
 * test) are compiled separately with -DSHELL, exactly like the real
 * sh binary.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>

#include "shell.h"
#include "main.h"
#include "options.h"
#include "output.h"
#include "parser.h"
#include "nodes.h"
#include "input.h"
#include "error.h"
#include "memalloc.h"
#include "var.h"
#include "trap.h"
#include "cd.h"
#include "eval.h"

static struct jmploc fuzz_handler;
static struct stackmark fuzz_smark;
static int fuzz_initialized;

static void
fuzz_init(void)
{
	int devnull;

	initcharset();
	rootpid = getpid();
	rootshell = 1;
	handler = &fuzz_handler;
	INTOFF;
	initvar();
	trap_init();
	pwd_init(0);
	INTON;
	nflag = 1;			/* sh -n: parse only */
	iflag = 0;
	/* syntax errors are reported on stderr; silence them */
	devnull = open("/dev/null", O_WRONLY);
	if (devnull >= 0)
		errout.fd = devnull;
	fuzz_initialized = 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	union node *n;
	char *buf;

	if (size == 0 || size > (1 << 20))
		return 0;
	if (!fuzz_initialized)
		fuzz_init();

	/* setinputstring() strlen()s its input, so NUL-terminate;
	 * embedded NULs simply truncate the script */
	buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	setstackmark(&fuzz_smark);
	if (setjmp(fuzz_handler.loc) != 0) {
		/* error(): unwind like main()'s top-level handler */
		popstackmark(&fuzz_smark);
		reseteval();
		resetinput();
		FORCEINTON;
		free(buf);
		return 0;
	}

	setinputstring(buf, 1);
	while ((n = parsecmd(0)) != NEOF) {
		popstackmark(&fuzz_smark);
		setstackmark(&fuzz_smark);
	}

	/* pops the parsefile pushed by setinputstring(), incl. any
	 * alias pushback strings still attached to it */
	popallfiles();
	popstackmark(&fuzz_smark);
	free(buf);
	return 0;
}
