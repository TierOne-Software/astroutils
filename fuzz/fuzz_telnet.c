/*
 * fuzz_telnet.c — libFuzzer harness for the telnet option-negotiation
 * state machine telrcv() in src.freebsd/telnet/telnet/telnet.c.
 *
 * telrcv() consumes the server-controlled byte stream from the network
 * (netiring) and drives the WILL/WONT/DO/DONT negotiation plus the
 * suboption parsers (TTYPE, TSPEED, LFLOW, LINEMODE/SLC, NEW_ENVIRON,
 * XDISPLOC).  All of that is reachable by a malicious telnet server.
 *
 * telnet.c is #included directly (like fuzz_http.c does) so the harness
 * can reset its internal state (options[], do_dont_resp[], opt_reply,
 * ...) between inputs.  Everything telnet.c normally gets from the rest
 * of the telnet binary (terminal handling, the command processor,
 * tracing, env management, the network fd layer) is stubbed below;
 * Exit()/ExitString()/quit() longjmp back into the harness instead of
 * terminating the fuzzer.  Built without ENCRYPTION/AUTHENTICATION, so
 * the TELOPT_ENCRYPT/TELOPT_AUTHENTICATION suboption arms (libtelnet)
 * are not compiled in.
 *
 * The fuzz bytes are supplied to netiring exactly as if they had been
 * read from the socket; the tty output ring is drained after each
 * telrcv() pass so a full input is always consumed.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <setjmp.h>
#include <ctype.h>

/* NOLINT: pull the state machine in with its static linkage; telnet.c
 * includes its own headers (ring.h, externs.h, ...) first */
#include "../src.freebsd/telnet/telnet/telnet.c"

/* ---- globals the rest of the telnet binary would provide ---------- */
Ring	netoring, netiring, ttyoring, ttyiring;	/* normally main.c */
#include "../src.freebsd/telnet/telnet/baud.h"	/* termspeeds[] (sys_bsd.c) */
int	net = 0, tin = 0, tout = 1, family = AF_INET,
	prettydump = 0, termdata = 0;
char	*hostname = (char *)"fuzz-target";
FILE	*NetTrace = NULL;
struct termio new_tc;		/* externs.h #defines termio -> termios */
#ifndef VSTATUS
cc_t	termAytChar = 030;	/* ^X */
#endif

/* ---- longjmp-based exit stubs (see fuzz_patch.c pattern) ---------- */
static jmp_buf fuzz_exit_jb;

void
Exit(int code)
{
	(void)code;
	longjmp(fuzz_exit_jb, 1);
}

void
ExitString(const char *s, int code)
{
	(void)s; (void)code;
	longjmp(fuzz_exit_jb, 1);
}

void
quit(void)
{
	longjmp(fuzz_exit_jb, 1);
}

/* ---- terminal/window stubs ----------------------------------------- */
void	TerminalFlushOutput(void) {}
void	TerminalNewMode(int f) { (void)f; }
void	TerminalRestoreState(void) {}
void	TerminalSaveState(void) {}
void	TerminalDefaultChars(void) {}
void	TerminalSpeeds(long *ispeed, long *ospeed)
	{ *ispeed = 9600; *ospeed = 9600; }
int	TerminalRead(char *buf, int n) { (void)buf; (void)n; return 0; }
int	TerminalWrite(char *buf, int n) { (void)buf; return n; }
int	TerminalAutoFlush(void) { return 0; }
int	TerminalWindowSize(long *rows, long *cols)
	{ *rows = 24; *cols = 80; return 0; }
int	TerminalSpecialChars(int c) { (void)c; return 1; }
cc_t   *tcval(int i) { static cc_t v; (void)i; return &v; }
int	ttyflush(int drop) { (void)drop; return 0; }

/* ---- mode/command stubs --------------------------------------------- */
void	setconnmode(int f) { (void)f; }
void	setcommandmode(void) {}
int	getconnmode(void) { return 0; }
void	command(int top, const char *tbuf, int tlen)
	{ (void)top; (void)tbuf; (void)tlen; }

/* ---- network stubs ---------------------------------------------------- */
void	init_network(void) {}
int	NetClose(int fd) { (void)fd; return 0; }
int	netflush(void) { return 0; }
int	stilloob(void) { return 0; }
int	SetSockOpt(int fd, int level, int opt, int val)
	{ (void)fd; (void)level; (void)opt; (void)val; return 0; }
void	setneturg(void) {}
int	process_rings(int a, int b, int c, int d, int e, int f)
	{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return 0; }

/* ---- misc init/action stubs ------------------------------------------ */
void	init_sys(void) {}
void	init_terminal(void) {}
void	sys_telnet_init(void) {}
void	tninit(void) {}

/* ---- tracing stubs: keep negotiation quiet, NetTrace stays NULL ------ */
void	printoption(const char *dir, int cmd, int option)
	{ (void)dir; (void)cmd; (void)option; }
void	printsub(char dir, unsigned char *p, int len)
	{ (void)dir; (void)p; (void)len; }
void	optionstatus(void) {}
void	Dump(char dir, unsigned char *p, int len)
	{ (void)dir; (void)p; (void)len; }
void	SetNetTrace(char *s) { (void)s; }

void
upcase(char *s)
{
	for (; *s; s++)
		if (islower((unsigned char)*s))
			*s = toupper((unsigned char)*s);
}

/* ---- environment stubs -------------------------------------------------
 * TERM/DISPLAY are answered so the TTYPE and XDISPLOC suboption paths
 * (gettermname/mklist, env_opt) are exercised. */
void
env_init(void)
{
}

unsigned char *
env_getvalue(const unsigned char *name)
{
	/* must be writable: gettermname()/mklist() upcase() it in place */
	static unsigned char term[] = "xterm";
	static unsigned char display[] = "localhost:0.0";

	if (strcmp((const char *)name, "TERM") == 0)
		return term;
	if (strcmp((const char *)name, "DISPLAY") == 0)
		return display;
	return NULL;
}

unsigned char *
env_default(int init, int welldefined)
{
	(void)init; (void)welldefined;
	return NULL;
}

/* ---- harness ----------------------------------------------------------- */

/* upper bound accepted per run; the real socket reader uses 4 KB chunks */
#define	FUZZ_MAX_INPUT	65536

static void
fuzz_reset(void)
{
	/* telrcv_state, options[], subbuffer, clocks-relevant globals */
	init_telnet();
	memset(do_dont_resp, 0, sizeof(do_dont_resp));
	memset(will_wont_resp, 0, sizeof(will_wont_resp));

	telnetport = 1;		/* >= 0: parse IAC, send replies */
	connected = 1;
	showoptions = 0;
	netdata = 0;
	crmod = 0;
	crlf = 0;
	SYNCHing = 0;
	flushout = 0;
	autoflush = 0;
	autosynch = 0;
	localchars = 0;
	donelclchars = 0;
	donebinarytoggle = 0;
	dontlecho = 0;
	globalmode = 0;
	linemode = 0;
	flushline = 1;
	eight = 0;
	autologin = 0;
#ifdef KLUDGELINEMODE
	kludgelinemode = 1;
#endif
	if (opt_reply != NULL) {	/* leaked by a longjmp'd run */
		free(opt_reply);
		opt_reply = NULL;
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static unsigned char ti_dummy[8];
	unsigned char *ni, *no, *to;
	size_t osz;
	int guard;

	if (size == 0 || size > FUZZ_MAX_INPUT)
		return 0;

	/* replies/echo are bounded well under 4x input + slack */
	osz = size * 4 + 4096;
	ni = malloc(size);
	no = malloc(osz);
	to = malloc(osz);
	if (ni == NULL || no == NULL || to == NULL) {
		free(ni); free(no); free(to);
		return 0;
	}

	ring_init(&netiring, ni, (int)size);
	ring_init(&netoring, no, (int)osz);
	ring_init(&ttyiring, ti_dummy, sizeof(ti_dummy)); /* unused by telrcv() */
	ring_init(&ttyoring, to, (int)osz);

	fuzz_reset();

	if (setjmp(fuzz_exit_jb) == 0) {
		ring_supply_data(&netiring, (unsigned char *)data, (int)size);
		for (guard = 0;
		     ring_full_count(&netiring) > 0 && guard < 4096;
		     guard++) {
			(void)telrcv();
			/* drain tty output so TTYROOM() never stalls us */
			ring_consumed(&ttyoring, ring_full_count(&ttyoring));
		}
	}

	if (opt_reply != NULL) {
		free(opt_reply);
		opt_reply = NULL;
	}
	free(ni);
	free(no);
	free(to);
	return 0;
}
