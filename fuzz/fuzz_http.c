/*
 * fuzz_http.c — libFuzzer harness for libfetch's HTTP parsers
 * (src.freebsd/libfetch/http.c): chunked transfer decoding, reply
 * status/header parsing, and the pure string parsers (mtime, length,
 * range, header lexer, auth challenges).  All of these consume
 * server-controlled input.
 *
 * The .c is included directly so the harness can reach the static
 * parser functions; the connection plumbing comes from common.c.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/* NOLINT: pull the parsers in with their static linkage; http.c
 * includes its own fetch.h/common.h first */
#include "../src.freebsd/libfetch/http.c"

static conn_t *
fuzz_conn(const uint8_t *data, size_t size)
{
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0)
		return NULL;
	/* ignore short writes: a truncated response is a valid case */
	(void)!write(sp[1], data, size);
	close(sp[1]);
	return fetch_reopen(sp[0]);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	conn_t *conn;
	FILE *f;
	http_headerbuf_t hbuf;
	const char *p;
	char *s;

	/* 1. chunked transfer decoding */
	if ((conn = fuzz_conn(data, size)) != NULL) {
		f = http_funopen(conn, 1);
		if (f != NULL) {
			char buf[512];
			while (fread(buf, 1, sizeof(buf), f) > 0)
				;
			fclose(f);
		} else {
			fetch_close(conn);
		}
	}

	/* 2. reply status + header parsing */
	if ((conn = fuzz_conn(data, size)) != NULL) {
		init_http_headerbuf(&hbuf);
		if (http_get_reply(conn) == HTTP_OK) {
			while (http_next_header(conn, &hbuf, &p) == 0)
				;
		}
		clean_http_headerbuf(&hbuf);
		fetch_close(conn);	}

	/* 3. pure string parsers */
	if ((s = malloc(size + 1)) != NULL) {
		time_t mt;
		off_t off, len, sz;
		http_auth_challenges_t cs;
		char *lbuf;
		const char *cp;
		int lex;

		memcpy(s, data, size);
		s[size] = '\0';

		http_parse_mtime(s, &mt);
		http_parse_length(s, &len);
		http_parse_range(s, &off, &len, &sz);

		/* the lexer bounds tokens only by input length */
		if ((lbuf = malloc(size + 2)) != NULL) {
			cp = s;
			do {
				lex = http_header_lex(&cp, lbuf);
			} while (lex == HTTPHL_WORD || lex == HTTPHL_STRING);
			free(lbuf);
		}

		init_http_auth_challenges(&cs);
		http_parse_authenticate(s, &cs);
		clean_http_auth_challenges(&cs);

		free(s);
	}

	return 0;
}
