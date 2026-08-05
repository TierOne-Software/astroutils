/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Daniel Kolesa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef CASPER_CAP_FILEARGS_H
#define CASPER_CAP_FILEARGS_H

#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <libcasper.h>
#include <sys/capsicum.h>
#include <sys/stat.h>

#define FA_OPEN 0
#define FA_REALPATH 1

/*
 * In-process fileargs: on FreeBSD the casper service opens files on
 * behalf of the sandboxed process, so post-enter opens of read-only
 * paths keep working.  Here caph_enter_casper() puts the process in a
 * read-only filesystem lockdown, so a plain open() achieves the same.
 * The rights the caller declared are still applied to each opened fd.
 */
typedef struct fileargs_t {
	uint64_t rights;
	int have_rights;
} fileargs_t;

static inline fileargs_t *fileargs_init(
    int argc, char *argv[], int flags,
    mode_t mode, cap_rights_t *rightsp, int operations
) {
	fileargs_t *fa;

	(void)argc;
	(void)argv;
	(void)mode;
	(void)operations;
	fa = malloc(sizeof(*fa));
	if (fa != NULL) {
		fa->rights = rightsp != NULL ? rightsp->mask : 0;
		fa->have_rights = rightsp != NULL;
		/* callers pass O_RDONLY; anything else is a porting bug */
		if (flags != O_RDONLY)
			abort();
	}
	return fa;
}

static inline fileargs_t *fileargs_cinit(
    cap_channel_t *cas, int argc, char *argv[], int flags, mode_t mode,
    cap_rights_t *rightsp, int operations
) {
	(void)cas;
	return fileargs_init(argc, argv, flags, mode, rightsp, operations);
}

static inline int fileargs_open(fileargs_t *fa, const char *path) {
	int fd;

	fd = open(path, O_RDONLY);
	if (fd >= 0 && fa->have_rights) {
		cap_rights_t rights;

		rights.mask = fa->rights;
		if (caph_rights_limit(fd, &rights) != 0) {
			int e = errno;
			close(fd);
			errno = e;
			return -1;
		}
	}
	return fd;
}

static inline FILE *fileargs_fopen(fileargs_t *fa, const char *path, const char *mode) {
	int fd;
	FILE *f;

	fd = fileargs_open(fa, path);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, mode);
	if (f == NULL) {
		int e = errno;
		close(fd);
		errno = e;
	}
	return f;
}

static inline void fileargs_free(fileargs_t *fa) {
	free(fa);
}

#endif
