/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zopen.h"

static void	compress(const char *, const char *, int);
static void	cwarn(const char *, ...) __printflike(1, 2);
static void	cwarnx(const char *, ...) __printflike(1, 2);
static void	decompress(const char *, const char *, int);
static int	permission(const char *);
static void	setfile(int, const char *, const struct stat *);
static FILE	*stdopen(const char *, const char *);
static void	usage(int);

static int eval, force, verbose;

int
main(int argc, char *argv[])
{
	enum {COMPRESS, DECOMPRESS} style;
	size_t len;
	int bits, cat, ch;
	char *p, newname[MAXPATHLEN];

	cat = 0;
	if ((p = strrchr(argv[0], '/')) == NULL)
		p = argv[0];
	else
		++p;
	if (!strcmp(p, "uncompress"))
		style = DECOMPRESS;
	else if (!strcmp(p, "compress"))
		style = COMPRESS;
	else if (!strcmp(p, "zcat")) {
		cat = 1;
		style = DECOMPRESS;
	} else
		errx(1, "unknown program name");

	bits = 0;
	while ((ch = getopt(argc, argv, "b:cdfv")) != -1)
		switch(ch) {
		case 'b':
			bits = strtol(optarg, &p, 10);
			if (*p)
				errx(1, "illegal bit count -- %s", optarg);
			break;
		case 'c':
			cat = 1;
			break;
		case 'd':		/* Backward compatible. */
			style = DECOMPRESS;
			break;
		case 'f':
			force = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			usage(style == COMPRESS);
		}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		switch(style) {
		case COMPRESS:
			(void)compress("/dev/stdin", "/dev/stdout", bits);
			break;
		case DECOMPRESS:
			(void)decompress("/dev/stdin", "/dev/stdout", bits);
			break;
		}
		exit (eval);
	}

	if (cat == 1 && style == COMPRESS && argc > 1)
		errx(1, "the -c option permits only a single file argument");

	for (; *argv; ++argv)
		switch(style) {
		case COMPRESS:
			if (strcmp(*argv, "-") == 0) {
				compress("/dev/stdin", "/dev/stdout", bits);
				break;
			} else if (cat) {
				compress(*argv, "/dev/stdout", bits);
				break;
			}
			if ((p = strrchr(*argv, '.')) != NULL &&
			    !strcmp(p, ".Z")) {
				cwarnx("%s: name already has trailing .Z",
				    *argv);
				break;
			}
			len = strlen(*argv);
			if (len > sizeof(newname) - 3) {
				cwarnx("%s: name too long", *argv);
				break;
			}
			memmove(newname, *argv, len);
			newname[len] = '.';
			newname[len + 1] = 'Z';
			newname[len + 2] = '\0';
			compress(*argv, newname, bits);
			break;
		case DECOMPRESS:
			if (strcmp(*argv, "-") == 0) {
				decompress("/dev/stdin", "/dev/stdout", bits);
				break;
			}
			len = strlen(*argv);
			if ((p = strrchr(*argv, '.')) == NULL ||
			    strcmp(p, ".Z")) {
				if (len > sizeof(newname) - 3) {
					cwarnx("%s: name too long", *argv);
					break;
				}
				memmove(newname, *argv, len);
				newname[len] = '.';
				newname[len + 1] = 'Z';
				newname[len + 2] = '\0';
				decompress(newname,
				    cat ? "/dev/stdout" : *argv, bits);
			} else {
				if (len - 2 > sizeof(newname) - 1) {
					cwarnx("%s: name too long", *argv);
					break;
				}
				memmove(newname, *argv, len - 2);
				newname[len - 2] = '\0';
				decompress(*argv,
				    cat ? "/dev/stdout" : newname, bits);
			}
			break;
		}
	exit (eval);
}

static void
compress(const char *in, const char *out, int bits)
{
	size_t nr;
	struct stat isb, sb;
	FILE *ifp, *ofp;
	int exists, isreg, ofd, oreg;
	u_char buf[1024];

	/*
	 * POSIX says "/dev/stdout" is a 'magic cookie', not a special
	 * file.  On Linux it is a symlink into /proc/self/fd, so stat()
	 * describes the file behind the descriptor instead of a device
	 * node as on FreeBSD; never prompt to overwrite it, and never
	 * manage it as a regular output file.
	 */
	if (strcmp(out, "/dev/stdout") == 0) {
		isreg = oreg = 0;
	} else {
		exists = !stat(out, &sb);
		if (!force && exists && S_ISREG(sb.st_mode) &&
		    !permission(out))
			return;
		isreg = oreg = !exists || S_ISREG(sb.st_mode);
	}

	ifp = ofp = NULL;
	ofd = -1;
	if ((ifp = stdopen(in, "r")) == NULL) {
		cwarn("%s", in);
		return;
	}
	if (stat(in, &isb)) {		/* DON'T FSTAT! */
		cwarn("%s", in);
		goto err;
	}
	if (!S_ISREG(isb.st_mode))
		isreg = 0;

	if ((ofp = zopen(out, "w", bits, &ofd)) == NULL) {
		cwarn("%s", out);
		goto err;
	}
	while ((nr = fread(buf, 1, sizeof(buf), ifp)) != 0)
		if (fwrite(buf, 1, nr, ofp) != nr) {
			cwarn("%s", out);
			goto err;
		}

	if (ferror(ifp)) {
		cwarn("%s", in);
		goto err;
	}
	if (fclose(ifp)) {
		ifp = NULL;
		cwarn("%s", in);
		goto err;
	}
	ifp = NULL;

	if (fclose(ofp)) {
		cwarn("%s", out);
		ofp = NULL;
		goto err;
	}
	ofp = NULL;

	if (isreg) {
		if (ofd >= 0 ? fstat(ofd, &sb) : stat(out, &sb)) {
			cwarn("%s", out);
			goto err;
		}

		if (!force && sb.st_size >= isb.st_size) {
			if (verbose)
		(void)fprintf(stderr, "%s: file would grow; left unmodified\n",
		    in);
			eval = 2;
			if (unlink(out))
				cwarn("%s", out);
			goto err;
		}

		if (ofd >= 0) {
			setfile(ofd, out, &isb);
			(void)close(ofd);
			ofd = -1;
		}

		if (unlink(in))
			cwarn("%s", in);

		if (verbose) {
			(void)fprintf(stderr, "%s: ", out);
			if (isb.st_size > sb.st_size)
				(void)fprintf(stderr, "%.0f%% compression\n",
				    ((float)sb.st_size / isb.st_size) * 100.0);
			else
				(void)fprintf(stderr, "%.0f%% expansion\n",
				    ((float)isb.st_size / sb.st_size) * 100.0);
		}
	}
	if (ofd >= 0)
		(void)close(ofd);
	return;

err:	if (ofp) {
		if (oreg)
			(void)unlink(out);
		(void)fclose(ofp);
	}
	if (ofd >= 0)
		(void)close(ofd);
	if (ifp)
		(void)fclose(ifp);
}

static void
decompress(const char *in, const char *out, int bits)
{
	size_t nr;
	struct stat sb;
	FILE *ifp, *ofp;
	int exists, isreg, ofd, oreg;
	u_char buf[1024];

	/*
	 * POSIX says "/dev/stdout" is a 'magic cookie', not a special
	 * file.  On Linux it is a symlink into /proc/self/fd, so stat()
	 * describes the file behind the descriptor instead of a device
	 * node as on FreeBSD; never prompt to overwrite it, and never
	 * manage it as a regular output file.
	 */
	if (strcmp(out, "/dev/stdout") == 0) {
		isreg = oreg = 0;
	} else {
		exists = !stat(out, &sb);
		if (!force && exists && S_ISREG(sb.st_mode) &&
		    !permission(out))
			return;
		isreg = oreg = !exists || S_ISREG(sb.st_mode);
	}

	ifp = ofp = NULL;
	ofd = -1;
	if ((ifp = zopen(in, "r", bits, NULL)) == NULL) {
		cwarn("%s", in);
		return;
	}
	if (stat(in, &sb)) {
		cwarn("%s", in);
		goto err;
	}
	if (!S_ISREG(sb.st_mode))
		isreg = 0;

	/*
	 * Try to read the first few uncompressed bytes from the input file
	 * before blindly truncating the output file.
	 */
	if ((nr = fread(buf, 1, sizeof(buf), ifp)) == 0) {
		cwarn("%s", in);
		(void)fclose(ifp);
		return;
	}
	if ((ofp = stdopen(out, "w")) == NULL ||
	    (nr != 0 && fwrite(buf, 1, nr, ofp) != nr)) {
		cwarn("%s", out);
		if (ofp)
			(void)fclose(ofp);
		(void)fclose(ifp);
		return;
	}

	/* Pin the output inode; setfile() runs after fclose(). */
	ofd = isreg ? dup(fileno(ofp)) : -1;

	while ((nr = fread(buf, 1, sizeof(buf), ifp)) != 0)
		if (fwrite(buf, 1, nr, ofp) != nr) {
			cwarn("%s", out);
			goto err;
		}

	if (ferror(ifp)) {
		cwarn("%s", in);
		goto err;
	}
	if (fclose(ifp)) {
		ifp = NULL;
		cwarn("%s", in);
		goto err;
	}
	ifp = NULL;

	if (fclose(ofp)) {
		ofp = NULL;
		cwarn("%s", out);
		goto err;
	}

	if (isreg) {
		if (ofd >= 0) {
			setfile(ofd, out, &sb);
			(void)close(ofd);
			ofd = -1;
		}

		if (unlink(in))
			cwarn("%s", in);
	}
	return;

err:	if (ofp) {
		if (oreg)
			(void)unlink(out);
		(void)fclose(ofp);
	}
	if (ofd >= 0)
		(void)close(ofd);
	if (ifp)
		(void)fclose(ifp);
}

static FILE *
stdopen(const char *fname, const char *mode)
{
	FILE *fp;
	int fd;

	/*
	 * POSIX says "/dev/stdout" and "/dev/stdin" are 'magic cookies',
	 * not special files.  On Linux they are symlinks into
	 * /proc/self/fd; opening them by name reopens the file behind
	 * the descriptor, losing its flags and offset and failing with
	 * ENXIO for sockets.  Open a duplicate of the descriptor itself
	 * instead, matching FreeBSD's fdescfs semantics.
	 */
	if (strcmp(fname, "/dev/stdout") == 0)
		fd = STDOUT_FILENO;
	else if (strcmp(fname, "/dev/stdin") == 0)
		fd = STDIN_FILENO;
	else if (*mode == 'w') {
		/*
		 * Do not follow symlinks when opening the output: the
		 * path was checked with stat() above, and following a
		 * symlink swapped in since then would truncate an
		 * unrelated file.
		 */
		if ((fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC |
		    O_NOFOLLOW, 0666)) == -1)
			return (NULL);
		if ((fp = fdopen(fd, mode)) == NULL)
			(void)close(fd);
		return (fp);
	} else
		return (fopen(fname, mode));
	if ((fd = dup(fd)) == -1)
		return (NULL);
	return (fdopen(fd, mode));
}

/*
 * Copy timestamps, ownership and mode from fs to the output.  The fd
 * refers to the file we just wrote, so a symlink or rename swapped in
 * at the path cannot redirect the metadata updates to another file;
 * name is only used in warning messages.
 */
static void
setfile(int fd, const char *name, const struct stat *fs)
{
	struct stat sb;
	static struct timespec tspec[2];

	sb = *fs;
	sb.st_mode &= S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO;

	tspec[0] = sb.st_atim;
	tspec[1] = sb.st_mtim;
	if (futimens(fd, tspec))
		cwarn("futimens: %s", name);

	/*
	 * Changing the ownership probably won't succeed, unless we're root
	 * or POSIX_CHOWN_RESTRICTED is not set.  Set uid/gid before setting
	 * the mode; current BSD behavior is to remove all setuid bits on
	 * chown.  If chown fails, lose setuid/setgid bits.
	 */
	if (fchown(fd, sb.st_uid, sb.st_gid)) {
		if (errno != EPERM)
			cwarn("fchown: %s", name);
		sb.st_mode &= ~(S_ISUID|S_ISGID);
	}
	if (fchmod(fd, sb.st_mode))
		cwarn("fchmod: %s", name);
}

static int
permission(const char *fname)
{
	int ch, first;

	if (!isatty(fileno(stderr)))
		return (0);
	(void)fprintf(stderr, "overwrite %s? ", fname);
	first = ch = getchar();
	while (ch != '\n' && ch != EOF)
		ch = getchar();
	return (first == 'y');
}

static void
usage(int iscompress)
{
	if (iscompress)
		(void)fprintf(stderr,
		    "usage: compress [-cfv] [-b bits] [file ...]\n");
	else
		(void)fprintf(stderr,
		    "usage: uncompress [-c] [-b bits] [file ...]\n");
	exit(1);
}

static void
cwarnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	eval = 1;
}

static void
cwarn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
	eval = 1;
}
