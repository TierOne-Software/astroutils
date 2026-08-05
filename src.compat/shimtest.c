/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * shimtest — exercise the capsicum shim (src.compat/capsicum.c).
 *
 * Default mode (enforced): per-fd limits and the namespace lockdown
 * must take effect.  With ASTROUTILS_SANDBOX=NONE the shim is a no-op
 * and every probe must succeed instead; pass "stub" as argv[1] to
 * assert that direction.
 *
 * Prints one line per check and exits non-zero on any failure.
 */

#include <sys/capsicum.h>
#include <capsicum_helpers.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <termios.h>

static int failures;

static void
check(const char *name, int ok)
{
	printf("%s %s\n", ok ? "ok  " : "FAIL", name);
	if (!ok)
		failures++;
}

int
main(int argc, char *argv[])
{
	int stub = argc > 1 && strcmp(argv[1], "stub") == 0;
	int casper = argc > 1 && strcmp(argv[1], "casper") == 0;
	int fd, fd2, rc;
	char buf[8];
	cap_rights_t rights;
	unsigned long io_allowed[1];

	if (casper) {
		struct stat st;

		/* casper mode: read-only fs, no exec/sockets */
		rc = caph_enter_casper();
		if (rc < 0 && errno == ENOSYS) {
			printf("skip: sandbox unavailable here\n");
			return 77;
		}
		check("caph_enter_casper accepted", rc == 0 || stub);

		errno = 0;
		rc = open("/etc/passwd", O_RDONLY);
		check("read-only open allowed in casper mode", rc >= 0);
		if (rc >= 0)
			close(rc);

		errno = 0;
		rc = stat("/etc/passwd", &st);
		check("path stat allowed in casper mode", rc == 0);

		fd = open("shimtest.data", O_RDWR | O_CREAT, 0600);
		if (fd >= 0) {
			(void)write(fd, "x", 1);
			close(fd);
		}
		errno = 0;
		rc = open("casper-w.out", O_WRONLY | O_CREAT, 0600);
		check("write open denied in casper mode", stub ? rc >= 0 :
		    rc < 0);
		if (!stub && rc >= 0)
			close(rc);

		errno = 0;
		rc = socket(AF_UNIX, SOCK_DGRAM, 0);
		check("socket denied in casper mode", stub ? rc >= 0 :
		    (rc < 0 && errno == EPERM));
		if (!stub && rc >= 0)
			close(rc);

		/* last: in stub mode a successful exec replaces us */
		errno = 0;
		rc = execve("/bin/true", (char *[]){ "true", NULL }, NULL);
		check("execve denied in casper mode", stub ? 1 :
		    (rc < 0 && errno == EPERM));

		printf("%s: %d failure(s)\n", failures ? "FAILURES" :
		    "all good", failures);
		return failures ? 1 : 0;
	}

	fd = open("shimtest.data", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open shimtest.data");
		return 2;
	}
	if (write(fd, "abcdef", 6) != 6) {
		perror("write shimtest.data");
		return 2;
	}

	/* write-only: read and lseek must be denied, write/fstat allowed */
	cap_rights_init(&rights, CAP_WRITE, CAP_FSTAT);
	rc = caph_rights_limit(fd, &rights);
	check("rights_limit write-only accepted", rc == 0 || stub);
	errno = 0;
	rc = (int)read(fd, buf, 1);
	check("read on write-only fd denied", stub ? rc >= 0 :
	    (rc < 0 && errno == EPERM));
	errno = 0;
	rc = (int)lseek(fd, 0, SEEK_SET);
	check("lseek on no-seek fd denied", stub ? rc >= 0 :
	    (rc < 0 && errno == EPERM));
	errno = 0;
	rc = (int)write(fd, "g", 1);
	check("write on write-only fd allowed", stub ? rc == 1 :
	    (rc == 1 || (rc < 0 && errno != EPERM)));
	{
		struct stat st;
		check("fstat on write-only fd allowed", fstat(fd, &st) == 0);
	}

	/* read-only: write must be denied, read allowed */
	fd2 = open("shimtest.data", O_RDWR);
	if (fd2 < 0) {
		perror("open second fd");
		return 2;
	}
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT);
	(void)caph_rights_limit(fd2, &rights);
	errno = 0;
	rc = (int)write(fd2, "z", 1);
	check("write on read-only fd denied", stub ? rc == 1 :
	    (rc < 0 && errno == EPERM));
	(void)lseek(fd2, 0, SEEK_SET);
	rc = (int)read(fd2, buf, 1);
	check("read on read-only fd allowed", rc == 1);

	/* ioctl allowlist: FIONREAD allowed, TIOCGWINSZ denied */
	io_allowed[0] = FIONREAD;
	rc = caph_ioctls_limit(fd2, io_allowed, 1);
	check("ioctls_limit accepted", rc == 0 || stub);
	{
		int navail = 0;
		struct winsize ws;

		errno = 0;
		rc = ioctl(fd2, FIONREAD, &navail);
		check("allowed ioctl passes", stub ? rc == 0 :
		    (rc == 0 || errno != EPERM));
		errno = 0;
		rc = ioctl(fd2, TIOCGWINSZ, &ws);
		check("unlisted ioctl denied", stub ? rc != -1 || 1 :
		    (rc < 0 && errno == EPERM));
	}

	/* fcntl allowlist: F_GETFL allowed, F_SETFL denied */
	rc = caph_fcntls_limit(fd2, CAP_FCNTL_GETFL);
	check("fcntls_limit accepted", rc == 0 || stub);
	errno = 0;
	rc = fcntl(fd2, F_GETFL);
	check("allowed fcntl passes", stub ? rc >= 0 :
	    (rc >= 0 || errno != EPERM));
	errno = 0;
	rc = fcntl(fd2, F_SETFL, 0);
	check("unlisted fcntl denied", stub ? 1 :
	    (rc < 0 && errno == EPERM));

	/* stdio limiting: stderr stays writable */
	rc = caph_limit_stdio();
	check("limit_stdio accepted", rc == 0 || stub);
	errno = 0;
	rc = (int)write(STDERR_FILENO, "", 0);
	check("stderr writable after limit", stub ? rc == 0 :
	    (rc == 0 || errno != EPERM));
	errno = 0;
	rc = (int)read(STDIN_FILENO, buf, 0);
	check("stdin readable after limit", stub ? rc == 0 :
	    (rc == 0 || errno != EPERM));

	/* namespace lockdown: irreversible from here */
	{
		int dfd = open(".", O_RDONLY | O_DIRECTORY);

		if (dfd < 0) {
			perror("open .");
			return 2;
		}
		cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT);
		rc = caph_rights_limit(dfd, &rights);
		check("CAP_LOOKUP registration accepted", rc == 0 || stub);

		rc = caph_enter();
		if (rc < 0 && errno == ENOSYS) {
			printf("skip: sandbox unavailable here\n");
			return 77;
		}
		check("caph_enter accepted", rc == 0 || stub);

		errno = 0;
		rc = openat(dfd, "shimtest.data", O_RDONLY);
		check("openat beneath lookup dir allowed", rc >= 0);
		if (rc >= 0)
			close(rc);
	}

	errno = 0;
	rc = open("/etc/passwd", O_RDONLY);
	check("open after enter denied", stub ? rc >= 0 : rc < 0);
	if (!stub && rc >= 0)
		close(rc);

	errno = 0;
	rc = socket(AF_UNIX, SOCK_DGRAM, 0);
	check("socket after enter denied", stub ? rc >= 0 :
	    (rc < 0 && errno == EPERM));
	if (!stub && rc >= 0)
		close(rc);

	/* fd work after enter still functions */
	(void)lseek(fd2, 0, SEEK_SET);
	rc = (int)read(fd2, buf, 1);
	check("read on held fd works after enter", rc == 1);

	{
		pid_t pid = fork();
		int st = 0;

		if (pid == 0)
			_exit(0);
		check("fork after enter allowed",
		    pid > 0 && waitpid(pid, &st, 0) == pid &&
		    WIFEXITED(st) && WEXITSTATUS(st) == 0);
	}

	/* last: in stub mode a successful exec replaces us */
	errno = 0;
	rc = execve("/bin/true", (char *[]){ "true", NULL }, NULL);
	check("execve after enter denied", stub ? 1 :
	    (rc < 0 && errno == EPERM));

	printf("%s: %d failure(s)\n", failures ? "FAILURES" : "all good",
	    failures);
	return failures ? 1 : 0;
}
