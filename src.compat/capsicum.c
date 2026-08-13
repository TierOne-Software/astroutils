/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Capsicum compatibility shim for Linux, implemented with:
 *
 *   - Landlock: caph_enter() installs a ruleset handling every
 *     filesystem access type the running kernel's ABI knows, with zero
 *     allowed rules -- a total path-based filesystem lockdown, matching
 *     FreeBSD capability mode for tools that open everything first.
 *   - seccomp-BPF: a namespace denylist (open/execve/socket/connect/
 *     ptrace/mount/... -> EPERM) plus per-fd rights enforcement via
 *     argument-inspecting filters installed by the caph_*_limit calls.
 *
 * Enforcement is required by default: if the kernel lacks Landlock or
 * seccomp, caph_enter() fails and the calling tool exits visibly via
 * its err(1) path.  Setting ASTROUTILS_SANDBOX=NONE in the environment
 * restores the historical no-op stub behavior.
 *
 * Known limitations (compared to real Capsicum):
 *   - fd rights are keyed on the fd *number*; the kernel does not let a
 *     seccomp filter follow a file description across dup(), so a
 *     dup'd copy of a limited fd escapes the limit, and a closed-then-
 *     reused fd number inherits a stale limit (over-restriction, the
 *     safe direction).  The namespace lockdown is the hard boundary;
 *     per-fd rights are best-effort hardening on top.
 *   - Casper services (cap_net, cap_syslog, ...) remain in-process
 *     stubs; caph_enter_casper() enforces exactly like caph_enter().
 */

#include <sys/capsicum.h>
#include <capsicum_helpers.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>

/* ------------------------------------------------------------------ */
/* environment escape hatch                                            */
/* ------------------------------------------------------------------ */

static int
sandbox_disabled(void)
{
	const char *e = getenv("ASTROUTILS_SANDBOX");

	return e != NULL && strcmp(e, "NONE") == 0;
}

/*
 * Enforcement modes.  caph_enter() is a full lockdown: no path-based
 * filesystem access at all post-enter (tools open everything first).
 * caph_enter_casper() mirrors what casper's fileargs service brokers on
 * FreeBSD: read-only opens of anything, no writes, no exec, no
 * sockets.  The distinction is what lets md5 -c / tail -F keep working.
 */
#define MODE_FULL	0
#define MODE_CASPER	1
#define MODE_PATHS	2

/*
 * Path-scoped mode (caph_enter_paths): path-based filesystem access is
 * confined by Landlock to the directories registered with
 * caph_allow_path(), with full read/write/create/delete beneath them;
 * the seccomp filter still denies exec/sockets/process control.
 */
static int allow_fds[8];
static int nallow_fds;

/*
 * Directories whose fd received CAP_LOOKUP via caph_rights_limit()
 * (e.g. write(1)'s /dev fd): openat/newfstatat/statx beneath them stay
 * permitted post-enter, and the Landlock ruleset excepts them.
 * Registration after entering is impossible and fails the call.
 */
static int lookup_fds[8];
static int lookup_nfds;
static int sandbox_entered;

/*
 * Pre-enter fd-limit registry.  Every caph_*_limit call made before
 * caph_enter() is accumulated here and flushed as one filter per type
 * at enter time, instead of installing 1-3 stacked filters per call
 * (~110us each; tools like tee/hexdump otherwise carry 10-13).
 * Calls made after entering still install immediately.
 */
#define LDENY_RD	0x01	/* read/readv/pread* */
#define LDENY_WR	0x02	/* write/writev/pwrite* */
#define LDENY_SEEK	0x04	/* lseek */
#define LDENY_TRUNC	0x08	/* ftruncate */
#define LDENY_FSYNC	0x10	/* fsync/fdatasync */
#define LDENY_SHUT	0x20	/* shutdown */
#define LDENY_MMAP	0x40	/* mmap with this fd */

struct fd_limit {
	int fd;
	uint64_t deny;
	long ioctls[16];
	int nioctls;	/* -1: unrestricted */
	long fcntls[6];
	int nfcntls;	/* -1: unrestricted */
};
static struct fd_limit fd_limits[32];
static int nfd_limits;

static struct fd_limit *
lim_find(int fd)
{
	int i;

	for (i = 0; i < nfd_limits; i++)
		if (fd_limits[i].fd == fd)
			return &fd_limits[i];
	if (nfd_limits == (int)(sizeof(fd_limits) / sizeof(fd_limits[0])))
		return NULL;
	fd_limits[nfd_limits].fd = fd;
	fd_limits[nfd_limits].deny = 0;
	fd_limits[nfd_limits].nioctls = -1;
	fd_limits[nfd_limits].nfcntls = -1;
	return &fd_limits[nfd_limits++];
}

/* intersect a registered allowlist with a new one (-1: adopt) */
static int
lim_merge(long *dst, int *dn, const long *src, size_t sn)
{
	size_t i;
	size_t j;
	int n;

	if (*dn < 0) {
		if (sn > 16)
			sn = 16;
		for (i = 0; i < sn; i++)
			dst[i] = src[i];
		*dn = (int)sn;
		return 0;
	}
	n = 0;
	for (i = 0; i < (size_t)*dn; i++) {
		for (j = 0; j < sn; j++)
			if (dst[i] == src[j]) {
				dst[n++] = dst[i];
				break;
			}
	}
	*dn = n;
	return 0;
}

/* ------------------------------------------------------------------ */
/* rights lists (varargs, CU_CAP_END sentinel appended by the macros)  */
/* ------------------------------------------------------------------ */

static uint64_t
collect_rights(uint64_t first, va_list ap)
{
	uint64_t m = 0, r = first;

	while (r != CU_CAP_END) {
		m |= r;
		r = va_arg(ap, uint64_t);
	}
	return m;
}

cap_rights_t *
cu_cap_rights_init(cap_rights_t *rights, ...)
{
	va_list ap;

	va_start(ap, rights);
	rights->mask = collect_rights(va_arg(ap, uint64_t), ap);
	va_end(ap);
	return rights;
}

cap_rights_t *
cu_cap_rights_set(cap_rights_t *rights, ...)
{
	va_list ap;

	va_start(ap, rights);
	rights->mask |= collect_rights(va_arg(ap, uint64_t), ap);
	va_end(ap);
	return rights;
}

cap_rights_t *
cu_cap_rights_clear(cap_rights_t *rights, ...)
{
	va_list ap;

	va_start(ap, rights);
	rights->mask &= ~collect_rights(va_arg(ap, uint64_t), ap);
	va_end(ap);
	return rights;
}

int
cu_cap_rights_is_set(const cap_rights_t *rights, ...)
{
	uint64_t want;
	va_list ap;

	va_start(ap, rights);
	want = collect_rights(va_arg(ap, uint64_t), ap);
	va_end(ap);
	return (rights->mask & want) == want;
}

/* ------------------------------------------------------------------ */
/* tiny BPF assembler                                                  */
/* ------------------------------------------------------------------ */

struct bpf_prog {
	struct sock_filter insns[512];
	size_t len;
};

static void
emit(struct bpf_prog *p, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
	if (p->len >= sizeof(p->insns) / sizeof(p->insns[0]))
		abort(); /* a shim program outgrew the buffer: shim bug */
	p->insns[p->len++] =
	    (struct sock_filter){ .code = code, .jt = jt, .jf = jf, .k = k };
}

#define E_STMT(c, k)	emit(p, (c), 0, 0, (k))
#define E_JUMP(c, k, t, f) emit(p, (c), (t), (f), (k))

#define E_LD(off)	E_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define E_JEQ(v, t, f)	E_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (v), (t), (f))
#define E_RET(k)	E_STMT(BPF_RET | BPF_K, (k))

#define LD_NR		E_LD(offsetof(struct seccomp_data, nr))
#define LD_ARG(n)	E_LD(offsetof(struct seccomp_data, args[n]))
#define RET_ALLOW	E_RET(SECCOMP_RET_ALLOW)
#define RET_EPERM	E_RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define RET_KILL	E_RET(SECCOMP_RET_KILL_PROCESS)

static int
seccomp_load(const struct bpf_prog *p)
{
	struct sock_fprog prog = {
	    .len = (unsigned short)p->len,
	    .filter = (struct sock_filter *)p->insns,
	};

	/* filter installs are allowed before caph_enter(); nnp is the
	 * unprivileged precondition for seccomp and is sticky */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	if (getenv("CU_SANDBOX_DEBUG") != NULL)
		(void)!write(2, "seccomp_load\n", 13);
	return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

/*
 * Architecture guard: a mismatched arch means a 32-bit or foreign ABI
 * syscall, whose numbers do not match our tables -- kill rather than
 * risk a confused-deputy allow.
 */
#if defined(__x86_64__)
#define CU_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CU_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define CU_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
#define CU_AUDIT_ARCH AUDIT_ARCH_RISCV64
#elif defined(__i386__)
#define CU_AUDIT_ARCH AUDIT_ARCH_I386
#else
#error "capsicum shim: unsupported architecture"
#endif

static void
emit_arch_guard(struct bpf_prog *p)
{
	E_LD(offsetof(struct seccomp_data, arch));
	E_JEQ(CU_AUDIT_ARCH, 1, 0);
	RET_KILL;
}

/* ------------------------------------------------------------------ */
/* namespace denylist (installed by caph_enter)                        */
/* ------------------------------------------------------------------ */

/*
 * Everything not listed here stays allowed, so post-enter fd work
 * (read/write/lseek/dup/fstat/mmap/poll/signals/exit...) keeps working.
 * seccomp(2) itself stays allowed: limit calls made after caph_enter()
 * need to stack further (only ever more restrictive) filters.
 *
 * In casper mode, path-read syscalls (stat/readlink/access family)
 * stay allowed and open/openat are allowed for read-only flags -- this
 * mirrors what casper's fileargs service brokers on FreeBSD.  Writes,
 * exec and sockets stay denied in both modes.
 */

#define E_AND(v)	E_STMT(BPF_ALU | BPF_AND | BPF_K, (v))

/*
 * 9-insn block: allow `nr` only with read-only open flags (flags live
 * in argument `argn`), deny otherwise.
 */
static void
emit_openflags_check(struct bpf_prog *p, int nr, int argn)
{
	E_JEQ((uint32_t)nr, 0, 8);	/* no match -> next block */
	LD_ARG(argn);
	E_AND(O_ACCMODE);
	E_JEQ(O_RDONLY, 0, 3);		/* not O_RDONLY -> RET_EPERM */
	LD_ARG(argn);
	E_AND(O_CREAT | O_TRUNC | O_APPEND | O_TMPFILE);
	E_JEQ(0, 1, 0);			/* clean -> RET_ALLOW */
	RET_EPERM;
	RET_ALLOW;
}

/*
 * Deny `nr` unless arg0 is a registered lookup fd (CAP_LOOKUP dirs).
 */
static void
emit_lookup_check(struct bpf_prog *p, int nr)
{
	int j;

	E_JEQ((uint32_t)nr, 0, (uint8_t)(lookup_nfds + 3));
	LD_ARG(0);
	for (j = 0; j < lookup_nfds; j++)
		E_JEQ((uint32_t)lookup_fds[j], (uint8_t)(lookup_nfds - j), 0);
	RET_EPERM;
	RET_ALLOW;
}

static int
install_namespace_filter(int mode)
{
	struct bpf_prog pbuf = { .len = 0 };
	struct bpf_prog *p = &pbuf;

	emit_arch_guard(p);
	LD_NR;

/* if nr == X, fall through to RET_EPERM; else skip it */
#define DENY(X) do { E_JEQ((X), 0, 1); RET_EPERM; } while (0)

#ifdef SYS_open
	if (mode == MODE_CASPER)
		emit_openflags_check(p, SYS_open, 1);
	else if (mode == MODE_FULL)
		DENY(SYS_open);
#endif
#ifdef SYS_openat
	if (mode == MODE_CASPER)
		emit_openflags_check(p, SYS_openat, 2);
	else if (mode == MODE_FULL) {
		if (lookup_nfds > 0)
			emit_lookup_check(p, SYS_openat);
		else
			DENY(SYS_openat);
	}
#endif
	if (mode == MODE_FULL) {
#ifdef SYS_newfstatat
		if (lookup_nfds > 0)
			emit_lookup_check(p, SYS_newfstatat);
		else
			DENY(SYS_newfstatat);
#endif
#ifdef SYS_statx
		if (lookup_nfds > 0)
			emit_lookup_check(p, SYS_statx);
		else
			DENY(SYS_statx);
#endif
	}
#ifdef SYS_openat2
	if (mode != MODE_PATHS)
		DENY(SYS_openat2);
#endif
#ifdef SYS_creat
	if (mode != MODE_PATHS)
		DENY(SYS_creat);
#endif
	/* path-mutation syscalls: denied except in path-scoped mode,
	 * where Landlock confines them to the allowed directories */
	if (mode != MODE_PATHS) {
#ifdef SYS_link
	DENY(SYS_link);
#endif
#ifdef SYS_linkat
	DENY(SYS_linkat);
#endif
#ifdef SYS_symlink
	DENY(SYS_symlink);
#endif
#ifdef SYS_symlinkat
	DENY(SYS_symlinkat);
#endif
#ifdef SYS_rename
	DENY(SYS_rename);
#endif
#ifdef SYS_renameat
	DENY(SYS_renameat);
#endif
#ifdef SYS_renameat2
	DENY(SYS_renameat2);
#endif
#ifdef SYS_mkdir
	DENY(SYS_mkdir);
#endif
#ifdef SYS_mkdirat
	DENY(SYS_mkdirat);
#endif
#ifdef SYS_rmdir
	DENY(SYS_rmdir);
#endif
#ifdef SYS_unlink
	DENY(SYS_unlink);
#endif
#ifdef SYS_unlinkat
	DENY(SYS_unlinkat);
#endif
#ifdef SYS_mknod
	DENY(SYS_mknod);
#endif
#ifdef SYS_mknodat
	DENY(SYS_mknodat);
#endif
#ifdef SYS_chdir
	DENY(SYS_chdir);
#endif
#ifdef SYS_chroot
	DENY(SYS_chroot);
#endif
#ifdef SYS_mount
	DENY(SYS_mount);
#endif
#ifdef SYS_umount2
	DENY(SYS_umount2);
#endif
#ifdef SYS_pivot_root
	DENY(SYS_pivot_root);
#endif
#ifdef SYS_fsopen
	DENY(SYS_fsopen);
#endif
#ifdef SYS_fsmount
	DENY(SYS_fsmount);
#endif
#ifdef SYS_fsconfig
	DENY(SYS_fsconfig);
#endif
#ifdef SYS_fspick
	DENY(SYS_fspick);
#endif
#ifdef SYS_move_mount
	DENY(SYS_move_mount);
#endif
#ifdef SYS_open_tree
	DENY(SYS_open_tree);
#endif
#ifdef SYS_mount_setattr
	DENY(SYS_mount_setattr);
#endif
#ifdef SYS_swapon
	DENY(SYS_swapon);
#endif
#ifdef SYS_swapoff
	DENY(SYS_swapoff);
#endif
#ifdef SYS_truncate
	DENY(SYS_truncate);
#endif
#ifdef SYS_utime
	DENY(SYS_utime);
#endif
#ifdef SYS_utimes
	DENY(SYS_utimes);
#endif
#ifdef SYS_utimensat
	DENY(SYS_utimensat);
#endif
#ifdef SYS_futimesat
	DENY(SYS_futimesat);
#endif
	} /* !MODE_PATHS (path mutation) */
	/* path-read syscalls: denied in full mode, allowed in casper mode */
	if (mode == MODE_FULL) {
#ifdef SYS_access
		DENY(SYS_access);
#endif
#ifdef SYS_faccessat
		DENY(SYS_faccessat);
#endif
#ifdef SYS_faccessat2
		DENY(SYS_faccessat2);
#endif
#ifdef SYS_stat
		DENY(SYS_stat);
#endif
#ifdef SYS_lstat
		DENY(SYS_lstat);
#endif
#ifdef SYS_readlink
		DENY(SYS_readlink);
#endif
#ifdef SYS_readlinkat
		DENY(SYS_readlinkat);
#endif
#ifdef SYS_getcwd
		DENY(SYS_getcwd);
#endif
	}
#ifdef SYS_inotify_add_watch
	DENY(SYS_inotify_add_watch);
#endif
#ifdef SYS_fanotify_mark
	DENY(SYS_fanotify_mark);
#endif
#ifdef SYS_name_to_handle_at
	DENY(SYS_name_to_handle_at);
#endif
#ifdef SYS_open_by_handle_at
	DENY(SYS_open_by_handle_at);
#endif
#ifdef SYS_execve
	DENY(SYS_execve);
#endif
#ifdef SYS_execveat
	DENY(SYS_execveat);
#endif
#ifdef SYS_socket
	DENY(SYS_socket);
#endif
#ifdef SYS_socketpair
	DENY(SYS_socketpair);
#endif
#ifdef SYS_connect
	DENY(SYS_connect);
#endif
#ifdef SYS_bind
	DENY(SYS_bind);
#endif
#ifdef SYS_listen
	DENY(SYS_listen);
#endif
#ifdef SYS_accept
	DENY(SYS_accept);
#endif
#ifdef SYS_accept4
	DENY(SYS_accept4);
#endif
#ifdef SYS_ptrace
	DENY(SYS_ptrace);
#endif
#ifdef SYS_process_vm_readv
	DENY(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
	DENY(SYS_process_vm_writev);
#endif
#ifdef SYS_kcmp
	DENY(SYS_kcmp);
#endif
#ifdef SYS_kexec_load
	DENY(SYS_kexec_load);
#endif
#ifdef SYS_kexec_file_load
	DENY(SYS_kexec_file_load);
#endif
#ifdef SYS_init_module
	DENY(SYS_init_module);
#endif
#ifdef SYS_finit_module
	DENY(SYS_finit_module);
#endif
#ifdef SYS_delete_module
	DENY(SYS_delete_module);
#endif
#ifdef SYS_bpf
	DENY(SYS_bpf);
#endif
#ifdef SYS_perf_event_open
	DENY(SYS_perf_event_open);
#endif
#ifdef SYS_io_uring_setup
	DENY(SYS_io_uring_setup);
#endif
#ifdef SYS_setns
	DENY(SYS_setns);
#endif
#ifdef SYS_unshare
	DENY(SYS_unshare);
#endif
#ifdef SYS_acct
	DENY(SYS_acct);
#endif
#ifdef SYS_add_key
	DENY(SYS_add_key);
#endif
#ifdef SYS_keyctl
	DENY(SYS_keyctl);
#endif
#ifdef SYS_request_key
	DENY(SYS_request_key);
#endif
#ifdef SYS_quotactl
	DENY(SYS_quotactl);
#endif

#undef DENY

	RET_ALLOW;
	return seccomp_load(p);
}

/* ------------------------------------------------------------------ */
/* Landlock filesystem lockdown                                        */
/* ------------------------------------------------------------------ */

static int
landlock_lockdown(int mode)
{
#if defined(SYS_landlock_create_ruleset) && defined(SYS_landlock_restrict_self)
	struct landlock_ruleset_attr attr;
	uint64_t handled, mutate;
	int abi, ruleset, i;

	abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
	    LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1) {
		errno = ENOSYS;
		return -1;
	}

	mutate = LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR |
	    LANDLOCK_ACCESS_FS_MAKE_DIR |
	    LANDLOCK_ACCESS_FS_MAKE_REG |
	    LANDLOCK_ACCESS_FS_MAKE_SOCK |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO |
	    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		mutate |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
	if (abi >= 3)
		mutate |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif

	/*
	 * Full mode restricts every fs access the ABI knows; casper mode
	 * restricts only mutation, leaving reads/lookups/execute free.
	 * Path-scoped mode restricts everything, with the registered
	 * directories excepted by rules below.
	 */
	if (mode == MODE_CASPER)
		handled = mutate;
	else
		handled = mutate | LANDLOCK_ACCESS_FS_EXECUTE |
		    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = handled;
	ruleset = (int)syscall(SYS_landlock_create_ruleset, &attr,
	    sizeof(attr), 0);
	if (ruleset < 0)
		return -1;

	/*
	 * Full mode: except the registered CAP_LOOKUP directories (which
	 * keep full access beneath them); with no registrations there are
	 * no rules at all and everything handled is denied.  Casper mode
	 * needs no rules: reads are not handled, writes are all denied.
	 * Path-scoped mode: allow everything handled beneath each
	 * registered directory, deny it elsewhere.
	 */
	for (i = 0; mode == MODE_FULL && i < lookup_nfds; i++) {
		struct landlock_path_beneath_attr pb;

		memset(&pb, 0, sizeof(pb));
		pb.allowed_access = handled;
		pb.parent_fd = lookup_fds[i];
		if (syscall(SYS_landlock_add_rule, ruleset,
		    LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
			int e = errno;
			(void)close(ruleset);
			errno = e;
			return -1;
		}
	}
	for (i = 0; mode == MODE_PATHS && i < nallow_fds; i++) {
		struct landlock_path_beneath_attr pb;

		memset(&pb, 0, sizeof(pb));
		pb.allowed_access = handled;
		pb.parent_fd = allow_fds[i];
		if (syscall(SYS_landlock_add_rule, ruleset,
		    LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0) {
			int e = errno;
			(void)close(ruleset);
			errno = e;
			return -1;
		}
	}

	if (syscall(SYS_landlock_restrict_self, ruleset, 0) < 0) {
		int e = errno;
		(void)close(ruleset);
		errno = e;
		return -1;
	}
	(void)close(ruleset);
	return 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* per-fd rights filters                                               */
/* ------------------------------------------------------------------ */

/*
 * Emit entries denying `nr` when its fd argument (arg `argn`) equals
 * the entry's fd.  Each entry is 3 insns.  A syscall matching no entry
 * falls through to RET_ALLOW; an fd match jumps to the RET_EPERM at
 * the end.
 */
struct deny_ent {
	int nr;
	int argn;
	int fd;
};

static void
emit_fd_deny(struct bpf_prog *p, const struct deny_ent *ents, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		/* nr matches -> fall through to the fd check; else skip it */
		E_JEQ((uint32_t)ents[i].nr, 0, 2);
		LD_ARG(ents[i].argn);
		/* fd matches -> jump to RET_EPERM; else next entry */
		E_JEQ((uint32_t)ents[i].fd, (uint8_t)(3 * (n - i) - 2), 0);
	}
	RET_ALLOW;
	RET_EPERM;
}

/* install one filter denying the given syscalls on fd; noop if n == 0 */
static int
limit_fd_syscalls(int fd, struct deny_ent *ents, size_t n)
{
	struct bpf_prog pbuf = { .len = 0 };
	struct bpf_prog *p = &pbuf;
	size_t i;

	if (n == 0)
		return 0;
	for (i = 0; i < n; i++)
		ents[i].fd = fd;
	emit_arch_guard(p);
	LD_NR;
	emit_fd_deny(p, ents, n);
	return seccomp_load(p);
}

/*
 * Emit a filter denying `nr` on `fd` unless arg1 is in the allowed
 * list (used for ioctl and fcntl).  Layout: the checks, then
 * RET_EPERM, then RET_ALLOW; every "not ours / explicitly allowed"
 * jump lands on RET_ALLOW, falling off the end hits RET_EPERM.
 */
static int
limit_fd_arg1(int fd, int nr, const long *allowed, size_t n)
{
	struct bpf_prog pbuf = { .len = 0 };
	struct bpf_prog *p = &pbuf;
	size_t i, idx, allow_idx, start;

	emit_arch_guard(p);
	LD_NR;
	start = p->len;
	E_JEQ((uint32_t)nr, 0, 0);	/* jf patched to allow */
	LD_ARG(0);
	E_JEQ((uint32_t)fd, 0, 0);	/* jf patched to allow */
	LD_ARG(1);
	for (i = 0; i < n; i++)
		E_JEQ((uint32_t)allowed[i], 0, 0); /* jt patched to allow */
	RET_EPERM;
	allow_idx = p->len;
	RET_ALLOW;

	/* nr mismatch -> allow */
	idx = start;
	p->insns[idx].jf = (uint8_t)(allow_idx - idx - 1);
	idx += 2; /* past LD_ARG(0) */
	/* fd mismatch -> allow */
	p->insns[idx].jf = (uint8_t)(allow_idx - idx - 1);
	idx += 2; /* past LD_ARG(1) */
	for (i = 0; i < n; i++, idx++)
		p->insns[idx].jt = (uint8_t)(allow_idx - idx - 1);
	return seccomp_load(p);
}

/* ------------------------------------------------------------------ */
/* flushing the pre-enter registry (one filter per type)               */
/* ------------------------------------------------------------------ */

/* entries are 3 insns each; keep jumps well inside the 8-bit range */
#define FLUSH_CHUNK 60

static int
install_entry_chunk(const struct deny_ent *ents, size_t n)
{
	struct bpf_prog pbuf = { .len = 0 };
	struct bpf_prog *p = &pbuf;

	emit_arch_guard(p);
	LD_NR;
	emit_fd_deny(p, ents, n);
	return seccomp_load(p);
}

/*
 * One filter for syscall `nr` covering every registered fd with an
 * allowlist (ioctl or fcntl).  Per fd block: fd mismatch falls to the
 * next block; a listed arg1 jumps to the shared RET_ALLOW; anything
 * else on a registered fd is EPERM.
 */
static int
install_arg1_limits(int nr, int which)
{
	struct bpf_prog pbuf = { .len = 0 };
	struct bpf_prog *p = &pbuf;
	size_t cmd_idx[96];
	size_t ncmd = 0, allow_idx, nr_idx, prev_fd_idx = (size_t)-1;
	int i, j, nblocks = 0;

	for (i = 0; i < nfd_limits; i++)
		if ((which == 0 ? fd_limits[i].nioctls :
		    fd_limits[i].nfcntls) >= 0)
			nblocks++;
	if (nblocks == 0)
		return 0;

	emit_arch_guard(p);
	LD_NR;
	nr_idx = p->len;
	E_JEQ((uint32_t)nr, 0, 0);	/* jf -> ALLOW, patched */
	for (i = 0; i < nfd_limits; i++) {
		const long *list;
		int nlist;

		nlist = which == 0 ? fd_limits[i].nioctls :
		    fd_limits[i].nfcntls;
		if (nlist < 0)
			continue;
		list = which == 0 ? fd_limits[i].ioctls :
		    fd_limits[i].fcntls;
		/* the previous block's fd-mismatch jump lands here */
		if (prev_fd_idx != (size_t)-1)
			p->insns[prev_fd_idx].jf =
			    (uint8_t)(p->len - prev_fd_idx - 1);
		LD_ARG(0);
		prev_fd_idx = p->len;
		E_JEQ((uint32_t)fd_limits[i].fd, 0, 0); /* jf patched */
		LD_ARG(1);
		for (j = 0; j < nlist; j++) {
			cmd_idx[ncmd++] = p->len;
			E_JEQ((uint32_t)list[j], 0, 0); /* jt patched */
		}
		RET_EPERM;
	}
	allow_idx = p->len;
	RET_ALLOW;

	/* the last block's fd mismatch -> ALLOW */
	p->insns[prev_fd_idx].jf =
	    (uint8_t)(allow_idx - prev_fd_idx - 1);
	p->insns[nr_idx].jf = (uint8_t)(allow_idx - nr_idx - 1);
	for (i = 0; i < (int)ncmd; i++)
		p->insns[cmd_idx[i]].jt =
		    (uint8_t)(allow_idx - cmd_idx[i] - 1);

	if (allow_idx > 200) {
		/* 8-bit jump budget exhausted: refuse rather than risk a
		 * mispatched filter (no real tool gets near this) */
		errno = ENOSPC;
		return -1;
	}
	return seccomp_load(p);
}

/*
 * Flush the pre-enter registry: one fd-rights filter (chunked), one
 * ioctl filter, one fcntl filter, instead of 1-3 stacked filters per
 * limit call.
 */
static int
flush_registered_limits(void)
{
	struct deny_ent ents[FLUSH_CHUNK];
	size_t n = 0;
	int i;

	for (i = 0; i < nfd_limits; i++) {
		int fd = fd_limits[i].fd;
		uint64_t d = fd_limits[i].deny;

#define ADD(syscall_nr, arg_idx) do { \
		ents[n].nr = (syscall_nr); \
		ents[n].argn = (arg_idx); \
		ents[n].fd = (fd); \
		if (++n == FLUSH_CHUNK) { \
			if (install_entry_chunk(ents, n) < 0) \
				return -1; \
			n = 0; \
		} \
	} while (0)

		if (d & LDENY_RD) {
#ifdef SYS_read
			ADD(SYS_read, 0);
#endif
#ifdef SYS_readv
			ADD(SYS_readv, 0);
#endif
#ifdef SYS_pread64
			ADD(SYS_pread64, 0);
#endif
#ifdef SYS_preadv
			ADD(SYS_preadv, 0);
#endif
#ifdef SYS_preadv2
			ADD(SYS_preadv2, 0);
#endif
		}
		if (d & LDENY_WR) {
#ifdef SYS_write
			ADD(SYS_write, 0);
#endif
#ifdef SYS_writev
			ADD(SYS_writev, 0);
#endif
#ifdef SYS_pwrite64
			ADD(SYS_pwrite64, 0);
#endif
#ifdef SYS_pwritev
			ADD(SYS_pwritev, 0);
#endif
#ifdef SYS_pwritev2
			ADD(SYS_pwritev2, 0);
#endif
		}
		if (d & LDENY_SEEK) {
#ifdef SYS_lseek
			ADD(SYS_lseek, 0);
#endif
#ifdef SYS__llseek
			ADD(SYS__llseek, 0);
#endif
		}
		if (d & LDENY_TRUNC) {
#ifdef SYS_ftruncate
			ADD(SYS_ftruncate, 0);
#endif
#ifdef SYS_ftruncate64
			ADD(SYS_ftruncate64, 0);
#endif
		}
		if (d & LDENY_FSYNC) {
#ifdef SYS_fsync
			ADD(SYS_fsync, 0);
#endif
#ifdef SYS_fdatasync
			ADD(SYS_fdatasync, 0);
#endif
		}
		if (d & LDENY_SHUT) {
#ifdef SYS_shutdown
			ADD(SYS_shutdown, 0);
#endif
		}
		if (d & LDENY_MMAP) {
#ifdef SYS_mmap
			ADD(SYS_mmap, 4);
#endif
#ifdef SYS_mmap2
			ADD(SYS_mmap2, 4);
#endif
		}
	}
#undef ADD
	if (n > 0 && install_entry_chunk(ents, n) < 0)
		return -1;

#ifdef SYS_ioctl
	if (install_arg1_limits(SYS_ioctl, 0) < 0)
		return -1;
#endif
#if defined(SYS_fcntl)
	if (install_arg1_limits(SYS_fcntl, 1) < 0)
		return -1;
#elif defined(SYS_fcntl64)
	if (install_arg1_limits(SYS_fcntl64, 1) < 0)
		return -1;
#endif
	return 0;
}

int
caph_ioctls_limit(int fd, const unsigned long *cmds, size_t ncmds)
{
	long allowed[16];
	size_t i, n;
	struct fd_limit *L;

	if (sandbox_disabled())
		return 0;
	n = ncmds < 16 ? ncmds : 16;
	for (i = 0; i < n; i++)
		allowed[i] = (long)cmds[i];
	if (!sandbox_entered) {
		L = lim_find(fd);
		if (L == NULL) {
			errno = ENOSPC;
			return -1;
		}
		return lim_merge(L->ioctls, &L->nioctls, allowed, n);
	}
#ifdef SYS_ioctl
	return limit_fd_arg1(fd, SYS_ioctl, allowed, n);
#else
	return 0;
#endif
}

int
caph_fcntls_limit(int fd, uint32_t fcntlrights)
{
	long allowed[6];
	size_t n = 0;
	struct fd_limit *L;

	if (sandbox_disabled())
		return 0;
	allowed[n++] = F_GETFD;
	allowed[n++] = F_SETFD;
	if (fcntlrights & CAP_FCNTL_GETFL)
		allowed[n++] = F_GETFL;
	if (fcntlrights & CAP_FCNTL_SETFL)
		allowed[n++] = F_SETFL;
	if (!sandbox_entered) {
		L = lim_find(fd);
		if (L == NULL) {
			errno = ENOSPC;
			return -1;
		}
		return lim_merge(L->fcntls, &L->nfcntls, allowed, n);
	}
#if defined(SYS_fcntl)
	return limit_fd_arg1(fd, SYS_fcntl, allowed, n);
#elif defined(SYS_fcntl64)
	return limit_fd_arg1(fd, SYS_fcntl64, allowed, n);
#else
	return 0;
#endif
}

/* ioctls left allowed when a rights set lacks CAP_IOCTL */
static const unsigned long safe_ioctls[] = {
#ifdef FIONREAD
	FIONREAD,
#endif
#ifdef FIOCLEX
	FIOCLEX,
#endif
#ifdef FIONCLEX
	FIONCLEX,
#endif
#ifdef TCGETS
	TCGETS,
#endif
#ifdef TIOCGWINSZ
	TIOCGWINSZ,
#endif
};

int
caph_rights_limit(int fd, const cap_rights_t *rights)
{
	struct deny_ent ents[24];
	size_t n = 0;

	if (sandbox_disabled())
		return 0;
	if (fcntl(fd, F_GETFD) < 0)
		return -1;

	/*
	 * CAP_LOOKUP on a directory fd: register it so openat/stat
	 * beneath it stay possible post-enter (write(1)'s /dev fd).
	 * Registration must happen before entering; afterwards the
	 * Landlock ruleset is already enforced and cannot be extended.
	 */
	if (rights->mask & CAP_LOOKUP) {
		struct stat st;

		if (sandbox_entered) {
			errno = ENOSYS;
			return -1;
		}
		if (fstat(fd, &st) < 0)
			return -1;
		if (!S_ISDIR(st.st_mode)) {
			errno = ENOTDIR;
			return -1;
		}
		if (lookup_nfds < (int)(sizeof(lookup_fds) /
		    sizeof(lookup_fds[0])))
			lookup_fds[lookup_nfds++] = fd;
	}

	/*
	 * Pre-enter: accumulate into the registry; the filters are built
	 * once, at enter time.  Post-enter: install immediately below.
	 */
	if (!sandbox_entered) {
		struct fd_limit *L = lim_find(fd);
		long safe_l[8];
		size_t nsafe, si;

		if (L == NULL) {
			errno = ENOSPC;
			return -1;
		}
		if ((rights->mask & CAP_READ) == 0)
			L->deny |= LDENY_RD;
		if ((rights->mask & (CAP_WRITE | CAP_PWRITE)) == 0)
			L->deny |= LDENY_WR;
		if ((rights->mask & CAP_SEEK) == 0)
			L->deny |= LDENY_SEEK;
		if ((rights->mask & CAP_FTRUNCATE) == 0)
			L->deny |= LDENY_TRUNC;
		if ((rights->mask & CAP_FSYNC) == 0)
			L->deny |= LDENY_FSYNC;
		if ((rights->mask & CAP_SHUTDOWN) == 0)
			L->deny |= LDENY_SHUT;
		if ((rights->mask & CAP_MMAP) == 0)
			L->deny |= LDENY_MMAP;
		if ((rights->mask & CAP_IOCTL) == 0) {
			nsafe = sizeof(safe_ioctls) / sizeof(safe_ioctls[0]);
			for (si = 0; si < nsafe; si++)
				safe_l[si] = (long)safe_ioctls[si];
			lim_merge(L->ioctls, &L->nioctls, safe_l, nsafe);
		}
		if ((rights->mask & CAP_FCNTL) == 0) {
			safe_l[0] = F_GETFD;
			safe_l[1] = F_SETFD;
			safe_l[2] = F_GETFL;
			safe_l[3] = F_SETFL;
			lim_merge(L->fcntls, &L->nfcntls, safe_l, 4);
		}
		return 0;
	}

#define ENT(sysno) do { ents[n].nr = (sysno); ents[n].argn = 0; n++; } while (0)
#define ENT_ARG(sysno, a) do { ents[n].nr = (sysno); ents[n].argn = (a); n++; } while (0)

	if ((rights->mask & CAP_READ) == 0) {
#ifdef SYS_read
		ENT(SYS_read);
#endif
#ifdef SYS_readv
		ENT(SYS_readv);
#endif
#ifdef SYS_pread64
		ENT(SYS_pread64);
#endif
#ifdef SYS_preadv
		ENT(SYS_preadv);
#endif
#ifdef SYS_preadv2
		ENT(SYS_preadv2);
#endif
	}
	if ((rights->mask & (CAP_WRITE | CAP_PWRITE)) == 0) {
#ifdef SYS_write
		ENT(SYS_write);
#endif
#ifdef SYS_writev
		ENT(SYS_writev);
#endif
#ifdef SYS_pwrite64
		ENT(SYS_pwrite64);
#endif
#ifdef SYS_pwritev
		ENT(SYS_pwritev);
#endif
#ifdef SYS_pwritev2
		ENT(SYS_pwritev2);
#endif
	}
	if ((rights->mask & CAP_SEEK) == 0) {
#ifdef SYS_lseek
		ENT(SYS_lseek);
#endif
#ifdef SYS__llseek
		ENT(SYS__llseek);
#endif
	}
	if ((rights->mask & CAP_FTRUNCATE) == 0) {
#ifdef SYS_ftruncate
		ENT(SYS_ftruncate);
#endif
#ifdef SYS_ftruncate64
		ENT(SYS_ftruncate64);
#endif
	}
	if ((rights->mask & CAP_FSYNC) == 0) {
#ifdef SYS_fsync
		ENT(SYS_fsync);
#endif
#ifdef SYS_fdatasync
		ENT(SYS_fdatasync);
#endif
	}
	if ((rights->mask & CAP_SHUTDOWN) == 0) {
#ifdef SYS_shutdown
		ENT(SYS_shutdown);
#endif
	}
	if ((rights->mask & CAP_MMAP) == 0) {
#ifdef SYS_mmap
		ENT_ARG(SYS_mmap, 4);
#endif
#ifdef SYS_mmap2
		ENT_ARG(SYS_mmap2, 4);
#endif
	}

	if (limit_fd_syscalls(fd, ents, n) < 0)
		return -1;

	if ((rights->mask & CAP_IOCTL) == 0 &&
	    caph_ioctls_limit(fd, safe_ioctls,
	        sizeof(safe_ioctls) / sizeof(safe_ioctls[0])) < 0)
		return -1;
	if ((rights->mask & CAP_FCNTL) == 0 &&
	    caph_fcntls_limit(fd,
	        CAP_FCNTL_GETFL | CAP_FCNTL_SETFL) < 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* stream/stdio helpers                                                */
/* ------------------------------------------------------------------ */

int
caph_limit_stream(int fd, int flags)
{
	cap_rights_t rights;

	if (sandbox_disabled())
		return 0;
	if (fcntl(fd, F_GETFD) < 0) {
		if (flags & CAPH_IGNORE_EBADF)
			return 0;
		return -1;
	}
	rights.mask = CAP_FSTAT;
	if (flags & CAPH_READ)
		rights.mask |= CAP_READ;
	if (flags & CAPH_WRITE)
		rights.mask |= CAP_WRITE | CAP_PWRITE;
	/* CAPH_LOOKUP has no meaning for an already-open fd here */
	return caph_rights_limit(fd, &rights);
}

int
caph_limit_stdin(void)
{
	return caph_limit_stream(STDIN_FILENO, CAPH_READ);
}

int
caph_limit_stdout(void)
{
	return caph_limit_stream(STDOUT_FILENO, CAPH_WRITE);
}

int
caph_limit_stderr(void)
{
	return caph_limit_stream(STDERR_FILENO, CAPH_WRITE);
}

int
caph_limit_stdio(void)
{
	if (caph_limit_stdin() < 0 ||
	    caph_limit_stdout() < 0 ||
	    caph_limit_stderr() < 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* mode entry / cache helpers                                          */
/* ------------------------------------------------------------------ */

static int
enter_mode(int mode)
{
	if (sandbox_disabled())
		return 0;
	if (sandbox_entered)
		return 0;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	if (landlock_lockdown(mode) < 0)
		return -1;
	if (install_namespace_filter(mode) < 0)
		return -1;
	if (flush_registered_limits() < 0)
		return -1;
	sandbox_entered = 1;
	return 0;
}

int
caph_enter(void)
{
	return enter_mode(MODE_FULL);
}

int
caph_enter_casper(void)
{
	/*
	 * Casper services are in-process stubs here, so entering is the
	 * read-only lockdown (see MODE_CASPER).  logger(1) calls
	 * cap_openlog/syslog afterwards and glibc defers the /dev/log
	 * socket to first use unless LOG_NDELAY, so force it open before
	 * the lockdown.  A missing syslogd just leaves it unopened.
	 */
	if (!sandbox_disabled())
		openlog(NULL, LOG_NDELAY, LOG_USER);
	return enter_mode(MODE_CASPER);
}

int
caph_allow_path(const char *path)
{
	int fd;

	if (sandbox_disabled())
		return 0;
	if (sandbox_entered) {
		errno = ENOSYS;
		return -1;
	}
	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd < 0)
		return -1;
	if (nallow_fds == (int)(sizeof(allow_fds) / sizeof(allow_fds[0]))) {
		(void)close(fd);
		errno = ENOSPC;
		return -1;
	}
	allow_fds[nallow_fds++] = fd;
	return 0;
}

int
caph_enter_paths(void)
{
	return enter_mode(MODE_PATHS);
}

void
caph_cache_tzdata(void)
{
	if (!sandbox_disabled())
		tzset();
}

void
caph_cache_catpages(void)
{
	/* tools here build WITHOUT_NLS; nothing to preload */
}
