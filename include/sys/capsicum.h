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
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SYS_CAPSICUM_H
#define SYS_CAPSICUM_H

/*
 * Capsicum compatibility for Linux: implemented on top of Landlock
 * (filesystem namespace) and seccomp-BPF (everything else) in
 * src.compat/capsicum.c.  Enforcement is required by default; set
 * ASTROUTILS_SANDBOX=NONE in the environment to fall back to the
 * historical no-op stub behavior.
 *
 * The rights are a bitmask; only the names used in this tree are
 * defined.  Unlike FreeBSD, the variadic cap_rights_* macros append a
 * sentinel (CU_CAP_END) themselves, so call sites do not change.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAP_READ	(1ULL << 0)
#define CAP_WRITE	(1ULL << 1)
#define CAP_SEEK	(1ULL << 2)
#define CAP_FSTAT	(1ULL << 3)
#define CAP_FSYNC	(1ULL << 4)
#define CAP_FCNTL	(1ULL << 5)
#define CAP_FSTATFS	(1ULL << 6)
#define CAP_FTRUNCATE	(1ULL << 7)
#define CAP_IOCTL	(1ULL << 8)
#define CAP_MMAP_R	(1ULL << 9)
#define CAP_EVENT	(1ULL << 10)
#define CAP_LOOKUP	(1ULL << 11)
#define CAP_PWRITE	(1ULL << 12)
#define CAP_CONNECT	(1ULL << 13)
#define CAP_SHUTDOWN	(1ULL << 14)

typedef struct cap_rights cap_rights_t;

struct cap_rights {
	uint64_t mask;
};

/* sentinel terminating the variadic right lists */
#define CU_CAP_END	(~0ULL)

cap_rights_t *cu_cap_rights_init(cap_rights_t *rights, ...);
cap_rights_t *cu_cap_rights_set(cap_rights_t *rights, ...);
cap_rights_t *cu_cap_rights_clear(cap_rights_t *rights, ...);
int cu_cap_rights_is_set(const cap_rights_t *rights, ...);
int caph_rights_limit(int fd, const cap_rights_t *rights);

#define cap_rights_init(rights, ...) \
    cu_cap_rights_init(rights, ##__VA_ARGS__, CU_CAP_END)
#define cap_rights_set(rights, ...) \
    cu_cap_rights_set(rights, ##__VA_ARGS__, CU_CAP_END)
#define cap_rights_clear(rights, ...) \
    cu_cap_rights_clear(rights, ##__VA_ARGS__, CU_CAP_END)
#define cap_rights_is_set(rights, ...) \
    cu_cap_rights_is_set(rights, ##__VA_ARGS__, CU_CAP_END)

#ifdef __cplusplus
}
#endif

#endif
