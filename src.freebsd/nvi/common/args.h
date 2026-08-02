/*-
 * Copyright (c) 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 1993, 1994, 1995, 1996
 *	Keith Bostic.  All rights reserved.
 *
 * See the LICENSE file for redistribution information.
 */

/*
 * Structure for building "argc/argv" vector of arguments.
 *
 * !!!
 * All arguments are nul terminated as well as having an associated length.
 * The argument vector is NOT necessarily NULL terminated.  The proper way
 * to check the number of arguments is to use the argc value in the EXCMDARG
 * structure or to walk the array until an ARGS structure with a length of 0
 * is found.
 */
#include <sys/cdefs.h>

typedef struct _args {
	size_t	 blen;		/* Buffer length. */
	CHAR_T	*bp __cu_counted_by(blen); /* Argument. */
	size_t	 len;		/* Argument length. */

#define	A_ALLOCATED	0x01	/* If allocated space. */
	u_int8_t flags;
} ARGS;
