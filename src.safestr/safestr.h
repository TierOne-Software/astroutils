/*
 * safestr.h — bounds-checked C string primitives (libsafestr).
 *
 * The copy/cat/len primitives are implemented in Zig (src.safestr/safestr.zig)
 * and exposed over the C ABI. The printf wrappers are static inline here
 * because C variadic calls cannot be implemented portably in Zig; they are
 * thin checked wrappers around vsnprintf(3).
 *
 * All functions:
 *   - take the destination capacity explicitly,
 *   - always NUL-terminate the destination on SSTR_OK / SSTR_TRUNCATED,
 *   - return a status instead of silently truncating or overflowing.
 */
#ifndef SAFESTR_H
#define SAFESTR_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SSTR_OK = 0,        /* operation completed, nothing truncated */
    SSTR_TRUNCATED = 1, /* output was truncated; result is NUL-terminated */
    SSTR_INVALID = 2    /* bad arguments (NULL pointer or zero size) */
} sstr_status;

/* Bounded strlen: length of s, scanning at most max_len bytes. */
size_t sstr_len(const char *s, size_t max_len);

/* Copy src into dst (capacity dst_size). */
sstr_status sstr_copy(char *dst, size_t dst_size, const char *src);

/* Append src to the string in dst (capacity dst_size). */
sstr_status sstr_cat(char *dst, size_t dst_size, const char *src);

/* Copy up to src_len bytes of src (need not be NUL-terminated) into dst. */
sstr_status sstr_copy_n(char *dst, size_t dst_size, const char *src, size_t src_len);

/* Checked vsnprintf: SSTR_OK if everything fit, SSTR_TRUNCATED if the
 * output was cut (still NUL-terminated), SSTR_INVALID on bad arguments or
 * encoding errors. */
static inline sstr_status
sstr_vprintf(char *dst, size_t dst_size, const char *fmt, va_list ap)
{
    int n;

    if (dst == NULL || dst_size == 0 || fmt == NULL)
        return SSTR_INVALID;
    n = vsnprintf(dst, dst_size, fmt, ap);
    if (n < 0)
        return SSTR_INVALID;
    if ((size_t)n >= dst_size)
        return SSTR_TRUNCATED;
    return SSTR_OK;
}

/* Checked snprintf; see sstr_vprintf. */
static inline sstr_status
sstr_printf(char *dst, size_t dst_size, const char *fmt, ...)
{
    va_list ap;
    sstr_status st;

    va_start(ap, fmt);
    st = sstr_vprintf(dst, dst_size, fmt, ap);
    va_end(ap);
    return st;
}

#ifdef __cplusplus
}
#endif

#endif /* SAFESTR_H */
