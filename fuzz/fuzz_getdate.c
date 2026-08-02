/*
 * fuzz_getdate.c — libFuzzer harness for get_date()
 * (src.freebsd/findutils/find/getdate.y), the yacc date parser used by
 * find(1) and others on user-supplied date strings.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* the findutils parser entry point (not glibc's XPG getdate) */
extern time_t get_date(char *p);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 4096)
        return 0;
    char *buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    (void)get_date(buf);
    free(buf);
    return 0;
}
