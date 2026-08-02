/*
 * fuzz_setmode.c — libFuzzer harness for setmode(3)
 * (src.freebsd/compat/setmode.c), the symbolic-mode parser used by
 * chmod(1), mkdir(1), install(1) on user-supplied mode strings.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern void *setmode(const char *p);
extern mode_t getmode(const void *bbox, mode_t omode);

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
    void *bbox = setmode(buf);
    if (bbox != NULL) {
        (void)getmode(bbox, 0644);
        (void)getmode(bbox, 0);
        free(bbox);
    }
    free(buf);
    return 0;
}
