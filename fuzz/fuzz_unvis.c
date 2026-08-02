/*
 * fuzz_unvis.c — libFuzzer harness for strunvis/strnunvisx
 * (src.freebsd/compat/unvis.c), which decodes vis(3)-encoded input.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <vis.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* strunvis wants a NUL-terminated string */
    char *src = malloc(size + 1);
    char *dst = malloc(size * 4 + 1);
    if (!src || !dst) {
        free(src);
        free(dst);
        return 0;
    }
    memcpy(src, data, size);
    src[size] = '\0';

    char *cdst;
    (void)strunvis(dst, src);
    /* also exercise the unvis(3) state machine byte-by-byte */
    if ((cdst = malloc(size * 4 + 1)) != NULL) {
        int state = 0;
        char *cp = cdst;
        for (size_t i = 0; i < size; i++) {
            if (unvis(cp, (int)data[i], &state, 0) > 0)
                cp++;
        }
        free(cdst);
    }
    free(src);
    free(dst);
    return 0;
}
