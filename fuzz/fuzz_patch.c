/*
 * fuzz_patch.c — libFuzzer harness for patch(1)'s diff parser.
 *
 * Drives open_patch_file() + there_is_another_patch() + another_hunk()
 * over attacker-controlled input, i.e. the whole "intuit the diff type and
 * parse the hunks" surface, without ever applying anything to a file.
 * ED_DIFF input is not executed (do_ed_script is never called).
 *
 * patch reports malformed input via fatal() -> my_exit() -> exit(1); the
 * build rewrites exit() (-Dexit=fuzz_skip_exit) to a longjmp back into the
 * harness, which resets the parser's static state via pch_reset() before
 * the next input.
 *
 * Linked against the patch sources with -Dmain=patch_disabled_main so
 * patch.c's own main() is out of the way.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>

#include "common.h"
#include "pch.h"

static jmp_buf fuzz_fatal_jmp;

/* replaces exit() inside the patch objects (-Dexit=fuzz_skip_exit) */
void
fuzz_skip_exit(int status)
{
    (void)status;
    longjmp(fuzz_fatal_jmp, 1);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > (1 << 20))
        return 0;

    char tmpl[] = "/tmp/fuzz-patch-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return 0;
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    batch = true;
    force = true;
    verbose = false;

    /* normally done by patch.c's main() */
    if (buf == NULL) {
        buf_size = INITLINELEN;
        buf = malloc(buf_size);
        if (buf == NULL)
            return 0;
    }

    if (setjmp(fuzz_fatal_jmp) != 0) {
        /* fatal(): input rejected; free hunk lines parsed so far and
         * reset parser state for the next input */
        pch_reset();
        free(filearg[0]);
        filearg[0] = NULL;
        unlink(tmpl);
        return 0;
    }

    int guard = 0;
    for (open_patch_file(tmpl);
         there_is_another_patch() && guard++ < 64;
         re_patch()) {
        if (diff_type == ED_DIFF)
            break; /* never execute ed scripts */
        int hunk_guard = 0;
        while (another_hunk() && hunk_guard++ < 4096) {
            /* parse only */
        }
    }

    close_patch_file();
    unlink(tmpl);
    return 0;
}
