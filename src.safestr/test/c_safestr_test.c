/*
 * c_safestr_test.c — verifies libsafestr's C ABI from a C consumer,
 * including the static inline printf wrappers from safestr.h.
 */
#include <assert.h>
#include <string.h>

#include <safestr.h>

int
main(void)
{
    char buf[8];

    assert(sstr_copy(buf, sizeof(buf), "abc") == SSTR_OK);
    assert(strcmp(buf, "abc") == 0);

    assert(sstr_cat(buf, sizeof(buf), "de") == SSTR_OK);
    assert(strcmp(buf, "abcde") == 0);

    assert(sstr_cat(buf, sizeof(buf), "XYZ") == SSTR_TRUNCATED);
    assert(strcmp(buf, "abcdeXY") == 0);

    assert(sstr_len("hello", 100) == 5);
    assert(sstr_len("hello", 3) == 3);

    assert(sstr_copy(buf, sizeof(buf), "") == SSTR_OK);
    assert(buf[0] == '\0');

    assert(sstr_copy_n(buf, sizeof(buf), "raw-no-nul", 3) == SSTR_OK);
    assert(strcmp(buf, "raw") == 0);

    assert(sstr_printf(buf, sizeof(buf), "%d", 42) == SSTR_OK);
    assert(strcmp(buf, "42") == 0);

    assert(sstr_printf(buf, sizeof(buf), "%s", "0123456789") == SSTR_TRUNCATED);
    assert(strcmp(buf, "0123456") == 0);

    assert(sstr_copy(buf, 0, "x") == SSTR_INVALID);
    assert(sstr_copy(NULL, sizeof(buf), "x") == SSTR_INVALID);
    assert(sstr_printf(buf, 0, "x") == SSTR_INVALID);

    return 0;
}
