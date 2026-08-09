/*
 * fuzz_patch_struct.c — structure-aware libFuzzer harness for patch(1)'s
 * diff parser.
 *
 * Same execution machinery as fuzz_patch.c (open_patch_file() +
 * there_is_another_patch() + another_hunk() over a temp file, with
 * fatal() -> exit() longjmp'd back into the harness and pch_reset()
 * between inputs), plus a LLVMFuzzerCustomMutator that builds
 * grammar-shaped diffs instead of relying on byte-level mutation to
 * discover the multi-line header/hunk structure:
 *
 *   - unified diffs (---/+++ file headers, @@ -a[,b] +c[,d] @@ hunks,
 *     ' '/'-'/'+'/'\' body lines, "\ No newline at end of file"),
 *   - context diffs (*** /--- headers, "***************" separators,
 *     "*** a,b ****" / "--- c,d ----" range headers, "  "/"! "/"- "/"+ "
 *     body lines; old-style context without the trailing "****"),
 *   - normal diffs (Na,b / a,bc,d / Nd commands with "< ", "---",
 *     "> " sections),
 *   - ed scripts (digit commands terminated by "."),
 *   - git-style ("diff --git a/x b/y", "index ...") and Perforce-style
 *     ("==== ... - path ====") wrappers, Index:/Prereq: lines,
 *   - garbage sections before, between and after diffs,
 *   - per-diff indentation prefixes (' ', '\t', 'X') to exercise the
 *     p_indent logic in intuit_diff_type()/pgets(),
 *   - line numbers drawn from small plausible values, zero, and
 *     huge/overflowing digit strings (INT32_MAX, UINT32_MAX,
 *     LINENUM_MAX-1, >64-bit) to hit the range checks in another_hunk()
 *     and strtolinenum().
 *
 * Strategies compose: ~40% of mutations build a fresh structured diff,
 * ~30% run the default mutator on the existing (usually structured)
 * input, ~20% build a structure and then byte-mangle it, ~10% splice a
 * structured diff onto the existing input.
 *
 * Build like fuzz_patch (see build-fuzz.sh): same patch sources,
 * -Dmain=patch_disabled_main -Dexit=fuzz_skip_exit.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/param.h>		/* nitems() */

#include "common.h"
#include "pch.h"

/* from libFuzzer */
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

static jmp_buf fuzz_fatal_jmp;

/* replaces exit() inside the patch objects (-Dexit=fuzz_skip_exit) */
void
fuzz_skip_exit(int status)
{
    (void)status;
    longjmp(fuzz_fatal_jmp, 1);
}

/* ------------------------------------------------------------------ */
/* mutator                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t s;
} rng_t;

static uint64_t
rnd(rng_t *r)
{
    /* xorshift64* */
    uint64_t x = r->s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    r->s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static size_t
rnd_below(rng_t *r, size_t n)
{
    return n == 0 ? 0 : (size_t)(rnd(r) % n);
}

typedef struct {
    uint8_t *buf;
    size_t pos;
    size_t max;
    rng_t rng;
    char indent[4];		/* per-diff p_indent prefix */
    size_t indent_len;
} emit_t;

static void
emit(emit_t *e, const char *s, size_t len)
{
    size_t room = e->max - e->pos;

    if (len > room)
        len = room;
    memcpy(e->buf + e->pos, s, len);
    e->pos += len;
}

static void
emit_str(emit_t *e, const char *s)
{
    emit(e, s, strlen(s));
}

/* a line belonging to the current diff: indent prefix + text + '\n' */
static void
emit_line(emit_t *e, const char *s)
{
    if (e->max - e->pos < e->indent_len + 2)
        return;
    emit(e, e->indent, e->indent_len);
    emit_str(e, s);
    emit(e, "\n", 1);
}

static void
emit_garbage(emit_t *e)
{
    size_t lines = rnd_below(&e->rng, 6);
    size_t i, j, n;
    char line[64];

    for (i = 0; i < lines; i++) {
        n = rnd_below(&e->rng, sizeof(line) - 1);
        for (j = 0; j < n; j++) {
            if (rnd_below(&e->rng, 8) == 0)
                line[j] = (char)rnd(&e->rng);	/* any byte */
            else
                line[j] = (char)(32 + rnd_below(&e->rng, 95));
        }
        line[n] = '\0';
        emit_str(e, line);
        emit(e, "\n", 1);
    }
}

/*
 * Line numbers: mostly plausible, but deliberately hit the range
 * checks in another_hunk() (p_first >= LINENUM_MAX - p_ptrn_lines,
 * hunk-too-large) and strtolinenum()'s overflow path.
 */
static void
gen_linenum(rng_t *r, char *out, size_t outsz)
{
    static const char *const special[] = {
        "0",
        "1",
        "2",
        "2147483647",		/* INT32_MAX */
        "2147483648",
        "4294967295",		/* UINT32_MAX */
        "4294967296",
        "9223372036854775800",
        "9223372036854775806",	/* LINENUM_MAX - 1 */
        "9223372036854775807",	/* LINENUM_MAX */
        "99999999999999999999999999",	/* overflows long */
        "00042",
        "999999999999",
    };

    switch (rnd_below(r, 4)) {
    case 0:
        snprintf(out, outsz, "%u", (unsigned)rnd_below(r, 100));
        break;
    case 1:
        snprintf(out, outsz, "%u", (unsigned)rnd_below(r, 1000000));
        break;
    default:
        snprintf(out, outsz, "%s", special[rnd_below(r, nitems(special))]);
        break;
    }
}

/* comma-separated range "a" or "a,b" (b may be < a for context diffs) */
static void
gen_range(rng_t *r, char *out, size_t outsz)
{
    char a[32], b[32];

    gen_linenum(r, a, sizeof(a));
    if (rnd_below(r, 3) == 0) {
        snprintf(out, outsz, "%s", a);
        return;
    }
    gen_linenum(r, b, sizeof(b));
    snprintf(out, outsz, "%s,%s", a, b);
}

static void
gen_text(rng_t *r, char *out, size_t outsz)
{
    size_t n = rnd_below(r, outsz > 24 ? 24 : outsz - 1);
    size_t i;

    for (i = 0; i < n; i++) {
        switch (rnd_below(r, 8)) {
        case 0:
            out[i] = (char)rnd(r);		/* arbitrary byte, may be \0 */
            break;
        case 1:
            out[i] = "\t \\<>=*+-"[rnd_below(r, 10)];
            break;
        default:
            out[i] = (char)(32 + rnd_below(r, 95));
            break;
        }
    }
    out[n] = '\0';
}

static const char *
gen_filename(rng_t *r)
{
    static const char *const names[] = {
        "old.c",
        "new.c",
        "a/old.c",
        "b/new.c",
        "/dev/null",
        "file with spaces.c",
        "a/very/long/path/component/name/that/keeps/going/file.c",
        "f.c\t2024-01-01 00:00:00.000000000 +0000",
        "f.c.orig",
        "\t",
    };

    return names[rnd_below(r, nitems(names))];
}

/* @@ -a[,b] +c[,d] @@ hunk, body of ' ', '-', '+', '\' lines */
static void
build_unified_hunk(emit_t *e)
{
    char ra[72], rb[72], line[80], text[32];
    size_t nbody, i;

    gen_range(&e->rng, ra, sizeof(ra));
    gen_range(&e->rng, rb, sizeof(rb));
    if (rnd_below(&e->rng, 4) == 0)
        snprintf(line, sizeof(line), "@@ -%s +%s @@ section heading", ra, rb);
    else
        snprintf(line, sizeof(line), "@@ -%s +%s @@", ra, rb);
    emit_line(e, line);

    nbody = rnd_below(&e->rng, 12);
    for (i = 0; i < nbody; i++) {
        char lead;

        switch (rnd_below(&e->rng, 8)) {
        case 0: case 1:
            lead = ' ';
            break;
        case 2: case 3:
            lead = '-';
            break;
        case 4: case 5:
            lead = '+';
            break;
        case 6:
            lead = '\\';	/* usually "\ No newline at end of file" */
            break;
        default:
            lead = (char)(32 + rnd_below(&e->rng, 95));	/* junk lead */
            break;
        }
        gen_text(&e->rng, text, sizeof(text));
        line[0] = lead;
        line[1] = '\0';
        if (lead == '\\' && rnd_below(&e->rng, 2) == 0)
            snprintf(line, sizeof(line), "\\ No newline at end of file");
        else
            strncat(line, text, sizeof(line) - 2);
        emit_line(e, line);
    }
}

static void
build_unified(emit_t *e)
{
    char line[512];

    if (rnd_below(&e->rng, 3) == 0) {
        snprintf(line, sizeof(line), "diff --git a/%s b/%s",
            gen_filename(&e->rng), gen_filename(&e->rng));
        emit_line(e, line);
        if (rnd_below(&e->rng, 2) == 0)
            emit_line(e, "index 0123abc..4567def 100644");
    }
    if (rnd_below(&e->rng, 4) == 0) {
        snprintf(line, sizeof(line), "Index: %s", gen_filename(&e->rng));
        emit_line(e, line);
    }
    if (rnd_below(&e->rng, 6) == 0)
        emit_line(e, "Prereq: 1.2.3");
    snprintf(line, sizeof(line), "--- %s", gen_filename(&e->rng));
    emit_line(e, line);
    snprintf(line, sizeof(line), "+++ %s", gen_filename(&e->rng));
    emit_line(e, line);
    for (size_t i = 0, n = 1 + rnd_below(&e->rng, 3); i < n; i++)
        build_unified_hunk(e);
}

/* "*** a,b ****" old section, "--- c,d ----" new section */
static void
build_context(emit_t *e)
{
    static const char *const oldleads[] = { "  ", "- ", "! ", "\\ " };
    static const char *const newleads[] = { "  ", "+ ", "! ", "\\ " };
    char line[512], range[72], text[32];
    size_t i, n;
    int old_style = rnd_below(&e->rng, 3) == 0;	/* CONTEXT_DIFF vs NEW */

    snprintf(line, sizeof(line), "*** %s", gen_filename(&e->rng));
    emit_line(e, line);
    snprintf(line, sizeof(line), "--- %s", gen_filename(&e->rng));
    emit_line(e, line);
    for (size_t h = 0, nh = 1 + rnd_below(&e->rng, 2); h < nh; h++) {
        emit_line(e, "***************");
        gen_range(&e->rng, range, sizeof(range));
        snprintf(line, sizeof(line), "*** %s %s", range,
            old_style ? "" : "****");
        emit_line(e, line);
        for (i = 0, n = rnd_below(&e->rng, 10); i < n; i++) {
            gen_text(&e->rng, text, sizeof(text));
            snprintf(line, sizeof(line), "%s%s",
                oldleads[rnd_below(&e->rng, nitems(oldleads))], text);
            emit_line(e, line);
        }
        gen_range(&e->rng, range, sizeof(range));
        snprintf(line, sizeof(line), "--- %s %s", range,
            old_style ? "" : "----");
        emit_line(e, line);
        for (i = 0, n = rnd_below(&e->rng, 10); i < n; i++) {
            gen_text(&e->rng, text, sizeof(text));
            snprintf(line, sizeof(line), "%s%s",
                newleads[rnd_below(&e->rng, nitems(newleads))], text);
            emit_line(e, line);
        }
    }
}

/* "5a6,8" / "3d2" / "10,12c15,16" with "< "/"---"/"> " bodies */
static void
build_normal(emit_t *e)
{
    char line[512], ra[72], rb[72], text[32];
    char cmd;
    size_t i, n;

    for (size_t h = 0, nh = 1 + rnd_below(&e->rng, 3); h < nh; h++) {
        gen_range(&e->rng, ra, sizeof(ra));
        gen_range(&e->rng, rb, sizeof(rb));
        cmd = "adc"[rnd_below(&e->rng, 3)];
        snprintf(line, sizeof(line), "%s%c%s", ra, cmd, rb);
        emit_line(e, line);
        if (cmd == 'd' || cmd == 'c') {
            for (i = 0, n = rnd_below(&e->rng, 8); i < n; i++) {
                gen_text(&e->rng, text, sizeof(text));
                snprintf(line, sizeof(line), "< %s", text);
                emit_line(e, line);
            }
        }
        if (cmd == 'c')
            emit_line(e, "---");
        if (cmd == 'a' || cmd == 'c') {
            for (i = 0, n = rnd_below(&e->rng, 8); i < n; i++) {
                gen_text(&e->rng, text, sizeof(text));
                snprintf(line, sizeof(line), "> %s", text);
                emit_line(e, line);
            }
        }
    }
}

/* digit commands + "." terminator: parsed as ED_DIFF (never executed) */
static void
build_ed(emit_t *e)
{
    char line[64], text[32];
    size_t i, n;

    for (i = 0, n = 1 + rnd_below(&e->rng, 6); i < n; i++) {
        if (rnd_below(&e->rng, 3) == 0) {
            gen_text(&e->rng, text, sizeof(text));
            snprintf(line, sizeof(line), "%s", text);
        } else {
            snprintf(line, sizeof(line), "%u%c",
                (unsigned)rnd_below(&e->rng, 1000),
                "acdr"[rnd_below(&e->rng, 4)]);
        }
        emit_line(e, line);
    }
    emit_line(e, ".");
}

static size_t
build_structured(rng_t *r, uint8_t *data, size_t max)
{
    static const char *const indents[] = { "", " ", "  ", "\t", "X", "X  " };
    emit_t e;
    size_t i, ndiffs;

    e.buf = data;
    e.pos = 0;
    e.max = max;
    e.rng = *r;
    e.indent_len = 0;

    if (rnd_below(&e.rng, 3) == 0)
        emit_garbage(&e);

    for (i = 0, ndiffs = 1 + rnd_below(&e.rng, 3); i < ndiffs; i++) {
        const char *ind = indents[rnd_below(&e.rng, nitems(indents))];

        e.indent_len = strlen(ind);
        if (e.indent_len > sizeof(e.indent))
            e.indent_len = sizeof(e.indent);
        memcpy(e.indent, ind, e.indent_len);

        switch (rnd_below(&e.rng, 8)) {
        case 0: case 1: case 2:
            build_unified(&e);
            break;
        case 3: case 4:
            build_context(&e);
            break;
        case 5: case 6:
            build_normal(&e);
            break;
        default:
            build_ed(&e);
            break;
        }
        if (rnd_below(&e.rng, 3) == 0)
            emit_garbage(&e);
    }

    *r = e.rng;
    return e.pos;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
    unsigned int Seed)
{
    rng_t rng;
    size_t n;
    static int use_default_only = -1;

    /* A/B arm switch: with FUZZ_STRUCT_DEFAULT_MUTATE set, defer entirely
     * to the built-in mutator so coverage of this same binary can be
     * compared against the structured mutator without the counter sets
     * differing. */
    if (use_default_only < 0)
        use_default_only = getenv("FUZZ_STRUCT_DEFAULT_MUTATE") != NULL;
    if (use_default_only)
        return LLVMFuzzerMutate(Data, Size, MaxSize);

    rng.s = Seed ? Seed : 0x9e3779b97f4a7c15ULL;
    (void)rnd(&rng);

    if (MaxSize < 32)
        return LLVMFuzzerMutate(Data, Size, MaxSize);

    switch (rnd_below(&rng, 10)) {
    case 0: case 1: case 2: case 3:
        /* fresh grammar-shaped diff from scratch */
        return build_structured(&rng, Data, MaxSize);
    case 4: case 5: case 6:
        /* mutate the (usually structured) existing input */
        if (Size == 0)
            return build_structured(&rng, Data, MaxSize);
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    case 7: case 8:
        /* structured template, then byte-mangle it in place */
        n = build_structured(&rng, Data, MaxSize);
        return LLVMFuzzerMutate(Data, n,
            n + 64 <= MaxSize ? n + 64 : MaxSize);
    default:
        /* splice a structured diff onto the existing input */
        if (Size == 0 || Size >= MaxSize / 2)
            return build_structured(&rng, Data, MaxSize);
        Size = LLVMFuzzerMutate(Data, Size, MaxSize / 2);
        if (Size == 0 || Data[Size - 1] != '\n')
            emit(&(emit_t){ Data, Size, MaxSize, rng, "", 0 }, "\n", 1), Size++;
        Size += build_structured(&rng, Data + Size, MaxSize - Size);
        return Size;
    }
}

/* ------------------------------------------------------------------ */
/* execution (identical machinery to fuzz_patch.c)                     */
/* ------------------------------------------------------------------ */

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > (1 << 20))
        return 0;

    char tmpl[] = "/tmp/fuzz-patch-struct-XXXXXX";
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
