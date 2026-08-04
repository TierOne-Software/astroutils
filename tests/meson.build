# Functional and security regression suite.
#
# The suite is a standalone POSIX-sh harness (it also runs against the zig
# build or an installed image); here it is registered so that `meson test`
# exercises it against the tools this build tree just produced.

run_tests = find_program('run-tests.sh')

# The corpus replay dominates the runtime, so it gets its own test entry:
# `meson test --suite functional` stays quick for the edit/build/test loop
# while CI runs everything.
test(
    'functional',
    run_tests,
    args: [
        '--build', meson.project_build_root(),
        '--quiet',
        '00-smoke', '10-regress', '11-regress', '12-regress', '13-regress',
    ],
    suite: 'functional',
    timeout: 600,
    workdir: meson.project_source_root(),
)

test(
    'fuzz-corpus',
    run_tests,
    args: [
        '--build', meson.project_build_root(),
        '--quiet',
        '20-fuzz-corpus',
    ],
    suite: 'fuzz',
    timeout: 1800,
    workdir: meson.project_source_root(),
)
