# libsafestr — bounds-checked string primitives implemented in zig.
# Requires zig; when zig is not available the library and any consumer
# hooks are simply not provided (C tools fall back to strlcpy/strlcat).

zig_prog = find_program('zig', required: false)

libsafestr_dep = disabler()

if zig_prog.found()
    libsafestr_a = custom_target(
        'libsafestr.a',
        output: 'libsafestr.a',
        input: 'safestr.zig',
        command: [
            zig_prog, 'build-lib', '-static', '-O', 'ReleaseSafe',
            '-lc', '-fcompiler-rt', '--name', 'safestr',
            '-femit-bin=@OUTPUT@', '@INPUT@',
        ],
    )

    libsafestr_dep = declare_dependency(
        sources: libsafestr_a,
        include_directories: include_directories('.'),
    )

    c_safestr_test = executable(
        'c_safestr_test',
        'test/c_safestr_test.c',
        dependencies: libsafestr_dep,
    )
    test('c_safestr_test', c_safestr_test)
endif
