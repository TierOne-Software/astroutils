libcompat_sources = [
    'getbsize.c',
    'heapsort.c',
    'humanize_number.c',
    'merge.c',
    'mktemp.c',
    'ohash.c',
    'setmode.c',
    'strmode.c',
    'strftime.c',
    'strptime.c',
    'stringlist.c',
    'expand_number.c',
    'unvis.c',
    'vis.c',
    '../../src.compat/b64.c',
    '../../src.compat/err.c',
    '../../src.compat/strlfuncs.c',
    '../../src.compat/signames.c',
    '../../src.compat/strtonum.c',
    '../../src.compat/reallocf.c',
    '../../src.compat/capsicum.c',
]

libcompat = static_library(
    'compat',
    libcompat_sources,
    include_directories: [inc, cinc],
    c_args: ['-DHAVE_NBTOOL_CONFIG_H'],
)

# capsicum shim self-test; not installed, driven by tests/t/14-sandbox.sh
shimtest = executable(
    'shimtest',
    '../../src.compat/shimtest.c',
    include_directories: [inc, cinc],
    c_args: ['-DHAVE_NBTOOL_CONFIG_H'],
    link_with: libcompat,
    install: false,
)
