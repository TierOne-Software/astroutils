patch_prog = executable(
    'patch',
    [
        'patch.c', 'backupfile.c', 'inp.c', 'mkpath.c', 'pch.c', 'util.c',
    ],
    include_directories : inc,
    # the diff parser's line-number arithmetic is allowed to wrap on overflow
    c_args: ['-fwrapv'],
    link_with : [ libcompat ],
    install : true,
)

install_man('patch.1')
