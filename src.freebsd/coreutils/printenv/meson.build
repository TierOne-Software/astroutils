printenv_prog = executable(
    'printenv',
    [ 'printenv.c' ],
    include_directories : inc,
    link_with : libcompat,
    install : true,
)

install_man('printenv.1')
