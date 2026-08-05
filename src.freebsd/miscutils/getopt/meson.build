getopt_prog = executable(
    'getopt',
    [ 'getopt.c' ],
    include_directories : inc,
    link_with : libcompat,
    install : true,
)

install_man('getopt.1')
