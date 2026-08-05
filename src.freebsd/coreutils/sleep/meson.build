sleep_prog = executable(
    'sleep',
    [ 'sleep.c' ],
    include_directories : inc,
    link_with : libcompat,
    install : true,
)

install_man('sleep.1')
