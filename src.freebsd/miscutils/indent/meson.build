indent_prog = executable(
    'indent',
    ['indent.c', 'io.c', 'lexi.c', 'parse.c', 'pr_comment.c', 'args.c'],
    include_directories: [inc],
    link_with : libcompat,
    install: true,
)

install_man('indent.1')
