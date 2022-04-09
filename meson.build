project('socks5', 'c',
  version : '0.1',
  default_options : ['warning_level=2'])

liburing = dependency('liburing')

executable('socks5',
           [ 'socks.c' ],
           dependencies: liburing,
           install : true)
