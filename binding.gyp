{
  "targets": [
    {
      "target_name": "modsecurity",
      "sources": [ "modsecurity_wrap.cxx" ],
      "include_dirs": ['/usr/local/modsecurity/include/',],
      "libraries": ['-L/usr/local/modsecurity/lib/'],
      "cflags" : [ "-std=c++11" ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ]
    }
  ]
}