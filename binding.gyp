{
  "targets": [
    {
      "target_name": "modsecurity",
      "sources": [ "modsecurity_wrap.cxx" ],
      "include_dirs": ['/usr/include/modsecurity/',],
      "libraries": ['/usr/lib/libmodsecurity.a',
      '/usr/lib/libmodsecurity.so',
      '/usr/lib/libmodsecurity.a',
      '/usr/lib/libmodsecurity.so.3.0.0',
      '/usr/lib/x86_64-linux-gnu/libxml2.so',
      '/usr/lib/x86_64-linux-gnu/libcurl.so',
      '/lib/x86_64-linux-gnu/libpcre.so.3',
      '/usr/lib/x86_64-linux-gnu/libyajl.so',
      '/usr/lib/x86_64-linux-gnu/libGeoIP.so',
      '/usr/lib/x86_64-linux-gnu/liblmdb.so'],
      "cflags" : [ "-std=c++11" ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ]
    }
  ]
}