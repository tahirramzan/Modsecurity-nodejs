#Introduction

This repo contains the binding of libModSecurity(aka ModSecurity v3) in Node.js. These bindings will allow users to utilize the exposed libmodsecurity interfaces directly from node.js.


#Installation guide
Before you follow the following steps make sure you have npm, nodejs and swig(3.0+) installed in your system.

1. First build libModSecurity in your system. [Compilation recipes](https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes)

2. Open `binding.gyp`, edit `include_dirs` and `libraries` to point to the headers(include directories) and libraries folder of modsecurity. By default it's looking at:

```
"include_dirs": ['/usr/local/modsecurity/include/',],
"libraries": ['-L/usr/local/modsecurity/lib/']
```

3. Then type: `make`
	The `Makefile` will first generates the wrapper `modsecurity_wrap.cxx` , then installs node package and finally `node-gyp` generate the node module of modsecurity. You must see `ok` at the end to make sure that build was successfull.

#Disclaimer
This is in early development phase and is highly unstable.
