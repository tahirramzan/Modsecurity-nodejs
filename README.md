#Introduction

This repo contains the binding of libModSecurity(aka ModSecurity v3) in Node.js. These bindings will allow users to utilize the exposed libmodsecurity interfaces directly from node.js.


Please head over to the project [**Wiki**](https://github.com/manishmalik/Modsecurity-nodejs/wiki) for more details.

#Installation guide
Before you follow the following steps make sure you have npm, nodejs and swig(3.0+) installed in your system.

1. First build libModSecurity in your system. [Compilation recipes](https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes)

2. Open `binding.gyp`, edit `include_dirs` and `libraries` to point to the headers(include directories) and libraries folder of modsecurity. By default it's looking at:
	```
	"include_dirs": ['/usr/include/modsecurity/',],
	"libraries": ['/usr/lib/libmodsecurity.a','other_shared_libraries']
	```
3. Then type: `make`
	The `Makefile` will first generates the wrapper `modsecurity_wrap.cxx` , then installs node package and finally `node-gyp` generate the node module of modsecurity. You must see `ok` at the end to make sure that build was successfull.

4. To test the node module, you may use : `npm test`. Further to test the simple connector you can `cd` into `example` and type `node simple_example.js`.

#Disclaimer
This is in early development phase and is highly unstable. To see some known bugs or issues you may check [this](todo.md).
