all:
	swig -I/usr/local/modsecurity/include/ -javascript -node -Wall -Wextra -c++ modsecurity/modsecurity.i
	npm install
	./node_modules/node-gyp/bin/node-gyp.js configure
	./node_modules/node-gyp/bin/node-gyp.js build


