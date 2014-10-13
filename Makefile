SHELL=/bin/bash
LIBS=$(shell find . -regex "^./lib\/.*\.coffee\$$" | sed s/\.coffee$$/\.js/ | sed s/lib/dist/)

.PHONY: test

build: $(LIBS)

dist/%.js : lib/%.coffee
	node_modules/coffee-script/bin/coffee --bare -c -o $(@D) $(patsubst dist/%,lib/%,$(patsubst %.js,%.coffee,$@))

test: build
	NODE_ENV=test node_modules/mocha/bin/mocha --ignore-leaks --timeout 60000 --compilers coffee:coffee-script/register test/*.coffee

clean:
	rm -rf dist
