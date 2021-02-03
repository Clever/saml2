SHELL=/bin/bash
LIBS=$(shell find . -regex "^./lib\/.*\.coffee\$$" | sed s/\.coffee$$/\.js/ | sed s/lib/lib-js/)

.PHONY: test

build: $(LIBS)

lib-js/%.js : lib/%.coffee
	node_modules/coffee-script/bin/coffee --bare -c -o $(@D) $(patsubst lib-js/%,lib/%,$(patsubst %.js,%.coffee,$@))

test-cov:
	rm -rf lib-js lib-js-cov
	node_modules/.bin/coffee -c -o lib-js lib
	node_modules/.bin/jscoverage lib-js lib-js-cov
	NODE_ENV=test TEST_COV_SAML2=1 node_modules/mocha/bin/mocha --ignore-leaks --require coffee-script/register test/*.coffee
	open coverage/index.html

test: build
	NODE_ENV=test node_modules/mocha/bin/mocha --ignore-leaks --timeout 60000 -R spec --require coffee-script/register test/*.coffee

clean:
	rm -rf lib-js lib-js-cov
