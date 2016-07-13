NODE_VERSION = $(wordlist 1,1,$(subst ., ,$(subst v, ,$(shell node -v))))

TESTS = test/**/**/*.test.js test/**/*.test.js

test:
	node \
		./node_modules/.bin/_mocha \
		$(TESTS)

coverage:
	node \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		$(TESTS)

test-travis:
	node \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		--report lcovonly \
		$(TESTS)

.PHONY: test coverage
