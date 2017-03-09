TESTS = test/**/**/*.test.js test/**/*.test.js

test:
	node \
		./node_modules/.bin/_mocha \
		-r test/test_helper \
		$(TESTS)

coverage:
	node \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		-r test/test_helper \
		$(TESTS)

test-travis:
	node \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		-r test/test_helper \
		--report lcovonly \
		$(TESTS)

.PHONY: test coverage
