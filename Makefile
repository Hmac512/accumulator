.PHONY: all build bench clean cover deflake fmt lint test test-clean test-long

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT=/tmp/coverage.out
PACKAGE=./...

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})


.PHONY: all
all: test build

.PHONY: build
build:
	${GO} build ./...

.PHONY: bench
bench:
	${GO} test -short -bench=. -test.timeout=0 -run=^noTests ./...

.PHONY: clean
clean:
	${GO} clean -cache -modcache -i -r

.PHONY: cover
cover: ## compute and display test coverage report
	${GO} test -short -coverprofile=${COVERAGE_OUT} ${PACKAGE}
	${GO} tool cover -html=${COVERAGE_OUT}

.PHONY: test
test:
	${GO} test -short ${TEST_CLAUSE} ./...

.PHONY: test-clean
test-clean: ## Clear test cache and force all tests to be rerun
	${GO} clean -testcache && ${GO} test -count=1 -short ${TEST_CLAUSE} ./...

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${TEST_CLAUSE} ./...


.PHONY: run-accumulator-ecc
run-accumulator-ecc: ## Runs test of cryptographic accumulator
	${GO} run test/accumulator/ecc/main.go

