default: test.test

all: clean build.linux build.osx build.win

clean:
	rm -rf build
	rm -f test/bench.*
	rm -f test/prof.*
	find . -name '*.test' -delete

test.all: test.benchmark.new test.test test.vet test.errcheck

test.test:
	GIN_MODE=release go test ./...

test.errcheck:
	errcheck ./...

test.vet:
	go vet -v ./...

test.benchmark.new:
	go list ./... |  xargs go test -run=^$$ -bench=. | tee test/bench.new

test.benchmark.old:
	go list ./... |  xargs go test -run=^$$ -bench=. | tee test/bench.old

test.benchmark.cmp:
	benchcmp test/bench.old test/bench.new

# requires: % go get github.com/laher/gols/...
check.dependencies:
	go-ls -ignore=/vendor/ -exec="depscheck -v" ./...

prepare:
	@mkdir -p build/linux
	@mkdir -p build/osx
	@mkdir -p build/windows
	@echo created ./build/ directories

build.scmfile:
	@echo '{"url": "git:git@github.com:zalando-incubator/skoap.git", "revision": "'$$(git rev-parse HEAD)'", "author": "'$$USER'", "status": "test"}'  > scm-source.json
	@echo "created scm-source.json"

# release
build.linux.release: prepare
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build go build -o build/linux/skoap -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=`git describe --tags`" -tags zalandoValidation ./cmd/skoap

# dev builds
build.service.local: prepare
	go build -o build/skoap -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=HEAD" -tags zalandoValidation ./cmd/skoap

# docker
build.docker: build.linux build.scmfile
	docker build -t skoap .
	docker tag skoap gcr.io/zalando-teapot/skoap:latest
	gcloud docker -- push gcr.io/zalando-teapot/skoap:latest

# OS specific builds
build.linux: prepare
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/linux/skoap -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=HEAD" -tags zalandoValidation ./cmd/skoap

build.osx: prepare
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o build/osx/skoap -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=HEAD" -tags zalandoValidation ./cmd/skoap

build.win: prepare
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o build/windows/skoap -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=HEAD" -tags zalandoValidation ./cmd/skoap

# build and install multi binary project
dev.install:
	go install -ldflags "-X main.Buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Githash=`git rev-parse HEAD` -X main.Version=HEAD" -tags zalandoValidation ./...
