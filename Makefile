SOURCES = $(shell find . -iname '*.go')


ayd: ${SOURCES}
	go build -ldflags="-s -w" -trimpath .


.PHONY: test cover fmt clean

test:
	go test -race -cover ./...

cover:
	go test -race -coverprofile=cov ./... && go tool cover -html=cov; rm cov

fmt:
	gofmt -s -w ${SOURCES}

clean:
	-rm lauth
