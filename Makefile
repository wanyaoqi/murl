#####################################################

GO_BUILD_FLAGS:=-mod vendor
GO_BUILD := go build $(GO_BUILD_FLAGS)

export GO111MODULE:=on

all: build

build:
	$(GO_BUILD) -o murl

clean:
	rm -f murl

.PHONY: all build clean