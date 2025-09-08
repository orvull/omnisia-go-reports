PROTOC_GEN_GO       := $(shell which protoc-gen-go)
PROTOC_GEN_GRPC_GO  := $(shell which protoc-gen-go-grpc)

PROTO_DIR = proto
GEN_DIR   = gen/admin_auth

.PHONY: proto run tidy lint test

proto:
	@[ -n "$(PROTOC_GEN_GO)" ] || (echo "Install protoc-gen-go: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest" && false)
	@[ -n "$(PROTOC_GEN_GRPC_GO)" ] || (echo "Install protoc-gen-go-grpc: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest" && false)
	mkdir -p $(GEN_DIR)
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/admin_auth.proto

run: proto
	go run ./cmd/server

tidy:
	go mod tidy

lint:
	@echo "(add golangci-lint if desired)"

test:
	go test ./...
