M golang:1.22 as build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make proto && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/admin-auth ./cmd/server


FROM gcr.io/distroless/base-debian12
COPY --from=build /out/admin-auth /admin-auth
ENV GRPC_ADDR=:50051
ENV JWT_SIGNING_KEY=dev_insecure_change_me
ENV JWT_TTL_SECONDS=900
ENV REFRESH_TTL_SECONDS=1209600
ENV GOOGLE_OAUTH_CLIENT_ID=""
ENTRYPOINT ["/omnisia-go-reports"]