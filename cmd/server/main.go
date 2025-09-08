package main

import (
	"log"
	"net"
	"time"

	"google.golang.org/grpc"

	"github.com/orvull/omnisia-go-reports/gen/admin_auth"
	"github.com/orvull/omnisia-go-reports/internal/auth"
	"github.com/orvull/omnisia-go-reports/internal/config"
	"github.com/orvull/omnisia-go-reports/internal/google"
	"github.com/orvull/omnisia-go-reports/internal/server"
	"github.com/orvull/omnisia-go-reports/internal/storage"
)

func main() {
	cfg := config.Load()
	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer(
	// add interceptors (logging, recovery, metrics) here later
	)

	store := storage.NewMemory()
	signer := auth.JWTSigner{Key: []byte(cfg.JWTSigningKey), TTL: time.Duration(cfg.JWTTTLSeconds) * time.Second}
	gv := google.Verifier{ClientID: cfg.GoogleClientID}
	service := server.New(store, signer, time.Duration(cfg.RefreshTTLSeconds)*time.Second, gv)

	admin_auth.RegisterAdminAuthServiceServer(grpcServer, service)
	log.Printf("AdminAuth gRPC listening at %s", cfg.GRPCAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
