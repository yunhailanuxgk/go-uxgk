// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/monitor"
	"github.com/google/keytransparency/core/monitorserver"

	mopb "github.com/google/keytransparency/core/api/monitor/v1/monitor_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	addr     = flag.String("addr", ":8099", "The ip:port combination to listen on")
	keyFile  = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile = flag.String("tls-cert", "genfiles/server.pem", "TLS cert file")

	signingKey         = flag.String("sign-key", "genfiles/monitor_sign-key.pem", "Path to private key PEM for SMH signing")
	signingKeyPassword = flag.String("password", "towel", "Password of the private key PEM file for SMH signing")
	ktURL              = flag.String("kt-url", "localhost:8080", "URL of key-server.")
	insecure           = flag.Bool("insecure", false, "Skip TLS checks")
	directoryID        = flag.String("directoryid", "", "KT Directory identifier to monitor")

	// TODO(ismail): expose prometheus metrics: a variable that tracks valid/invalid MHs
	// metricsAddr = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	// Connect to Key Transparency
	cc, err := dial(*ktURL, *insecure)
	if err != nil {
		glog.Exitf("Error Dialing %v: %v", ktURL, err)
	}
	ktClient := pb.NewKeyTransparencyClient(cc)

	config, err := ktClient.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: *directoryID})
	if err != nil {
		glog.Exitf("Could not read directory info %v:", err)
	}

	// Read signing key:
	key, err := pem.ReadPrivateKeyFile(*signingKey, *signingKeyPassword)
	if err != nil {
		glog.Exitf("Could not create signer from %v: %v", *signingKey, err)
	}
	signer := crypto.NewSHA256Signer(key)
	store := fake.NewMonitorStorage()

	// Create monitoring background process.
	mon, err := monitor.NewFromDirectory(ktClient, config, signer, store)
	if err != nil {
		glog.Exitf("Failed to initialize monitor: %v", err)
	}

	// TODO(gbelvin): persist trusted roots
	trusted := types.LogRootV1{}
	go func() {
		if err := mon.ProcessLoop(ctx, *directoryID, trusted); err != nil {
			glog.Errorf("ProcessLoop: %v", err)
		}
	}()

	// Monitor Server.
	srv := monitorserver.New(store)

	// Create gRPC server.
	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)
	mopb.RegisterMonitorServer(grpcServer, srv)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	// Create HTTP handlers and gRPC gateway.
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(tcreds)}
	gwmux, err := serverutil.GrpcGatewayMux(ctx, *addr, dopts,
		mopb.RegisterMonitorHandlerFromEndpoint)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	// Insert handlers for other http paths here.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", gwmux)

	// Serve HTTP2 server over TLS.
	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		serverutil.GrpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}

func dial(url string, insecure bool) (*grpc.ClientConn, error) {
	tcreds, err := transportCreds(url, insecure)
	if err != nil {
		return nil, err
	}

	// TODO(ismail): authenticate the monitor to the kt-server:
	return grpc.Dial(url, grpc.WithTransportCredentials(tcreds))
}

func transportCreds(ktURL string, insecure bool) (credentials.TransportCredentials, error) {
	host, _, err := net.SplitHostPort(ktURL)
	if err != nil {
		return nil, err
	}

	if insecure {
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // nolint: gosec
		}), nil
	}
	return credentials.NewClientTLSFromCert(nil, host), nil
}
