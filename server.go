package go_translator

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/WirePact/go-translator/internal"
	"github.com/WirePact/go-translator/pki"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
)

// Translator acts as the server for translation and communicating with envoy.
type Translator struct {
	close chan bool

	config *TranslatorConfig

	ingressServer *grpc.Server
	ingressListen *net.Listener

	egressServer *grpc.Server
	egressListen *net.Listener
}

// NewTranslator creates a new translator that adheres to the given config.
func NewTranslator(config *TranslatorConfig) (*Translator, error) {
	var ingressOpts []grpc.ServerOption
	ingressServer := grpc.NewServer(ingressOpts...)
	auth.RegisterAuthorizationServer(ingressServer, &internal.IngressServer{
		IngressTranslator: config.IngressTranslator,
	})

	ingressListen, err := net.Listen("tcp", fmt.Sprintf(":%v", config.IngressPort))
	if err != nil {
		return nil, err
	}

	var egressOpts []grpc.ServerOption
	egressServer := grpc.NewServer(egressOpts...)
	auth.RegisterAuthorizationServer(egressServer, &internal.EgressServer{
		EgressTranslator: config.EgressTranslator,
		JWTConfig:        &config.JWTConfig,
	})

	egressListen, err := net.Listen("tcp", fmt.Sprintf(":%v", config.EgressPort))
	if err != nil {
		return nil, err
	}

	return &Translator{
		config:        config,
		ingressServer: ingressServer,
		ingressListen: &ingressListen,
		egressServer:  egressServer,
		egressListen:  &egressListen,
	}, nil
}

// Start runs the server by ensuring the PKI key material and then starting the grpc servers.
// When a system interrupt is received the server stops.
func (translator *Translator) Start() {
	err := pki.EnsureKeyMaterial(&translator.config.Config)
	if err != nil {
		panic(err)
	}

	translator.close = make(chan bool)

	go func() {
		err := translator.ingressServer.Serve(*translator.ingressListen)
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		err := translator.egressServer.Serve(*translator.egressListen)
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
		<-signalChannel
		translator.close <- true
	}()

	<-translator.close

	translator.ingressServer.GracefulStop()
	translator.egressServer.GracefulStop()
}

// Stop closes the server and returns the "start" function.
func (translator *Translator) Stop() {
	translator.close <- true
}
