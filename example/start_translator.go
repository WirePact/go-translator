package example

import (
	gotranslator "github.com/WirePact/go-translator"
	"github.com/WirePact/go-translator/pki"
	"github.com/WirePact/go-translator/translator"
	"github.com/WirePact/go-translator/wirepact"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

func ingress(_ string, _ *auth.CheckRequest) (translator.IngressResult, error) {
	return translator.IngressResult{
		HeadersToAdd:    nil,
		HeadersToRemove: []string{"foobar"},
	}, nil
}

func egress(_ *auth.CheckRequest) (translator.EgressResult, error) {
	return translator.EgressResult{
		UserID:          "1337",
		HeadersToRemove: []string{"authorization"},
	}, nil
}

func main() {
	translator, _ := gotranslator.NewTranslator(&gotranslator.TranslatorConfig{
		IngressTranslator: ingress,
		EgressTranslator:  egress,
		Config:            pki.Config{ /* the config... */ },
		JWTConfig:         wirepact.JWTConfig{ /* the config... */ },
	})

	translator.Start()
}
