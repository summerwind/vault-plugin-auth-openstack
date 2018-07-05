package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
	openstack "github.com/summerwind/vault-plugin-auth-openstack/plugin"
)

func main() {
	meta := &pluginutil.APIClientMeta{}

	flags := meta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := meta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: openstack.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
