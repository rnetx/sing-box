//go:build with_proxyprovider

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/proxyprovider"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandParseProxyProvider = &cobra.Command{
	Use:   "parse-proxyprovider",
	Short: "Parse Proxy Provider Peers",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(parseProxyProvider())
	},
}

var parseProxyProviderLink string

func init() {
	mainCommand.AddCommand(commandParseProxyProvider)
	commandParseProxyProvider.Flags().StringVarP(&parseProxyProviderLink, "link", "l", "", "Clash Link")
}

func parseProxyProvider() int {
	if parseProxyProviderLink == "" {
		log.Fatal("link is empty")
		return 1
	}

	pp, err := proxyprovider.NewProxyProvider(context.Background(), nil, nil, option.ProxyProviderOptions{
		Tag: "proxy-provider",
		URL: parseProxyProviderLink,
	})
	if err != nil {
		log.Fatal(E.Cause(err, "new proxy provider"))
		return 1
	}

	err = pp.ForceSubScribeToCache()
	if err != nil {
		log.Fatal(E.Cause(err, "update proxy provider"))
		return 1
	}

	outs, err := pp.GetOutboundOptions()
	if err != nil {
		log.Fatal(E.Cause(err, "get proxy provider outbound options"))
		return 1
	}

	opt := map[string]any{
		"outbounds": outs[:len(outs)-1],
	}

	content, err := json.MarshalIndent(opt, "", "  ")
	if err != nil {
		log.Fatal(err)
		return 1
	}

	fmt.Println(string(content))

	return 0
}
