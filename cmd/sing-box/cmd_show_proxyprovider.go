//go:build with_proxyprovider

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/proxyprovider"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandShowProxyProvider = &cobra.Command{
	Use:   "show-proxyprovider",
	Short: "Show Proxy Provider Peers",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(showProxyProvider())
	},
}

var showProxyProviderTags []string

func init() {
	mainCommand.AddCommand(commandShowProxyProvider)
	commandShowProxyProvider.Flags().StringSliceVarP(&showProxyProviderTags, "tags", "t", nil, "Tags to update")
}

func showProxyProvider() int {
	options, err := readConfigAndMerge()
	if err != nil {
		log.Fatal(err)
		return 1
	}

	allTags := false
	var tagMap map[string]bool
	if updateProxyProviderTags == nil || len(updateProxyProviderTags) == 0 {
		allTags = true
	} else {
		tagMap = make(map[string]bool)
		for _, tag := range updateProxyProviderTags {
			tagMap[tag] = true
		}
	}

	needShowProxyProviders := make([]adapter.ProxyProvider, 0)

	for _, proxyProvider := range options.ProxyProviders {
		add := allTags
		if !add {
			add = tagMap[proxyProvider.Tag]
		}

		if add {
			pp, err := proxyprovider.NewProxyProvider(context.Background(), nil, nil, proxyProvider)
			if err != nil {
				log.Fatal(E.Cause(err, "create proxy provider ", proxyProvider.Tag))
				return 1
			}
			needShowProxyProviders = append(needShowProxyProviders, pp)
		}
	}

	m := make([]option.Outbound, 0)

	for _, pp := range needShowProxyProviders {
		err := pp.SubScribeAndParse()
		if err != nil {
			log.Error(E.Cause(err, "update proxy provider ", pp.Tag()))
			continue
		}
		outs, err := pp.GetOutboundOptions()
		if err != nil {
			log.Error(E.Cause(err, "get proxy provider outbound options", pp.Tag()))
			continue
		}
		m = append(m, outs...)
	}

	opt := map[string]any{
		"outbounds": m,
	}

	content, err := json.MarshalIndent(opt, "", "  ")
	if err != nil {
		log.Fatal(err)
		return 1
	}

	fmt.Println(string(content))

	return 0
}
