//go:build with_proxyprovider

package main

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/proxyprovider"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandUpdateProxyProvider = &cobra.Command{
	Use:   "update-proxyprovider",
	Short: "Update Proxy Provider",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(updateProxyProvider())
	},
}

var updateProxyProviderTags []string

func init() {
	mainCommand.AddCommand(commandUpdateProxyProvider)
	commandUpdateProxyProvider.Flags().StringSliceVarP(&updateProxyProviderTags, "tags", "t", nil, "Tags to update")
}

func updateProxyProvider() int {
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

	needUpdateProxyProviders := make([]adapter.ProxyProvider, 0)

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
			needUpdateProxyProviders = append(needUpdateProxyProviders, pp)
		}
	}

	for _, pp := range needUpdateProxyProviders {
		err := pp.ForceSubScribeToCache()
		if err != nil {
			log.Error(E.Cause(err, "subscribe and cache proxy provider ", pp.Tag()))
			continue
		}
		log.Info("Proxy Provider ", pp.Tag(), " updated")
	}

	return 0
}
