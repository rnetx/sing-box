//go:build with_proxyprovider

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-box/proxyprovider"

	"github.com/spf13/cobra"
)

var commandParseLink = &cobra.Command{
	Use:   "parselink",
	Short: "Parse Subscribe Link. Support Clash/Sing-box/Raw",
	Run: func(cmd *cobra.Command, args []string) {
		parseLinkDo()
	},
}

var parseLink string

func init() {
	commandParseLink.PersistentFlags().StringVarP(&parseLink, "link", "l", "", "Subscribe Link. Support Clash/Sing-box/Raw")
	mainCommand.AddCommand(commandParseLink)
}

func parseLinkDo() {
	if parseLink == "" {
		fmt.Println("link is empty")
		os.Exit(1)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		select {
		case <-signalChan:
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	outbounds, err := proxyprovider.ParseLink(ctx, parseLink)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		return
	}

	var data any
	if len(outbounds) == 1 {
		data = outbounds[0]
	} else {
		data = outbounds
	}

	buffer := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		return
	}

	fmt.Println(buffer.String())
}
