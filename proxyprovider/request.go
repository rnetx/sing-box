package proxyprovider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/proxyprovider/clash"
	"github.com/sagernet/sing-box/proxyprovider/raw"
	"github.com/sagernet/sing-box/proxyprovider/singbox"
)

func request(ctx context.Context, httpClient *http.Client, url string, ua string) (*Cache, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)

	req = req.WithContext(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body.Close()

	// Try Clash Config
	outbounds, err := clash.ParseClashConfig(buffer.Bytes())
	if err != nil {
		// Try Raw Config
		outbounds, err = raw.ParseRawConfig(buffer.Bytes())
		if err != nil {
			// Try Singbox Config
			outbounds, err = singbox.ParseSingboxConfig(buffer.Bytes())
			if err != nil {
				return nil, fmt.Errorf("parse config failed, config is not clash config or raw links or sing-box config")
			}
		}
	}

	var clashInfo ClashInfo
	var ok bool
	subscriptionUserInfo := resp.Header.Get("subscription-userinfo")
	if subscriptionUserInfo != "" {
		subscriptionUserInfo = strings.ToLower(subscriptionUserInfo)
		regTraffic := regexp.MustCompile(`upload=(\d+); download=(\d+); total=(\d+)`)
		matchTraffic := regTraffic.FindStringSubmatch(subscriptionUserInfo)
		if len(matchTraffic) == 4 {
			uploadUint64, err := strconv.ParseUint(matchTraffic[1], 10, 64)
			if err == nil {
				clashInfo.Upload = uploadUint64
				ok = true
			}
			downloadUint64, err := strconv.ParseUint(matchTraffic[2], 10, 64)
			if err == nil {
				clashInfo.Download = downloadUint64
				ok = true
			}
			totalUint64, err := strconv.ParseUint(matchTraffic[3], 10, 64)
			if err == nil {
				clashInfo.Total = totalUint64
				ok = true
			}
		}
		regExpire := regexp.MustCompile(`expire=(\d+)`)
		matchExpire := regExpire.FindStringSubmatch(subscriptionUserInfo)
		if len(matchExpire) == 2 {
			expireUint64, err := strconv.ParseUint(matchExpire[1], 10, 64)
			if err == nil {
				clashInfo.Expire = time.Unix(int64(expireUint64), 0)
				ok = true
			}
		}
	}

	cache := &Cache{
		Outbounds:  outbounds,
		LastUpdate: time.Now(),
	}
	if ok {
		cache.ClashInfo = &clashInfo
	}

	return cache, nil
}
