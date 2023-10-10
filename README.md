# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## Support

https://community.sagernet.org/c/sing-box/

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```

### ProxyProvider 支持

- 编译时需要使用 `with_proxyprovider` tag

##### 配置详解
```json5
{
    "proxyproviders": [
        {
            "tag": "proxy-provider-x", // 标签，必填，用于区别不同的 proxy-provider，不可重复，设置后outbounds会暴露一个同名的selector出站
            "url": "", // 订阅链接，必填，支持Clash订阅链接，支持普通分享链接，支持Sing-box订阅链接
            "cache_file": "/tmp/proxy-provider-x.cache", // 缓存文件，选填，强烈建议填写，可以加快启动速度
            "update_interval": "4h", // 更新间隔，选填，仅填写 cache_file 有效，若当前缓存文件已经超过该时间，将会进行后台自动更新
            "request_timeout": "10s", // 请求超时时间
            "dns": "tls://223.5.5.5", // 使用自定义 DNS 请求订阅域名
            "tag_format": "proxy-provider - %s", // 如果有多个订阅并且订阅间存在重名节点，可以尝试使用，其中 %s 为占位符，会被替换为原节点名。比如：原节点名："HongKong 01"，tag_format设置为 "PP - %s"，替换后新节点名会更变为 "PP - HongKong 01"，以解决节点名冲突的问题
            "global_filter": {
                "white_mode": true, // 白名单模式，匹配的节点会被保留，不匹配的节点会被删除
                "rules": [], // 规则，Golang 正则表达式
            },
            "dialer": {}, // 附加在节点 outbound 配置的 Dial 字段
            "request_dialer": {}, // 请求时使用的 Dial 字段配置，detour 字段无效
            "running_detour": "", // 运行时后台自动更新所使用的 outbound
            "groups": [ // 自定义分组
                {
                    "tag": "", // outbound tag，必填
                    "type": "selector", // outbound 类型，必填，仅支持selector, urltest
                    "filter": {}, // 节点过滤规则，选填，详见上global_filter字段
                    ... Selector 或 URLTest 其他字段配置
                }
            ]
        }
    ]
}
```

##### DNS 支持格式
```
tcp://1.1.1.1
tcp://1.1.1.1:53
tcp://[2606:4700:4700::1111]
tcp://[2606:4700:4700::1111]:53
udp://1.1.1.1
udp://1.1.1.1:53
udp://[2606:4700:4700::1111]
udp://[2606:4700:4700::1111]:53
tls://1.1.1.1
tls://1.1.1.1:853
tls://[2606:4700:4700::1111]
tls://[2606:4700:4700::1111]:853
tls://1.1.1.1/?sni=cloudflare-dns.com
tls://1.1.1.1:853/?sni=cloudflare-dns.com
tls://[2606:4700:4700::1111]/?sni=cloudflare-dns.com
tls://[2606:4700:4700::1111]:853/?sni=cloudflare-dns.com
https://1.1.1.1
https://1.1.1.1:443/dns-query
https://[2606:4700:4700::1111]
https://[2606:4700:4700::1111]:443
https://1.1.1.1/dns-query?sni=cloudflare-dns.com
https://1.1.1.1:443/dns-query?sni=cloudflare-dns.com
https://[2606:4700:4700::1111]/dns-query?sni=cloudflare-dns.com
https://[2606:4700:4700::1111]:443/dns-query?sni=cloudflare-dns.com
1.1.1.1 => udp://1.1.1.1:53
1.1.1.1:53 => udp://1.1.1.1:53
[2606:4700:4700::1111] => udp://[2606:4700:4700::1111]:53
[2606:4700:4700::1111]:53 => udp://[2606:4700:4700::1111]:53
```

##### 简易配置示例
```json5
{
    "proxyproviders": [
        {
            "tag": "proxy-provider",
            "url": "你的订阅链接",
            "cache_file": "缓存文件路径",
            "dns": "tcp://223.5.5.5",
            "update_interval": "4h", // 自动更新缓存
            "request_timeout": "10s" // 请求超时时间
        }
    ]
}
```


### RuleProvider 支持

- 编译时需要使用 `with_ruleprovider` tag

##### 配置详解
```json5
{
    "ruleproviders": [
        {
            "tag": "rule-provider-x", // 标签，必填，用于区别不同的 rule-provider，不可重复
            "url": "", // 规则订阅链接，必填，仅支持Clash订阅规则
            "behavior": "", // 规则类型，必填，可选 domain / ipcidr / classical
            "format": "". // 规则格式，选填，可选 yaml / text，默认 yaml
            "cache_file": "/tmp/rule-provider-x.cache", // 缓存文件，选填，强烈建议填写，可以加快启动速度
            "update_interval": "4h", // 更新间隔，选填，仅填写 cache_file 有效，若当前缓存文件已经超过该时间，将会进行后台自动更新
            "request_timeout": "10s", // 请求超时时间
            "dns": "tls://223.5.5.5", // 使用自定义 DNS 请求订阅域名，格式与 proxyprovider 相同
            "request_dialer": {}, // 请求时使用的 Dial 字段配置，detour 字段无效
            "running_detour": "" // 运行时后台自动更新所使用的 outbound
        }
    ]
}
```

##### 用法

用于 Route Rule 或者 DNS Rule

假设规则有以下内容：
```yaml
payload:
  - '+.google.com'
  - '+.github.com'
```

```json5
{
    "dns": {
        "rules": [
            {
                "@rule_provider": "rule-provider-x",
                "server": "proxy-dns"
            }
        ]
    },
    "route": {
        "rules": [
            {
                "@rule_provider": "rule-provider-x",
                "outbound": "proxy-out"
            }
        ]
    }
}
```
等效于
```json5
{
    "dns": {
        "rules": [
            {
                "domain_suffix": [
                    ".google.com",
                    ".github.com"
                ],
                "server": "proxy-dns"
            }
        ]
    },
    "route": {
        "rules": [
            {
                "domain_suffix": [
                    ".google.com",
                    ".github.com"
                ],
                "outbound": "proxy-out"
            }
        ]
    }
}
```

##### 注意

- 由于 sing-box 规则支持与 Clash 可能不同，某些无法在 sing-box 上使用的规则会被**自动忽略**，请注意
- 不支持 **logical** 规则，由于规则数目可能非常庞大，设置多个 @rule_provider 靶点可能会导致内存飙升和性能问题（笛卡儿积）
- DNS Rule 不支持某些类型，如：GeoIP IP-CIDR IP-CIDR6，这是因为 sing-box 程序逻辑所决定的
- 目前支持的 Clash 规则类型：

```
Clash 类型       ==>     对于的 sing-box 配置

DOMAIN           ==> domain
DOMAIN-SUFFIX    ==> domain_suffix
DOMAIN-KEYWORD   ==> domain_keyword
GEOSITE          ==> geosite
GEOIP            ==> geoip
IP-CIDR          ==> ip_cidr
IP-CIDR6         ==> ip_cidr
SRC-IP-CIDR      ==> source_ip_cidr
SRC-PORT         ==> source_port
DST-PORT         ==> port
PROCESS-NAME     ==> process_name
PROCESS-PATH     ==> process_path
NETWORK          ==> network
```

### Tor No Fatal 启动

```json
{
    "outbounds": [
        {
            "tag": "tor-out",
            "type": "tor",
            "no_fatal": true // 启动时将 tor outbound 启动置于后台，加快启动速度，但启动失败会导致无法使用
        }
    ]
}
```

### Clash Dashboard 内置支持

- 编译时需要使用 `with_clash_dashboard` tag
- 编译前需要先初始化 web 文件

```
使用 yacd 作为 Clash Dashboard：make init_yacd
使用 metacubexd 作为 Clash Dashboard：make init_metacubexd
清除 web 文件：make clean_clash_dashboard
```

##### 用法

```json5
{
    "experimental": {
        "clash_api": {
            "external_controller": "0.0.0.0:9090",
            //"external_ui": "" // 无需填写
            "external_ui_buildin": true // 启用内置 Clash Dashboard
        }
    }
}
```

### Geo Resource 自动更新支持

##### 用法
```json5
{
    "route": {
        "geosite": {
            "path": "/temp/geosite.db",
            "auto_update_interval": "12h" // 更新间隔，在程序运行时会间隔时间自动更新
        },
        "geoip": {
            "path": "/temp/geoip.db",
            "auto_update_interval": "12h"
        }
    }
}
```

- 支持在 Clash API 中调用 API 更新 Geo Resource
