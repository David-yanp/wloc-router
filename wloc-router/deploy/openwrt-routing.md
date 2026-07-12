# OpenWrt routing notes

This service should only receive WLOC traffic from selected Apple devices. Do not globally hijack all Apple devices unless that is intentional.

## DNS

The simplest first test is host override:

```sh
uci add_list dhcp.@dnsmasq[0].address='/gs-loc.apple.com/192.168.1.254'
uci add_list dhcp.@dnsmasq[0].address='/gs-loc-cn.apple.com/192.168.1.254'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

This is global. Use it only for a short test, or replace it with source-scoped DNS behavior in the existing policy stack.

## Port redirect

If clients connect to `192.168.1.254:443` after DNS override, redirect only the selected source IP to the service port:

```sh
nft add rule inet fw4 dstnat ip saddr 192.168.1.37 ip daddr 192.168.1.254 tcp dport 443 redirect to :9443
```

Persist this through the router's normal firewall include mechanism after testing.

## Avoid upstream loop

If OpenWrt itself resolves `gs-loc*.apple.com` back to `192.168.1.254`, the service will call itself instead of Apple. Use one of these approaches:

- Keep DNS hijack source-scoped so router-originated DNS still resolves Apple normally.
- Fill `upstream_resolve` in `/etc/wloc-router/config.toml` with real Apple edge IPs.
- Run the service with an upstream DNS path that bypasses local dnsmasq overrides.

## Quick checks

```sh
logread -f | grep wloc-router
curl -k --resolve gs-loc.apple.com:9443:192.168.1.254 \
  'https://gs-loc.apple.com:9443/wloc-settings/save?action=query'
```
