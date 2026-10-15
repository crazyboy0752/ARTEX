package server

import (
	"net/url"
	"testing"
)

func TestSocks5DialAddressSupportsIPv6(t *testing.T) {
	u, err := url.Parse("socks5://[::1]:1080")
	if err != nil {
		t.Fatal(err)
	}
	if got := socks5DialAddress(u); got != "[::1]:1080" {
		t.Fatalf("unexpected dial address %q", got)
	}
}

func TestSocks5DialAddressUsesDefaultPort(t *testing.T) {
	u, err := url.Parse("socks5://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := socks5DialAddress(u); got != "127.0.0.1:1080" {
		t.Fatalf("unexpected dial address %q", got)
	}
}

func TestValidateProxyEgressDistinguishesSameAndDifferentIPs(t *testing.T) {
	base := proxyProbeResult{OK: true, Reachable: true, EgressIP: "203.0.113.10", DirectIP: "203.0.113.10"}
	if got := validateProxyEgress("socks5://127.0.0.1:1080", base); got.OK || got.Error == "" {
		t.Fatalf("same IP must be marked ineffective, got %#v", got)
	}

	base.EgressIP = "198.51.100.20"
	if got := validateProxyEgress("socks5://127.0.0.1:1080", base); !got.OK || got.Error != "" {
		t.Fatalf("distinct egress should pass, got %#v", got)
	}
}
