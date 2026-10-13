package internal

import "testing"

func TestParsePortMapping(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		bind       []string
		localPort  int
		remoteHost string
		remotePort int
	}{
		{
			name:       "default bind IPv4 remote",
			input:      "8080:192.0.2.10:443",
			bind:       []string{"127.0.0.1", "::1"},
			localPort:  8080,
			remoteHost: "192.0.2.10",
			remotePort: 443,
		},
		{
			name:       "explicit bind hostname remote preserved",
			input:      "localhost:8080:example.com:443",
			bind:       []string{"127.0.0.1", "::1"},
			localPort:  8080,
			remoteHost: "example.com",
			remotePort: 443,
		},
		{
			name:       "bracketed IPv6 bind and remote",
			input:      "[::1]:8080:[2001:db8::1]:443",
			bind:       []string{"::1"},
			localPort:  8080,
			remoteHost: "2001:db8::1",
			remotePort: 443,
		},
		{
			name:       "unbracketed IPv6 remote",
			input:      "[::1]:8080:2001:db8::1:443",
			bind:       []string{"::1"},
			localPort:  8080,
			remoteHost: "2001:db8::1",
			remotePort: 443,
		},
		{
			name:       "wildcard bind",
			input:      "*:8080:example.com:443",
			bind:       []string{"0.0.0.0"},
			localPort:  8080,
			remoteHost: "example.com",
			remotePort: 443,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParsePortMapping(test.input)
			if err != nil {
				t.Fatalf("ParsePortMapping() error = %v", err)
			}
			if !containsString(test.bind, got.BindAddress) || got.LocalPort != test.localPort || got.RemoteIP != test.remoteHost || got.RemotePort != test.remotePort {
				t.Fatalf("ParsePortMapping() = %+v, want bind=%v local=%d remote=%q:%d", got, test.bind, test.localPort, test.remoteHost, test.remotePort)
			}
		})
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestParsePortMappingRejectsMalformedInput(t *testing.T) {
	tests := []string{
		"",
		"8080",
		"localhost:0:example.com:443",
		"localhost:8080:example.com:0",
		"localhost:8080:not-a-host:443",
		"[::1:8080:example.com:443",
		"localhost:8080:[2001:db8::1:443",
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			if _, err := ParsePortMapping(test); err == nil {
				t.Fatal("ParsePortMapping() error = nil")
			}
		})
	}
}
