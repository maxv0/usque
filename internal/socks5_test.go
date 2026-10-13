package internal

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/txthinking/socks5"
)

func TestSOCKS5UDPFlowReservationIsAtomic(t *testing.T) {
	server := &SOCKS5Server{udpFlows: make(map[socksUDPFlowKey]*socksUDPFlow)}
	key := socksUDPFlowKey{client: "127.0.0.1:1000", destination: "198.51.100.7:443"}

	const requests = 64
	start := make(chan struct{})
	owners := make(chan bool, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, owner := server.reserveUDPFlow(key)
			owners <- owner
		}()
	}
	close(start)
	wg.Wait()
	close(owners)

	ownerCount := 0
	for owner := range owners {
		if owner {
			ownerCount++
		}
	}
	if ownerCount != 1 {
		t.Fatalf("flow owners = %d, want 1", ownerCount)
	}
	if len(server.udpFlows) != 1 {
		t.Fatalf("flow count = %d, want 1", len(server.udpFlows))
	}
}

func TestNewSOCKS5ServerDoesNotReplaceDependencyDialers(t *testing.T) {
	originalTCP := socks5.DialTCP
	originalUDP := socks5.DialUDP
	defer func() {
		socks5.DialTCP = originalTCP
		socks5.DialUDP = originalUDP
	}()

	sentinel := errors.New("sentinel dialer")
	socks5.DialTCP = func(string, string, string) (net.Conn, error) {
		return nil, sentinel
	}
	socks5.DialUDP = func(string, string, string) (net.Conn, error) {
		return nil, sentinel
	}

	_, err := NewSOCKS5Server(SOCKS5Config{
		Addr:    "127.0.0.1:0",
		DialTCP: func(context.Context, string, string) (net.Conn, error) { return nil, nil },
		TCPOnly: true,
	})
	if err != nil {
		t.Fatalf("NewSOCKS5Server() error = %v", err)
	}
	if _, err := socks5.DialTCP("tcp", "", "198.51.100.7:443"); !errors.Is(err, sentinel) {
		t.Fatalf("NewSOCKS5Server replaced socks5.DialTCP: %v", err)
	}
	if _, err := socks5.DialUDP("udp", "", "198.51.100.7:443"); !errors.Is(err, sentinel) {
		t.Fatalf("NewSOCKS5Server replaced socks5.DialUDP: %v", err)
	}
}
