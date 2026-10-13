package internal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestParentProxyDialContextCancellationInterruptsGreeting(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy := &ParentProxy{address: listener.Addr().String()}
	result := make(chan error, 1)
	go func() {
		_, err := proxy.DialContext(ctx, "tcp", "198.51.100.7:443")
		result <- err
	}()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("parent proxy did not accept the control connection")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DialContext did not return after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("control connection was not closed after cancellation")
	}
}

func TestMaxSOCKSUDPHeaderIncludesLongestDomain(t *testing.T) {
	const longestDomainHeader = 3 + 1 + 1 + 255 + 2
	if maxSOCKSUDPHeader != longestDomainHeader {
		t.Fatalf("maxSOCKSUDPHeader = %d, want %d", maxSOCKSUDPHeader, longestDomainHeader)
	}
}

func TestSOCKSUDPConnKeepsQUICOnSOCKSPath(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	conn := &socksUDPConn{
		udpConn: client,
		relay:   relay.LocalAddr().(*net.UDPAddr),
	}
	defer func() { _ = conn.Close() }()

	destination := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	payload := []byte("QUIC packet")
	relayResult := make(chan error, 1)
	go func() {
		packet := make([]byte, 2048)
		n, source, err := relay.ReadFromUDP(packet)
		if err != nil {
			relayResult <- err
			return
		}

		header, err := marshalSOCKSAddress(destination.IP.String(), uint16(destination.Port))
		if err != nil {
			relayResult <- err
			return
		}
		expected := append([]byte{0, 0, 0}, header...)
		expected = append(expected, payload...)
		if !bytes.Equal(packet[:n], expected) {
			relayResult <- &packetMismatchError{got: packet[:n], want: expected}
			return
		}

		response := append([]byte{0, 0, 0}, header...)
		response = append(response, []byte("response")...)
		_, err = relay.WriteToUDP(response, source)
		relayResult <- err
	}()

	if n, err := conn.WriteTo(payload, destination); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	} else if n != len(payload) {
		t.Fatalf("WriteTo() bytes = %d, want %d", n, len(payload))
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, address, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if got := string(buffer[:n]); got != "response" {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, "response")
	}
	if got := address.(*net.UDPAddr); !sameUDPAddr(got, destination) {
		t.Fatalf("ReadFrom() address = %s, want %s", got, destination)
	}
	if err := <-relayResult; err != nil {
		t.Fatal(err)
	}
}

func TestListenPacketAssociatesActualUDPPort(t *testing.T) {
	controlListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = controlListener.Close() }()

	udpRelay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpRelay.Close() }()

	associatePort := make(chan int, 1)
	serverErr := make(chan error, 1)
	go func() {
		control, err := controlListener.AcceptTCP()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = control.Close() }()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(control, greeting); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(greeting, []byte{socksVersion, 1, socksNoAuth}) {
			serverErr <- &packetMismatchError{got: greeting, want: []byte{socksVersion, 1, socksNoAuth}}
			return
		}
		if _, err := control.Write([]byte{socksVersion, socksNoAuth}); err != nil {
			serverErr <- err
			return
		}

		request := make([]byte, 10)
		if _, err := io.ReadFull(control, request); err != nil {
			serverErr <- err
			return
		}
		if request[0] != socksVersion || request[1] != socksUDPAssociate || request[3] != socksIPv4 {
			serverErr <- &packetMismatchError{got: request[:4], want: []byte{socksVersion, socksUDPAssociate, 0, socksIPv4}}
			return
		}
		associatePort <- int(binary.BigEndian.Uint16(request[8:10]))

		relayAddr := udpRelay.LocalAddr().(*net.UDPAddr)
		reply := append([]byte{socksVersion, 0, 0, socksIPv4}, relayAddr.IP.To4()...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(relayAddr.Port))
		reply = append(reply, port[:]...)
		_, err = control.Write(reply)
		serverErr <- err
	}()

	proxy := &ParentProxy{address: controlListener.Addr().String()}
	packetConn, err := proxy.ListenPacket(context.Background(), "udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer func() { _ = packetConn.Close() }()

	actualPort := packetConn.LocalAddr().(*net.UDPAddr).Port
	if associatedPort := <-associatePort; associatedPort != actualPort {
		t.Fatalf("UDP ASSOCIATE port = %d, want bound UDP port %d", associatedPort, actualPort)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestSOCKSUDPConnDoesNotExposeUDPOptimizations(t *testing.T) {
	var packetConn net.PacketConn = &socksUDPConn{}
	if _, ok := packetConn.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); !ok {
		t.Fatal("socksUDPConn does not expose buffer sizing for quic-go")
	}
	if _, ok := packetConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		t.Fatal("socksUDPConn exposes SyscallConn, allowing quic-go to bypass SOCKS UDP encapsulation")
	}
	if _, ok := packetConn.(interface {
		ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	}); ok {
		t.Fatal("socksUDPConn exposes ReadMsgUDP, allowing quic-go to bypass SOCKS UDP encapsulation")
	}
}

type packetMismatchError struct {
	got  []byte
	want []byte
}

func (err *packetMismatchError) Error() string {
	return "unexpected SOCKS packet"
}
