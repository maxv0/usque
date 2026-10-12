package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion      = 5
	socksConnect      = 1
	socksUDPAssociate = 3
	socksNoAuth       = 0
	socksUserPassword = 2
	socksNoAcceptable = 255
	socksIPv4         = 1
	socksDomain       = 3
	socksIPv6         = 4
	maxSOCKSUDPHeader = 22 // RSV, FRAG, ATYP, an IPv6 address, and a port.
)

// ParentProxy is a SOCKS5/SOCKS5H parent transport. SOCKS5 resolves target
// hostnames locally; SOCKS5H gives the hostname to the proxy to resolve.
type ParentProxy struct {
	address   string
	username  string
	password  string
	remoteDNS bool
}

// NewParentProxy parses a parent SOCKS5 or SOCKS5H URL. It returns nil when
// parent proxying is disabled.
func NewParentProxy(raw string) (*ParentProxy, error) {
	if raw == "" {
		return nil, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid parent_proxy: %w", err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("parent_proxy must use socks5 or socks5h")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("parent_proxy must include host and port")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("parent_proxy must not include a path")
	}

	p := &ParentProxy{
		address:   u.Host,
		remoteDNS: u.Scheme == "socks5h",
	}
	if u.User != nil {
		p.username = u.User.Username()
		p.password, _ = u.User.Password()
	}
	return p, nil
}

// DialContext opens a TCP connection through the configured SOCKS parent.
func (p *ParentProxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS parent does not support %s connections", network)
	}

	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, fmt.Errorf("dial parent SOCKS proxy: %w", err)
	}
	if err := p.setContextDeadline(control, ctx); err != nil {
		_ = control.Close()
		return nil, err
	}
	if _, err := p.request(control, socksConnect, address); err != nil {
		_ = control.Close()
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	return control, nil
}

// ListenPacket creates a SOCKS5 UDP ASSOCIATE connection. Closing the returned
// PacketConn also closes its TCP control connection, as required by RFC 1928.
func (p *ParentProxy) ListenPacket(ctx context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	if p == nil {
		return net.ListenUDP(network, laddr)
	}
	if network != "udp" && network != "udp4" && network != "udp6" {
		return nil, fmt.Errorf("unsupported UDP network %s", network)
	}

	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, fmt.Errorf("dial parent SOCKS proxy: %w", err)
	}
	if err := p.setContextDeadline(control, ctx); err != nil {
		_ = control.Close()
		return nil, err
	}
	udpNetwork, udpAddr, err := udpListenAddress(laddr, control.LocalAddr())
	if err != nil {
		_ = control.Close()
		return nil, err
	}

	// Bind before UDP ASSOCIATE so the server can restrict the association to
	// the actual source address and port when it chooses to enforce RFC 1928.
	udpConn, err := net.ListenUDP(udpNetwork, udpAddr)
	if err != nil {
		_ = control.Close()
		return nil, err
	}

	relay, err := p.request(control, socksUDPAssociate, udpConn.LocalAddr().String())
	if err != nil {
		_ = control.Close()
		_ = udpConn.Close()
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})

	if relay.IP.IsUnspecified() {
		proxyAddr, ok := control.RemoteAddr().(*net.TCPAddr)
		if !ok || proxyAddr.IP == nil {
			_ = control.Close()
			_ = udpConn.Close()
			return nil, fmt.Errorf("parent SOCKS proxy did not provide a usable UDP relay address")
		}
		relay.IP = append(net.IP(nil), proxyAddr.IP...)
	}

	return &socksUDPConn{
		udpConn: udpConn,
		control: control,
		relay:   relay,
	}, nil
}

// udpListenAddress selects the address family that reaches the SOCKS UDP
// relay. A parent proxy can relay to either IP family, so this must follow the
// TCP control connection instead of the MASQUE endpoint.
func udpListenAddress(requested *net.UDPAddr, controlLocal net.Addr) (string, *net.UDPAddr, error) {
	local, ok := controlLocal.(*net.TCPAddr)
	if !ok || local.IP == nil {
		return "", nil, fmt.Errorf("parent SOCKS proxy has an invalid control connection address")
	}

	port := 0
	if requested != nil {
		port = requested.Port
	}
	if local.IP.To4() != nil {
		return "udp4", &net.UDPAddr{IP: append(net.IP(nil), local.IP.To4()...), Port: port}, nil
	}
	if local.IP.To16() == nil {
		return "", nil, fmt.Errorf("parent SOCKS proxy has an invalid control connection IP")
	}
	return "udp6", &net.UDPAddr{IP: append(net.IP(nil), local.IP.To16()...), Port: port, Zone: local.Zone}, nil
}

func (p *ParentProxy) setContextDeadline(conn net.Conn, ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set parent SOCKS proxy deadline: %w", err)
		}
	}
	return nil
}

func (p *ParentProxy) request(conn net.Conn, command byte, target string) (*net.UDPAddr, error) {
	methods := []byte{socksNoAuth}
	if p.username != "" || p.password != "" {
		methods = append(methods, socksUserPassword)
	}
	if _, err := conn.Write(append([]byte{socksVersion, byte(len(methods))}, methods...)); err != nil {
		return nil, fmt.Errorf("write parent SOCKS greeting: %w", err)
	}

	var selected [2]byte
	if _, err := io.ReadFull(conn, selected[:]); err != nil {
		return nil, fmt.Errorf("read parent SOCKS greeting: %w", err)
	}
	if selected[0] != socksVersion || selected[1] == socksNoAcceptable {
		return nil, fmt.Errorf("parent SOCKS proxy rejected authentication")
	}
	if selected[1] == socksUserPassword {
		if err := p.authenticateUserPassword(conn); err != nil {
			return nil, err
		}
	} else if selected[1] != socksNoAuth {
		return nil, fmt.Errorf("unsupported parent SOCKS authentication method %d", selected[1])
	}

	address, err := p.requestAddress(target)
	if err != nil {
		return nil, err
	}
	request := append([]byte{socksVersion, command, 0}, address...)
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("write parent SOCKS request: %w", err)
	}

	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, fmt.Errorf("read parent SOCKS reply: %w", err)
	}
	if reply[0] != socksVersion {
		return nil, fmt.Errorf("invalid parent SOCKS reply version %d", reply[0])
	}
	if reply[1] != 0 {
		if command == socksUDPAssociate && reply[1] == 7 {
			return nil, fmt.Errorf("parent SOCKS proxy does not support UDP ASSOCIATE; HTTP/3/QUIC requires a SOCKS5 UDP relay")
		}
		return nil, fmt.Errorf("parent SOCKS proxy request failed: %s", socksReplyError(reply[1]))
	}

	if command != socksUDPAssociate {
		if err := discardSOCKSAddress(conn, reply[3]); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return readSOCKSUDPAddress(conn, reply[3])
}

func (p *ParentProxy) authenticateUserPassword(conn net.Conn) error {
	if len(p.username) > 255 || len(p.password) > 255 {
		return fmt.Errorf("parent SOCKS credentials are too long")
	}

	request := append([]byte{1, byte(len(p.username))}, p.username...)
	request = append(request, byte(len(p.password)))
	request = append(request, p.password...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write parent SOCKS authentication: %w", err)
	}

	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("read parent SOCKS authentication: %w", err)
	}
	if reply[0] != 1 || reply[1] != 0 {
		return fmt.Errorf("parent SOCKS authentication failed")
	}
	return nil
}

func (p *ParentProxy) requestAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS destination %q: %w", target, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS destination port %q: %w", portText, err)
	}

	if !p.remoteDNS && net.ParseIP(host) == nil {
		ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s for parent SOCKS proxy: %w", host, err)
		}
		host = ips[0].String()
	}

	return marshalSOCKSAddress(host, uint16(port))
}

func marshalSOCKSAddress(host string, port uint16) ([]byte, error) {
	var address []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			address = append([]byte{socksIPv4}, ipv4...)
		} else {
			address = append([]byte{socksIPv6}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("SOCKS hostname is too long")
		}
		address = append([]byte{socksDomain, byte(len(host))}, host...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	return append(address, portBytes[:]...), nil
}

func discardSOCKSAddress(reader io.Reader, atyp byte) error {
	length := 0
	switch atyp {
	case socksIPv4:
		length = net.IPv4len
	case socksIPv6:
		length = net.IPv6len
	case socksDomain:
		var domainLength [1]byte
		if _, err := io.ReadFull(reader, domainLength[:]); err != nil {
			return err
		}
		length = int(domainLength[0])
	default:
		return fmt.Errorf("invalid SOCKS address type %d", atyp)
	}
	_, err := io.CopyN(io.Discard, reader, int64(length+2))
	return err
}

func readSOCKSUDPAddress(reader io.Reader, atyp byte) (*net.UDPAddr, error) {
	var host string
	switch atyp {
	case socksIPv4:
		ip := make(net.IP, net.IPv4len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return nil, err
		}
		host = ip.String()
	case socksIPv6:
		ip := make(net.IP, net.IPv6len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return nil, err
		}
		host = ip.String()
	case socksDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, err
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(reader, name); err != nil {
			return nil, err
		}
		host = string(name)
	default:
		return nil, fmt.Errorf("invalid SOCKS UDP relay address type %d", atyp)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(reader, portBytes[:]); err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:])))))
}

func socksReplyError(code byte) string {
	if message, ok := map[byte]string{
		1: "general failure",
		2: "connection not allowed",
		3: "network unreachable",
		4: "host unreachable",
		5: "connection refused",
		6: "TTL expired",
		7: "command unsupported",
		8: "address type unsupported",
	}[code]; ok {
		return message
	}
	return fmt.Sprintf("unassigned error %d", code)
}

// socksUDPConn deliberately composes rather than embeds *net.UDPConn. If it
// embedded a UDPConn, quic-go would use ReadMsgUDP and WriteMsgUDP directly,
// bypassing the SOCKS UDP encapsulation implemented by ReadFrom and WriteTo.
type socksUDPConn struct {
	udpConn *net.UDPConn
	control net.Conn
	relay   *net.UDPAddr
	once    sync.Once
}

func (conn *socksUDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	packet := make([]byte, len(buffer)+maxSOCKSUDPHeader)
	for {
		n, source, err := conn.udpConn.ReadFromUDP(packet)
		if err != nil {
			return 0, nil, err
		}
		if !sameUDPAddr(source, conn.relay) {
			continue
		}

		payloadOffset, destination, err := parseSOCKSUDPPacket(packet[:n])
		if err != nil {
			return 0, nil, err
		}
		copied := copy(buffer, packet[payloadOffset:n])
		return copied, destination, nil
	}
}

func (conn *socksUDPConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	address, ok := destination.(*net.UDPAddr)
	if !ok || address.IP == nil {
		return 0, fmt.Errorf("SOCKS UDP destination must be a UDP address")
	}

	header, err := marshalSOCKSAddress(address.IP.String(), uint16(address.Port))
	if err != nil {
		return 0, err
	}
	packet := make([]byte, 3+len(header)+len(payload))
	copy(packet[3:], header)
	copy(packet[3+len(header):], payload)

	n, err := conn.udpConn.WriteToUDP(packet, conn.relay)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(payload), nil
}

func (conn *socksUDPConn) Close() error {
	var closeErr error
	conn.once.Do(func() {
		if conn.udpConn != nil {
			closeErr = conn.udpConn.Close()
		}
		if conn.control != nil {
			_ = conn.control.Close()
		}
	})
	return closeErr
}

func (conn *socksUDPConn) LocalAddr() net.Addr {
	if conn.udpConn == nil {
		return nil
	}
	return conn.udpConn.LocalAddr()
}

func (conn *socksUDPConn) SetDeadline(deadline time.Time) error {
	if conn.udpConn == nil {
		return net.ErrClosed
	}
	return conn.udpConn.SetDeadline(deadline)
}

func (conn *socksUDPConn) SetReadDeadline(deadline time.Time) error {
	if conn.udpConn == nil {
		return net.ErrClosed
	}
	return conn.udpConn.SetReadDeadline(deadline)
}

func (conn *socksUDPConn) SetWriteDeadline(deadline time.Time) error {
	if conn.udpConn == nil {
		return net.ErrClosed
	}
	return conn.udpConn.SetWriteDeadline(deadline)
}

// SetReadBuffer and SetWriteBuffer allow quic-go to tune the underlying UDP
// socket. They deliberately do not expose SyscallConn or ReadMsgUDP, which
// would let quic-go bypass the SOCKS UDP framing methods above.
func (conn *socksUDPConn) SetReadBuffer(bytes int) error {
	if conn.udpConn == nil {
		return net.ErrClosed
	}
	return conn.udpConn.SetReadBuffer(bytes)
}

func (conn *socksUDPConn) SetWriteBuffer(bytes int) error {
	if conn.udpConn == nil {
		return net.ErrClosed
	}
	return conn.udpConn.SetWriteBuffer(bytes)
}

func sameUDPAddr(first, second *net.UDPAddr) bool {
	return first != nil && second != nil && first.Port == second.Port && first.IP.Equal(second.IP)
}

func parseSOCKSUDPPacket(packet []byte) (int, *net.UDPAddr, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return 0, nil, fmt.Errorf("invalid SOCKS UDP packet")
	}
	if packet[2] != 0 {
		return 0, nil, fmt.Errorf("fragmented SOCKS UDP packets are unsupported")
	}

	offset := 4
	var host string
	switch packet[3] {
	case socksIPv4:
		if len(packet) < offset+net.IPv4len+2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case socksIPv6:
		if len(packet) < offset+net.IPv6len+2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	case socksDomain:
		if len(packet) < offset+1 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		length := int(packet[offset])
		offset++
		if len(packet) < offset+length+2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		host = string(packet[offset : offset+length])
		offset += length
	default:
		return 0, nil, fmt.Errorf("unsupported SOCKS UDP response address type %d", packet[3])
	}

	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2
	destination, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve SOCKS UDP response address: %w", err)
	}
	return offset, destination, nil
}
