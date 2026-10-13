# Static Code Audit Report

Audit date: 2026-10-13  
Scope: all first-party Go source, build/release configuration, and the current
parent-SOCKS implementation. Third-party module source was not audited. This
is a static review: the local checkout has no `go` or `gofmt` executable, so
the findings have not been compiled or exercised here.

Severity labels describe practical impact for the default command-line use.
"Confirmed" means the faulty control flow is demonstrated by the code itself;
"high-confidence" means it depends on a normal runtime condition stated in the
entry.

## Critical and high severity

### BUG-001 — Config writes can expose secrets and destroy the old config

**Status:** confirmed  
**Evidence:** `config/config.go:68-81`

`SaveConfig` ignores its receiver, opens the final pathname with `os.Create`,
and writes the global `AppConfig` directly. The file contains the private key,
access token, and possibly parent-proxy credentials. `os.Create` is subject to
the process umask, truncates an existing config before encoding is known to
succeed, and provides no crash-safe replacement. A full disk, process crash,
or write error can therefore leave an empty/partial config and default Unix
permissions can make credentials readable by other local users.

**Fix:** serialize the receiver to a same-directory temporary file created
with mode `0600`, `Sync` and close it, then atomically replace the destination
(`Rename`, with the Windows replacement semantics handled explicitly). Preserve
the existing mode where appropriate and remove the temporary file on every
error. Change `SaveConfig`, `GetEcPrivateKey`, and
`GetEcEndpointPublicKey` to use `c`, not `AppConfig`.

### BUG-002 — HTTP forward proxy leaks proxy credentials and hop-by-hop headers

**Status:** confirmed  
**Evidence:** `cmd/httpproxy.go:373-414`

For non-CONNECT requests, the proxy clones every inbound header and forwards
it to the origin. This includes `Proxy-Authorization`, so a configured proxy
username/password can be disclosed to arbitrary destination servers. It also
forwards hop-by-hop headers (`Connection`, headers named by `Connection`,
`Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`) in both
directions, violating HTTP proxy semantics and potentially corrupting a
request/response.

**Fix:** create a shared helper which first removes all RFC hop-by-hop headers,
including names nominated by the `Connection` header, and always removes
`Proxy-Authorization` and `Proxy-Connection` before sending upstream. Apply
the corresponding response-side filtering before copying headers to the
client. Add an integration test that proves credentials cannot reach an origin
server.

### BUG-003 — Public HTTP listeners have no server timeouts

**Status:** confirmed  
**Evidence:** `cmd/httpproxy.go:266-284`, `cmd/l4_http_proxy.go:33-51`

Both HTTP proxy commands listen on `0.0.0.0` by default but construct an
`http.Server` with no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or
`IdleTimeout`. A remote client can hold many partial request headers open
indefinitely (Slowloris), consuming file descriptors and goroutines.

**Fix:** set conservative, documented defaults—at minimum a
`ReadHeaderTimeout`, `IdleTimeout`, and a bounded `WriteTimeout`—and make them
flags if workloads need different values. Add a connection limit or semaphore
around accepted proxy clients for a public-facing deployment.

### BUG-004 — Register and enrol can panic on a valid-HTTP malformed API reply

**Status:** confirmed  
**Evidence:** `cmd/register.go:90-105`, `cmd/enroll.go:105-120`

Both commands index `Peers[0]` and strip endpoint strings with fixed byte
slices. An empty `peers` array, a short endpoint, an IPv4 value not ending in
`:0`, or an IPv6 value not matching the assumed `[address]:0` form panics the
process. The same response is then never saved or reported clearly.

**Fix:** centralize conversion of `models.AccountData` into `config.Config`.
Check that a peer exists, validate non-empty key/address fields, and parse
endpoints with `net.SplitHostPort` plus `net.ParseIP` rather than slicing.
Return contextual errors before changing `AppConfig` or writing the file. Add
table-driven tests for empty, malformed, IPv4, and IPv6 endpoint replies.

### BUG-005 — Invalid-public-key recovery in `enroll` is unreachable

**Status:** confirmed  
**Evidence:** `api/cloudflare.go:185-190`, `cmd/enroll.go:76-94`

`EnrollKey` returns `*models.APIError`, but `enroll` asserts the error as the
non-pointer `models.APIError`. The assertion always fails, so API error 1001
does not offer key regeneration and instead terminates the command.

**Fix:** use `var apiErr *models.APIError; if errors.As(err, &apiErr) &&
apiErr.HasErrorCode(...) { ... }`. Add a unit test that returns a pointer API
error and verifies the regeneration branch is selected.

### BUG-006 — IPv6 port mappings are parsed incorrectly; hostname mappings leak DNS

**Status:** confirmed  
**Evidence:** `internal/utils.go:156-211`, `cmd/portfw.go:375-400`

`strings.Split(port, ":")` splits inside bracketed IPv6 literals despite the
comment claiming support. For example, `[::1]:8080:2001:db8::1:443` cannot be
parsed. In addition, every remote hostname is resolved immediately using the
host resolver. That prevents tunnel-side name resolution for local forwarding
and leaks the name outside the tunnel before a connection is established.

**Fix:** define an unambiguous grammar and parse it with
`net.SplitHostPort`/`netip.ParseAddrPort` (or use separate structured flags).
Keep remote hostnames unmodified in `PortMapping`; resolve them only in the
appropriate connection path, through `tunNet` for `-L` and through the chosen
host/parent-proxy policy for `-R`. Add IPv4, bracketed IPv6, hostname, and
malformed-input tests.

### BUG-007 — The built-in SOCKS5 UDP relay races duplicate flows

**Status:** confirmed  
**Evidence:** `internal/socks5.go:364-447`

UDP datagrams are handled concurrently. Two first packets for the same
`src + dst` can both miss `UDPExchanges.Get`, both create a remote socket, and
overwrite the same map entry. Either cleanup goroutine can then delete the
other flow's entry and both consume the global relay budget. This creates
duplicate packets, premature flow removal, and a bounded but avoidable
resource-exhaustion path under normal UDP retransmission.

**Fix:** make lookup-or-create atomic, for example with a server-owned mutex
or a per-flow `singleflight`/pending entry. Use a structured key (client
address plus destination) instead of string concatenation. Ensure only the
creator owns the semaphore token and deletion, and regression-test concurrent
first packets.

### BUG-008 — Parent-proxy setup can ignore cancellation and hang L4 dials

**Status:** confirmed  
**Evidence:** `internal/parentproxy.go:69-151`,
`internal/parentproxy.go:260-278`, `api/l4proxy.go:230-293`

The SOCKS greeting/request reads have a deadline only when the caller supplied
one, and local SOCKS DNS uses `context.Background()`. Cancellation alone does
not interrupt an in-progress greeting, reply read, or lookup. Worse,
`listenUDPForEndpoint` discards the caller's L4 deadline and calls
`ListenPacket(context.Background(), ...)`. An unreachable or non-responsive
parent can therefore outlive the advertised L4 connect timeout and leave a
dial stuck.

**Fix:** thread the dial context through `getOrCreateClientConn`,
`listenUDPForEndpoint`, `ListenPacket`, `request`, and `requestAddress`. Use
context-aware DNS and arrange for `ctx.Done()` to close the control socket when
there is no deadline. Give control-plane API calls an explicit bounded timeout
as well. Test cancellation during SOCKS greeting, UDP ASSOCIATE, and DNS.

### BUG-009 — HTTP/3 SOCKS reply buffer is too small for legal domain headers

**Status:** confirmed  
**Evidence:** `internal/parentproxy.go:25`, `internal/parentproxy.go:383-400`

`maxSOCKSUDPHeader` is `22`, which fits an IPv6 SOCKS UDP header, but SOCKS5
also permits a domain name up to 255 bytes. A legal domain-form UDP response
header is 262 bytes (`RSV`, `FRAG`, `ATYP`, length, name, port). Such a reply
can truncate payload before `parseSOCKSUDPPacket` runs; no truncation error is
reported to QUIC.

**Fix:** size the receive frame for the actual maximum header (262 bytes), or
read into a maximum UDP datagram buffer and reject/report truncation before
copying. Add tests for IPv4, IPv6, and a 255-byte domain response header.

### BUG-010 — Android resolver can return `(nil, nil)` when every DNS dial fails

**Status:** confirmed  
**Evidence:** `dns_android.go:31-63`

When all workers fail, the goroutine closes `result`. Receiving from that
closed `chan net.Conn` yields a nil connection, but the select returns it with
a nil error. The resolver caller may then dereference a nil connection or
report an unrelated failure. `errChan` is populated but never read, and the
hard-coded timer ignores cancellation semantics.

**Fix:** send a result struct containing both connection and error, check the
receive `ok` value, retain the last meaningful error, and select on
`ctx.Done()` rather than an independent `time.After`. Close any losing
successful UDP connections. Add all-fail, first-success, cancellation, and
timeout tests.

### BUG-011 — Tunnel recovery can stall forever and drops the wake-up packet

**Status:** confirmed  
**Evidence:** `api/tunnel.go:240-254`, `api/tunnel.go:305-410`

In on-demand mode, the packet that wakes an idle tunnel is read, returned to
the pool, and never sent. Initial TCP SYNs depend on retransmission. During a
live tunnel failure, a blocked device reader cannot be cancelled; after two
seconds the code intentionally starts a new cycle while the old reader holds
`readMu`. The next reader blocks on that mutex and recovery can stop
permanently if the old device read never returns.

**Fix:** retain and send the wake-up packet after connecting. Architect one
long-lived device-reader goroutine that feeds a channel to connection-specific
writers, or close/unblock the device before reconnecting; do not begin another
reader until the old one has terminated. Make shutdown/reconnect state
explicit and test a device whose `ReadPacket` blocks indefinitely.

### BUG-012 — Parent-proxy routing is not complete for all outbound traffic

**Status:** confirmed for remote port forwards; policy gap for local DNS  
**Evidence:** `cmd/portfw.go:387-390`, `internal/dns.go:73-86`,
`internal/dns.go:134-145`

With `parent_proxy` configured, `portfw -R` opens its target using raw
`net.Dial("tcp", ...)`, bypassing the parent entirely. Local-DNS modes also
send direct UDP DNS to `-d` servers. The README currently promises a parent
for "all outbound usque traffic", so these paths violate that contract (or,
for local DNS, leave an important exception undocumented).

**Fix:** make the outbound-routing policy explicit and inject a parent-aware
dialer/resolver into remote forwarding and local-DNS code. For SOCKS5 parents,
use TCP CONNECT where applicable and UDP ASSOCIATE for DNS, or clearly define
and document that `--local-dns` is intentionally a direct-host escape hatch.
Add routing tests which assert no raw socket is opened while a parent is set.

### BUG-013 — CONNECT and port-forward relays destroy TCP half-close

**Status:** confirmed  
**Evidence:** `cmd/httpproxy.go:355-363`, `cmd/portfw.go:375-400`

The first copy goroutine defers `Close` on both connections. When a client
finishes writing but still expects a response, it closes the destination before
the reverse copy can complete. This truncates protocols that rely on a TCP
half-close, including common request/response uploads.

**Fix:** use the existing `api.RelayTCP` pattern (or one shared relay helper)
that calls `CloseWrite` after each direction reaches EOF, waits for both
directions, and only then closes both connections. Cover client half-close and
server half-close in tests.

### BUG-014 — Control-plane requests have no overall timeout

**Status:** confirmed  
**Evidence:** `api/cloudflare.go:17-25` and all request constructors in that
file

Registration, enrolment, and account operations use `http.DefaultClient` or a
fresh client without `Timeout`; request constructors also do not attach a
bounded context. A stalled TCP connection, response body, or SOCKS parent can
hang an interactive command indefinitely.

**Fix:** define an API client with a documented timeout and transport timeouts
(`DialContext`, TLS handshake, response-header, and idle). Build requests with
`http.NewRequestWithContext`, allow the CLI to supply a cancellation context,
and preserve useful timeout errors.

### BUG-015 — HTTP proxy DNS ignores both failover servers and `--dns-timeout`

**Status:** confirmed  
**Evidence:** `internal/dns.go:121-145`, `internal/dns.go:148-165`,
`cmd/httpproxy.go:191-249`

The HTTP proxy accepts a DNS server list and `--dns-timeout`, but
`GetProxyResolver` never uses its `timeout` argument. Both resolver factories
unconditionally dial `dnsAddrs[0]`, ignoring every configured fallback. A
temporary outage of the first DNS server therefore makes the HTTP proxy unable
to resolve names even when the remaining default servers are healthy.

**Fix:** implement a context-aware resolver dialer that tries the configured
servers with the supplied deadline (the existing `TunnelDNSResolver` supplies
a useful model), and use it in `GetProxyResolver`. Add tests that verify the
first-server failure falls back to the second server and that the configured
timeout is observed.

## Medium severity

### BUG-016 — Partial proxy credentials silently create an unauthenticated proxy

**Status:** confirmed  
**Evidence:** `cmd/httpproxy.go:225-230`, `cmd/l4_http_proxy.go:28-31`,
`cmd/socks.go:202-208`

HTTP and L4 HTTP authentication are enabled only if *both* strings are
non-empty. Passing only `--username` or only `--password` silently leaves a
default-public listener unauthenticated. SOCKS passes the partial values to a
third-party server, giving inconsistent behavior between commands.

**Fix:** reject an incomplete username/password pair before binding. If empty
passwords are meant to be supported, add an explicit opt-in and make all proxy
modes implement the same rule. Prefer a loopback default bind for an
unauthenticated listener, or require an explicit public-bind acknowledgement.

### BUG-017 — TLS pinning accepts an empty certificate list

**Status:** high-confidence defense-in-depth issue  
**Evidence:** `api/masque.go:48-87`

Normal verification is disabled unconditionally and the replacement pinning
callback returns success if `rawCerts` is empty. A normal full handshake sends
a certificate, but the secure mode should fail closed rather than treating an
absent certificate as a verified endpoint.

**Fix:** return a descriptive error for an empty certificate list and use
`VerifyConnection` where appropriate so the exact TLS state is inspected.
Keep the intentional public-key pin, but add tests for empty, unparsable,
wrong-key, and expected-key certificate input.

### BUG-018 — SOCKS server instances overwrite package-global dialers

**Status:** confirmed  
**Evidence:** `internal/socks5.go:23-25`, `internal/socks5.go:61-65`

`NewSOCKS5Server` assigns `socks5.DialTCP` and `socks5.DialUDP`, which are
globals in the dependency. Creating a second server changes routing for the
first server. This makes in-process tests and future multi-listener use racey
and can send a connection through the wrong tunnel.

**Fix:** avoid a dependency API based on mutable globals, fork/wrap it with
per-server dial functions, or serialize and prohibit multiple instances with a
clear error. Run `go test -race` with two differently configured servers once
the design is corrected.

### BUG-019 — Hook logging can deadlock, and reconnects can accumulate hooks

**Status:** confirmed  
**Evidence:** `api/hooks.go:27-77`, `api/tunnel.go:298-303`,
`api/tunnel.go:381-386`

`bufio.Scanner` stops reading when a hook writes a line over 1 MiB, but the
child process can remain blocked writing to the now-undrained pipe while
`RunHook` waits for it to exit. Separately, every reconnect launches a new
unbounded fire-and-forget process; a flapping connection can accumulate stuck
hooks.

**Fix:** stream output with a bounded chunk reader (or keep draining after a
scanner error), log reader errors, run hooks with a timeout/cancellation
policy, and set a per-event concurrency limit. Document whether a later event
replaces, queues, or skips a still-running hook.

### BUG-020 — Native TUN creation leaks a device when post-create setup fails

**Status:** confirmed  
**Evidence:** `cmd/nativetun_linux.go:19-70`, `cmd/nativetun_windows.go:17-57`

After the TUN device is created, failures while looking up the Linux link,
setting addresses/MTU, or configuring Windows `netsh` return without closing
the newly created device. This can leave a stray interface and handle behind.

**Fix:** immediately install deferred cleanup after successful creation; cancel
it only once all setup has succeeded. On Linux, delete a non-persistent
interface if closing alone does not remove it. Report the cleanup failure
alongside the original setup error.

### BUG-021 — Configuration methods ignore their receiver and rely on mutable global state

**Status:** confirmed  
**Evidence:** `config/config.go:68-124`

The three `Config` methods are declared as methods but read/write `AppConfig`.
Calling the methods on a copied or independently loaded `Config` silently uses
different data. This makes future tests and concurrent/multi-profile use
incorrect, and contributed to the unsafe persistence design.

**Fix:** use named receiver `c *Config` throughout; make `LoadConfig` return a
`Config` (or load into a supplied value) and keep global state only in the CLI
layer if it is still desired.

### BUG-022 — HTTP forwarding churns transports and has no destination connection policy

**Status:** confirmed  
**Evidence:** `cmd/httpproxy.go:373-405`, `cmd/l4_http_proxy.go:91-113`

The standard HTTP proxy makes a new `http.Transport` for every request and
does not close its idle connections. Under load this creates needless TCP/TUN
connection churn and temporarily retained idle connections. Neither forward
proxy defines destination dial, TLS-handshake, or response-header timeouts.

**Fix:** use a long-lived, command-owned transport with safe pool limits and
explicit timeouts, then close it during shutdown. If per-request transports
are retained by design, set `DisableKeepAlives` and call
`CloseIdleConnections` on every exit path.

### BUG-023 — No test or CI coverage protects most runtime paths

**Status:** confirmed  
**Evidence:** `.github/workflows/release.yml`, `internal/parentproxy_test.go`

The release workflow builds and publishes directly without `go test`, race
testing, static analysis, or cross-platform test coverage. The only in-tree
test file covers part of the recent parent SOCKS UDP wrapper. The defects in
this report—especially parsing, API-error recovery, proxy headers, Android
build-tag code, and concurrency—would not be caught before release.

**Fix:** add a non-release CI workflow that runs `go test ./...`,
`go test -race ./...` where supported, `go vet ./...`, and Go formatting
checks. Add a Windows matrix and Android compile-only job. Add focused unit and
integration tests before changing the networking code listed above.

## Protocol limits and observations (not code defects)

- HTTP/3/QUIC through a SOCKS5 parent requires the parent to implement `UDP
  ASSOCIATE`. A TCP-only SOCKS endpoint—including common Tor SOCKS listeners—
  cannot transport QUIC. The usable fallback is `--http2`, or a SOCKS5 server
  with UDP relay support.
- The current SOCKS UDP wrapper intentionally does **not** expose
  `ReadMsgUDP`, `WriteMsgUDP`, or `SyscallConn`, because quic-go would bypass
  SOCKS UDP framing through that fast path. It now exposes only the safe
  read/write buffer setters to avoid the quic-go receive-buffer warning.

## Suggested repair order

1. Protect configuration secrets and make persistence atomic (BUG-001).
2. Correct proxy authentication/header handling, server timeouts, and
   half-close behavior (BUG-002, BUG-003, BUG-013, BUG-015, BUG-021).
3. Make register/enrol error-safe and eliminate the pointer assertion bug
   (BUG-004, BUG-005).
4. Fix the SOCKS/parent transport concurrency, cancellation, and UDP sizing
   issues (BUG-007, BUG-008, BUG-009, BUG-012, BUG-018).
5. Repair tunnel recovery, Android DNS, and port mapping (BUG-006, BUG-010,
   BUG-011).
6. Add tests and CI gates before merging transport changes (BUG-023).
