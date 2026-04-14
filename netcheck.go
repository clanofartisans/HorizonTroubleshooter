//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	stunServer  = "stun1.l.google.com:19302"
	stunServer2 = "stun2.l.google.com:19302"
	stunMagic   = uint32(0x2112A442)
	netTimeout  = 5 * time.Second
	upnpTimeout = 3 * time.Second
	ssdpAddr    = "239.255.255.250:1900"
)

// NetSummary holds the structured results of runNetworkChecks for
// populating the UI summary panel.
type NetSummary struct {
	HTTPOk     bool   // external IP was reachable
	CGNAT      bool   // external IP is in RFC 6598 CGNAT range
	DoubleNAT  bool   // external IP is in a private RFC 1918 range
	NATType    string // "open" | "cone" | "cone-partial" | "symmetric" | "blocked"
	UDPBlocked bool   // STUN failed — outbound UDP appears blocked
	UPnPFound  bool   // UPnP gateway responded to SSDP discovery
}

// runNetworkChecks performs NAT-type and BitTorrent connectivity diagnostics,
// sending Markdown-formatted lines to logCh. IPs are masked before sending.
// Closes logCh when done. Returns a NetSummary for the UI summary panel.
func runNetworkChecks(logCh chan<- string) NetSummary {
	defer close(logCh)
	var ns NetSummary

	// Collect IPs first so the send wrapper can mask them throughout.
	extIP, httpErr := getExternalIP()
	localIPs := getLocalIPs()

	// All output goes through send(), which replaces discovered IPs with [masked].
	send := func(s string) {
		for _, ip := range localIPs {
			if ip != "" {
				s = strings.ReplaceAll(s, ip, "[masked]")
			}
		}
		if extIP != "" {
			s = strings.ReplaceAll(s, extIP, "[masked]")
		}
		logCh <- s
	}

	// ── NAT / Internet Connection ──────────────────────────────
	send("### NAT / Internet Connection")
	send("")

	if len(localIPs) > 0 {
		send("**Local IP(s):** `" + strings.Join(localIPs, ", ") + "`")
	}

	// Detect if this machine has a direct public IP (no NAT at all).
	isOpenInternet := false
	if httpErr == nil {
		for _, lip := range localIPs {
			if lip == extIP {
				isOpenInternet = true
				break
			}
		}
	}

	ns.HTTPOk = httpErr == nil
	if httpErr != nil {
		send("**External IP:** ❌ unreachable — " + httpErr.Error())
		send("> Cannot determine external IP — check internet connectivity.")
	} else {
		send("**External IP:** `" + extIP + "`")
		kind := addrKind(extIP)
		ns.CGNAT = kind == "cgnat"
		ns.DoubleNAT = kind == "double-nat"
		switch kind {
		case "cgnat":
			send("❌ **CGNAT detected** (100.64.0.0/10 shared address range)")
			send("> Your carrier is placing multiple customers behind one public IP.")
			send("> T-Mobile Home Internet is a common culprit.")
			send("> This is a known cause of connectivity failures with HorizonXI's networking stack.")
			send("> **Possible fixes:** request a public IP from your ISP, use a full-tunnel VPN, or switch to a wired/cable ISP.")
		case "double-nat":
			send("⚠️ **Double-NAT** — your external IP is in a private range.")
			send("> There is an extra NAT layer above your router. This can cause game connectivity issues.")
		default:
			if isOpenInternet {
				send("✅ Open Internet — direct public IP, no NAT.")
			} else {
				send("✅ Public IPv4 — behind router NAT, no CGNAT detected.")
			}
		}
	}
	send("")

	// ── STUN (UDP reachability + NAT mapping) ──────────────────
	// Single socket, two servers — required for a valid symmetric NAT test.
	addr1, addr2, pairErr := querySTUNPair()
	stunBlocked := addr1 == "" && addr2 == ""
	ns.UDPBlocked = stunBlocked

	if !stunBlocked {
		display := addr1
		if display == "" {
			display = addr2
		}
		host, _, _ := net.SplitHostPort(display)
		send("**STUN mapped (srv1):** `" + display + "`")
		if httpErr == nil && host != extIP {
			send("⚠️ STUN and HTTP report different external IPs — possible multiple exit paths or unusual NAT config.")
		} else if httpErr == nil {
			send("✅ External IP consistent between HTTP and UDP.")
		}
	}
	send("")

	// ── NAT Type ──────────────────────────────────────────────
	send("### NAT Type")
	send("")

	switch {
	case stunBlocked:
		send(fmt.Sprintf("❌ **STUN failed:** %v", pairErr))
		send("> Outbound UDP is blocked — cannot classify NAT type.")
		send("> HorizonXI uses UDP — the game will likely fail to connect.")
		send("**NAT Type:** `Unknown (UDP blocked)`")
		ns.NATType = "blocked"

	case isOpenInternet:
		send("**NAT Type:** `Open Internet (no NAT)`")
		send("✅ Direct public IP — best possible connectivity.")
		ns.NATType = "open"

	case addr1 == "" || addr2 == "":
		send("> Only one STUN server responded — symmetric test inconclusive.")
		send("**NAT Type:** `Cone NAT (symmetric test inconclusive)`")
		send("✅ Port mapping is consistent enough for the game.")
		ns.NATType = "cone-partial"

	default:
		_, port1, _ := net.SplitHostPort(addr1)
		_, port2, _ := net.SplitHostPort(addr2)
		send("**STUN mapped (srv2):** `" + addr2 + "`")
		if port1 == port2 {
			send(fmt.Sprintf("Both servers mapped to external port `%s` — consistent mapping.", port1))
			send("**NAT Type:** `Cone NAT (Full / Restricted / Port-Restricted)`")
			send("✅ Consistent port mapping — game UDP and BT connectivity should be fine.")
			send("> Note: Full / Restricted / Port-Restricted can only be distinguished with a CHANGE-REQUEST")
			send("> capable STUN server, which is not used here.")
			ns.NATType = "cone"
		} else {
			send(fmt.Sprintf("Srv1 port: `%s`  Srv2 port: `%s` — mapping differs per destination.", port1, port2))
			send("**NAT Type:** `Symmetric NAT`")
			send("❌ Different external port per destination — P2P hole-punching will fail.")
			send("> BitTorrent downloads work via outgoing connections only.")
			send("> Some game peer connections may be unreachable.")
			send("> A full-tunnel VPN with a cone-NAT exit may resolve this.")
			ns.NATType = "symmetric"
		}
	}
	send("")

	// ── BitTorrent client ──────────────────────────────────────
	send("### BitTorrent Client (Launcher Download)")
	send("")

	upnpFound := checkUPnP()
	ns.UPnPFound = upnpFound
	if upnpFound {
		send("✅ UPnP gateway found.")
		send("> The launcher's BT client can open ports automatically.")
		send("> Peer-to-peer downloads should work at full speed.")
	} else {
		send("⚠️ No UPnP gateway detected.")
		send("> The BT client cannot auto-open incoming ports.")
		if httpErr == nil && addrKind(extIP) == "cgnat" {
			send("> CGNAT is also present — manual port forwarding on your router will **not** help.")
			send("> Downloads work via outgoing connections only (slower).")
		} else {
			send("> Downloads work via outgoing connections but may be slower.")
			send("> Manually forwarding a TCP/UDP port on your router and configuring the launcher will improve speeds.")
		}
	}
	send("")

	if stunBlocked {
		send("❌ UDP blocked — BT UDP trackers will also fail (TCP fallback only).")
	} else {
		send("✅ UDP reachable — BT UDP tracker protocol should work.")
	}

	return ns
}

// getExternalIP fetches the machine's public IP via api.ipify.org (plain text).
func getExternalIP() (string, error) {
	client := &http.Client{Timeout: netTimeout}
	resp, err := client.Get("http://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected response: %q", ip)
	}
	return ip, nil
}

// addrKind classifies an IPv4 string as "cgnat", "double-nat", or "public".
func addrKind(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return "public" // IPv6 — treat as public
	}
	cidrs := map[string]string{
		"100.64.0.0/10":  "cgnat",      // RFC 6598 — carrier-grade NAT
		"10.0.0.0/8":     "double-nat", // RFC 1918
		"172.16.0.0/12":  "double-nat", // RFC 1918
		"192.168.0.0/16": "double-nat", // RFC 1918
	}
	for cidr, kind := range cidrs {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return kind
		}
	}
	return "public"
}

// getLocalIPs returns the machine's non-loopback IPv4 addresses.
func getLocalIPs() []string {
	var result []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
			}
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				result = append(result, ip.String())
			}
		}
	}
	return result
}

// buildSTUNReq constructs a 20-byte STUN Binding Request with a random
// transaction ID and returns both the packet and the ID for response matching.
func buildSTUNReq() (req []byte, txID [12]byte) {
	req = make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(req[2:4], 0x0000) // no attributes
	binary.BigEndian.PutUint32(req[4:8], stunMagic)
	io.ReadFull(rand.Reader, txID[:]) //nolint:errcheck — rand.Reader never fails
	copy(req[8:20], txID[:])
	return req, txID
}

// parseSTUNMappedAddr extracts the XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS
// fallback) from a raw STUN Binding Success Response.
func parseSTUNMappedAddr(resp []byte) (string, error) {
	n := len(resp)
	attrEnd := 20 + int(binary.BigEndian.Uint16(resp[2:4]))
	if attrEnd > n {
		attrEnd = n
	}
	for pos := 20; pos+4 <= attrEnd; {
		typ := binary.BigEndian.Uint16(resp[pos : pos+2])
		alen := int(binary.BigEndian.Uint16(resp[pos+2 : pos+4]))
		val := pos + 4
		if val+alen > n {
			break
		}
		switch typ {
		case 0x0020: // XOR-MAPPED-ADDRESS
			if alen >= 8 && resp[val+1] == 0x01 { // IPv4
				port := binary.BigEndian.Uint16(resp[val+2:val+4]) ^ 0x2112
				raw := binary.BigEndian.Uint32(resp[val+4:val+8]) ^ stunMagic
				ip := net.IP{byte(raw >> 24), byte(raw >> 16), byte(raw >> 8), byte(raw)}
				return fmt.Sprintf("%s:%d", ip, port), nil
			}
		case 0x0001: // MAPPED-ADDRESS (RFC 3489 fallback)
			if alen >= 8 && resp[val+1] == 0x01 {
				port := binary.BigEndian.Uint16(resp[val+2 : val+4])
				return fmt.Sprintf("%s:%d", net.IP(resp[val+4:val+8]), port), nil
			}
		}
		pad := alen
		if pad%4 != 0 {
			pad += 4 - pad%4
		}
		pos = val + pad
	}
	return "", fmt.Errorf("no mapped address in response")
}

// querySTUNPair sends STUN Binding Requests to two different servers from a
// single UDP socket and returns both mapped addresses. Using one socket is
// essential for a valid symmetric NAT test: cone NAT assigns the same external
// port to all destinations from a given source port; symmetric NAT does not.
// Comparing the two returned ports reliably distinguishes them.
func querySTUNPair() (addr1, addr2 string, err error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(netTimeout))

	dst1, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return "", "", fmt.Errorf("resolve srv1: %w", err)
	}
	dst2, err := net.ResolveUDPAddr("udp4", stunServer2)
	if err != nil {
		return "", "", fmt.Errorf("resolve srv2: %w", err)
	}

	req1, txID1 := buildSTUNReq()
	req2, txID2 := buildSTUNReq()

	if _, err := conn.WriteTo(req1, dst1); err != nil {
		return "", "", fmt.Errorf("write srv1: %w", err)
	}
	if _, err := conn.WriteTo(req2, dst2); err != nil {
		return "", "", fmt.Errorf("write srv2: %w", err)
	}

	// Collect up to 2 responses; match each to its request by transaction ID.
	// [12]byte arrays are directly comparable in Go — no bytes.Equal needed.
	buf := make([]byte, 512)
	for i := 0; i < 2; i++ {
		n, _, rerr := conn.ReadFrom(buf)
		if rerr != nil {
			break
		}
		if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0101 {
			continue
		}
		var rxID [12]byte
		copy(rxID[:], buf[8:20])
		mapped, merr := parseSTUNMappedAddr(buf[:n])
		if merr != nil {
			continue
		}
		switch rxID {
		case txID1:
			addr1 = mapped
		case txID2:
			addr2 = mapped
		}
	}

	if addr1 == "" && addr2 == "" {
		return "", "", fmt.Errorf("no responses received")
	}
	return addr1, addr2, nil
}

// checkUPnP sends an SSDP M-SEARCH for an Internet Gateway Device and reports
// whether any UPnP-capable gateway responded.
func checkUPnP() bool {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(upnpTimeout))

	dest, _ := net.ResolveUDPAddr("udp4", ssdpAddr)
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"\r\n"

	if _, err := conn.WriteTo([]byte(msg), dest); err != nil {
		return false
	}

	buf := make([]byte, 2048)
	n, _, err := conn.ReadFrom(buf)
	return err == nil && n > 0
}
