package amneziawg

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SocketDir = "/run/netos/amneziawg"

func validInterface(name string) bool {
	if len(name) > 15 {
		return false
	}
	suffix := strings.TrimPrefix(name, "awg-ch")
	if suffix == name {
		suffix = strings.TrimPrefix(name, "awg-srv")
	}
	if suffix == name || suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func exchange(ctx context.Context, path, request string) (State, error) {
	out := State{Device: map[string]string{}}
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return out, fmt.Errorf("сокет AmneziaWG недоступен: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return out, err
	}
	if _, err := io.WriteString(c, request); err != nil {
		return out, err
	}
	scan := bufio.NewScanner(io.LimitReader(c, 64<<20))
	scan.Buffer(make([]byte, 4096), 132000)
	var peer *Peer
	complete := false
	for scan.Scan() {
		line := scan.Text()
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return out, fmt.Errorf("некорректный ответ AmneziaWG")
		}
		if key == "errno" {
			if value != "0" {
				return out, fmt.Errorf("AmneziaWG отклонил конфигурацию (код %s)", value)
			}
			complete = true
			continue
		}
		if key == "public_key" {
			out.Peers = append(out.Peers, Peer{Key: value, Values: map[string]string{}})
			peer = &out.Peers[len(out.Peers)-1]
			continue
		}
		if peer == nil {
			out.Device[key] = value
		} else if key == "allowed_ip" {
			peer.AllowedIPs = append(peer.AllowedIPs, value)
		} else {
			peer.Values[key] = value
		}
	}
	if err := scan.Err(); err != nil {
		return out, err
	}
	if !complete {
		return out, fmt.Errorf("неполный ответ AmneziaWG")
	}
	return out, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func equalValue(key, a, b string) bool {
	zero := "0"
	switch key {
	case "private_key", "preshared_key", "header_protection_key":
		zero = strings.Repeat("0", 64)
	case "endpoint", "i1", "i2", "i3", "i4", "i5":
		zero = ""
	}
	if a == "" {
		a = zero
	}
	if b == "" {
		b = zero
	}
	return a == b
}

// Delta preserves existing peers and handshakes. Cost is O(N+A) apart from
// sorting the fixed-size device/peer field names; peer order is input order.
func Delta(want, live State) string {
	var b strings.Builder
	for _, key := range sortedKeys(want.Device) {
		if !equalValue(key, want.Device[key], live.Device[key]) {
			fmt.Fprintf(&b, "%s=%s\n", key, want.Device[key])
		}
	}
	existing := make(map[string]Peer, len(live.Peers))
	for _, p := range live.Peers {
		existing[p.Key] = p
	}
	wanted := make(map[string]bool, len(want.Peers))
	for _, p := range want.Peers {
		wanted[p.Key] = true
		old, exists := existing[p.Key]
		var fields strings.Builder
		for _, key := range sortedKeys(p.Values) {
			if !exists || !equalValue(key, p.Values[key], old.Values[key]) {
				fmt.Fprintf(&fields, "%s=%s\n", key, p.Values[key])
			}
		}
		prefixesEqual := len(p.AllowedIPs) == len(old.AllowedIPs)
		if prefixesEqual {
			set := make(map[string]bool, len(old.AllowedIPs))
			for _, v := range old.AllowedIPs {
				set[v] = true
			}
			for _, v := range p.AllowedIPs {
				if !set[v] {
					prefixesEqual = false
					break
				}
			}
		}
		if !exists || !prefixesEqual {
			fields.WriteString("replace_allowed_ips=true\n")
			for _, v := range p.AllowedIPs {
				fmt.Fprintf(&fields, "allowed_ip=%s\n", v)
			}
		}
		if fields.Len() != 0 {
			fmt.Fprintf(&b, "public_key=%s\n", p.Key)
			b.WriteString(fields.String())
		}
	}
	for _, p := range live.Peers {
		if !wanted[p.Key] {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", p.Key)
		}
	}
	return b.String()
}

// Execute is an internal multicall command. Telemetry deliberately excludes
// private/preshared/header-protection keys, including in diagnostic output.
func Execute(ctx context.Context, args []string, w io.Writer) error {
	if len(args) < 2 || !validInterface(args[1]) {
		return fmt.Errorf("ожидается команда AmneziaWG и интерфейс awg-chN/awg-srvN")
	}
	name := args[1]
	if args[0] == "serve" && len(args) == 2 {
		return serve(ctx, name)
	}
	path := filepath.Join(SocketDir, name+".sock")
	switch args[0] {
	case "syncconf":
		if len(args) != 3 {
			return fmt.Errorf("ожидается файл конфигурации")
		}
		info, err := os.Stat(args[2])
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return fmt.Errorf("ожидается обычный файл конфигурации до 8 МиБ")
		}
		f, err := os.Open(args[2])
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
		if err != nil {
			return err
		}
		want, err := ParseNative(ctx, string(data))
		if err != nil {
			return err
		}
		live, err := exchange(ctx, path, "get=1\n\n")
		if err != nil {
			return err
		}
		// Client configurations omit ListenPort. Preserve the allocated port.
		if _, ok := want.Device["listen_port"]; !ok {
			want.Device["listen_port"] = live.Device["listen_port"]
		}
		delta := Delta(want, live)
		if delta == "" {
			return nil
		}
		_, err = exchange(ctx, path, "set=1\n"+delta+"\n")
		return err
	case "show":
		if len(args) > 3 {
			return fmt.Errorf("лишние аргументы AmneziaWG show")
		}
		live, err := exchange(ctx, path, "get=1\n\n")
		if err != nil {
			return err
		}
		field := "status"
		if len(args) == 3 {
			field = args[2]
		}
		return telemetry(w, live, field)
	default:
		return fmt.Errorf("неизвестная команда AmneziaWG")
	}
}

func telemetry(w io.Writer, state State, field string) error {
	if field == "status" {
		_, err := fmt.Fprintln(w, "AmneziaWG")
		return err
	}
	if field == "listen-port" {
		v := state.Device["listen_port"]
		if v == "" {
			v = "0"
		}
		_, err := fmt.Fprintln(w, v)
		return err
	}
	if field != "latest-handshakes" && field != "endpoints" && field != "transfer" && field != "telemetry" {
		return fmt.Errorf("неподдерживаемое поле состояния AmneziaWG")
	}
	for _, p := range state.Peers {
		key, err := hex.DecodeString(p.Key)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("некорректный публичный ключ в состоянии AmneziaWG")
		}
		values := p.Values
		number := func(k string) string {
			v := values[k]
			if _, err := strconv.ParseUint(v, 10, 64); err != nil {
				return "0"
			}
			return v
		}
		ep := values["endpoint"]
		if ep == "" {
			ep = "(none)"
		}
		data := ""
		switch field {
		case "latest-handshakes":
			data = number("last_handshake_time_sec")
		case "endpoints":
			data = ep
		case "transfer":
			data = number("rx_bytes") + "\t" + number("tx_bytes")
		case "telemetry":
			data = number("last_handshake_time_sec") + "\t" + ep + "\t" + number("rx_bytes") + "\t" + number("tx_bytes")
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", base64.StdEncoding.EncodeToString(key), data); err != nil {
			return err
		}
	}
	return nil
}
