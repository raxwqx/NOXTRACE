// NOXTRACE Go engine: a bounded TCP connect scanner for authorized test scopes.
// It performs no stealth, evasion, exploit delivery, or UDP scan.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Target    string     `json:"target"`
	Ports     []int      `json:"ports_requested"`
	Open      []OpenPort `json:"open_ports"`
	Checked   int        `json:"checked"`
	ElapsedMS int64      `json:"elapsed_ms"`
	Notes     []string   `json:"notes"`
}
type OpenPort struct {
	Port    int    `json:"port"`
	Address string `json:"address"`
	State   string `json:"state"`
}

type job struct {
	host string
	port int
}
type outcome struct {
	address string
	port    int
	open    bool
}

func parsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port element")
		}
		if strings.Contains(part, "-") {
			pieces := strings.Split(part, "-")
			if len(pieces) != 2 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			a, errA := strconv.Atoi(pieces[0])
			b, errB := strconv.Atoi(pieces[1])
			if errA != nil || errB != nil || b < a {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if b-a+1 > 256 {
				return nil, fmt.Errorf("each port range is limited to 256 ports")
			}
			for p := a; p <= b; p++ {
				seen[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			seen[p] = true
		}
		if len(seen) > 256 {
			return nil, fmt.Errorf("at most 256 unique ports are allowed")
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("ports must be 1-65535")
		}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("specify at least one port")
	}
	return ports, nil
}

func scan(host string, ports []int, timeout time.Duration) Result {
	started := time.Now()
	resolveCtx, cancelResolve := context.WithTimeout(context.Background(), 3*time.Second)
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	cancelResolve()
	addresses := []string{}
	if err == nil {
		for _, ip := range ips {
			addresses = append(addresses, ip.IP.String())
		}
	}
	if len(addresses) == 0 {
		addresses = []string{host}
	}
	// Keep work bounded even if a hostname resolves to many addresses.
	if len(addresses) > 4 {
		addresses = addresses[:4]
	}
	jobs := make(chan job)
	results := make(chan outcome)
	var wg sync.WaitGroup
	workers := 32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				address := net.JoinHostPort(item.host, strconv.Itoa(item.port))
				conn, err := net.DialTimeout("tcp", address, timeout)
				opened := err == nil
				if conn != nil {
					_ = conn.Close()
				}
				results <- outcome{address: item.host, port: item.port, open: opened}
			}
		}()
	}
	go func() {
		for _, address := range addresses {
			for _, port := range ports {
				jobs <- job{host: address, port: port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	openPorts := []OpenPort{}
	checked := 0
	for result := range results {
		checked++
		if result.open {
			openPorts = append(openPorts, OpenPort{Port: result.port, Address: result.address, State: "open"})
		}
	}
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].Address == openPorts[j].Address {
			return openPorts[i].Port < openPorts[j].Port
		}
		return openPorts[i].Address < openPorts[j].Address
	})
	return Result{Target: host, Ports: ports, Open: openPorts, Checked: checked, ElapsedMS: time.Since(started).Milliseconds(), Notes: []string{"Authorized TCP connect checks only; no exploitation, stealth, evasion or UDP scan.", "An open port is not automatically a vulnerability."}}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "Usage: noxtrace-go scan --authorized [--timeout 500ms] HOST PORTS")
		os.Exit(2)
	}
	f := flag.NewFlagSet("scan", flag.ExitOnError)
	authorized := f.Bool("authorized", false, "confirm this target is owned or explicitly authorized")
	timeout := f.Duration("timeout", 500*time.Millisecond, "per-port TCP timeout (100ms-3s)")
	_ = f.Parse(os.Args[2:])
	if !*authorized {
		fmt.Fprintln(os.Stderr, "Refusing active scan: pass --authorized only for a target you own or have permission to test.")
		os.Exit(2)
	}
	if f.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: noxtrace-go scan --authorized HOST PORTS")
		os.Exit(2)
	}
	if *timeout < 100*time.Millisecond || *timeout > 3*time.Second {
		fmt.Fprintln(os.Stderr, "Timeout must be 100ms to 3s.")
		os.Exit(2)
	}
	ports, err := parsePorts(f.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result := scan(f.Arg(0), ports, *timeout)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
