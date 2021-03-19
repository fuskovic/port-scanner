package main

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"go.coder.com/cli"
	"golang.org/x/xerrors"
)

const (
	wellKnownPorts = 1024
	allPorts       = 65535
)

var timeout = 3 * time.Second

// This time our command struct has a few fields, we can use these to store flag values.
type scanCmd struct {
	host          string
	shouldScanAll bool
}

// cdr/cli supports subcommand aliases so lets define one in our
// command spec to allow users the opportunity to provide more succinct input.
func (cmd *scanCmd) Spec() cli.CommandSpec {
	return cli.CommandSpec{
		Name:    "scan",
		Usage:   "[flags]",
		Aliases: []string{"s"},
		Desc:    "Scan a host for open ports.",
	}
}

// When adding flags, use the following method-signature to implement FlaggedCommand as defined by cdr/cli.
// See https://pkg.go.dev/go.coder.com/cli#FlaggedCommand for more details.
func (cmd *scanCmd) RegisterFlags(fl *pflag.FlagSet) {
	fl.StringVar(&cmd.host, "host", "", "host to scan(ip address)")
	fl.BoolVarP(&cmd.shouldScanAll, "all", "a", false, "scan all ports(scans first 1024 if not enabled)")
}

func (cmd *scanCmd) Run(fl *pflag.FlagSet) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cmd.host == "" {
		fl.Usage()
		log.Fatal("host not provided")
	}

	scanner, err := newScanner(cmd.host, cmd.shouldScanAll)
	if err != nil {
		fl.Usage()
		log.Fatalf("failed to initialize port scanner: %s", err)
	}

	log.Printf("scanning %s...", cmd.host)
	start := time.Now()
	openPorts := scanner.scan(ctx)
	log.Printf("scan completed in %s", time.Since(start))

	if len(openPorts) == 0 {
		log.Printf("%q has no exposed ports", cmd.host)
		return
	}
	log.Printf("found %d open ports", len(openPorts))
	log.Printf("open-ports: %v", openPorts)
}

// Now lets implement our port scanner.
type scanner struct {
	// we're going to wan't to scan each port concurrently
	// so let's embed a mutex lock to help us make sure we
	// do this in a thread-safe way.
	sync.Mutex
	host      string
	openPorts []int
	scanAll   bool
}

func newScanner(host string, scanAll bool) (*scanner, error) {
	if net.ParseIP(host) == nil {
		return nil, xerrors.Errorf("%q is an invalid ip address", host)
	}

	return &scanner{
		Mutex:   sync.Mutex{},
		host:    host,
		scanAll: scanAll,
	}, nil
}

func (s *scanner) add(port int) {
	// Since we'll be appending to the same slice from different goroutines,
	// lets make sure we're locking and unlocking between writes.
	s.Lock()
	s.openPorts = append(s.openPorts, port)
	s.Unlock()
}

func (s *scanner) scan(ctx context.Context) []int {
	// Lets use a wait group so we can wait for all of our
	// goroutines to exit before returning our result.
	var wg sync.WaitGroup
	for _, port := range portsToScan(s.scanAll) {
		wg.Add(1)
		// Because 'port' is a loop-variable in this context,
		// we'll wan't to explicitly pass a copy of its value into
		// each goroutine on every iteration.
		go func(p int) {
			defer wg.Done()
			// We don't need to explicitly pass the 'host' variable
			// into the goroutine as a param because its not a
			// loop-variable and its value never changes.
			if isOpen(s.host, p) {
				s.add(p)
			}
		}(port)
	}
	wg.Wait()
	return s.openPorts
}

func portsToScan(shouldScanAll bool) []int {
	max := wellKnownPorts
	if shouldScanAll {
		max = allPorts
	}

	var ports []int
	for port := 1; port < max; port++ {
		ports = append(ports, port)
	}
	return ports
}

func isOpen(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
