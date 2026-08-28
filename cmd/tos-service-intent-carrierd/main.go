// Command tos-service-intent-carrierd runs the Gateway Intent Carrier as an
// independently deployable process.  It does not require the service catalog
// or a TOS RPC endpoint, so deleting or stopping this store cannot affect a
// separately operated Carrier.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-service-gateway/internal/intentcarrier"
)

type pinsFlag map[string]ed25519.PublicKey

func (p *pinsFlag) String() string { return fmt.Sprintf("%d configured", len(*p)) }
func (p *pinsFlag) Set(value string) error {
	parts := strings.SplitN(value, "=ed25519:", 2)
	if len(parts) != 2 || parts[0] == "" {
		return errors.New("authority pin must be AUTHORITY_ID=ed25519:HEX")
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("authority pin contains an invalid Ed25519 key")
	}
	if *p == nil {
		*p = pinsFlag{}
	}
	if _, exists := (*p)[parts[0]]; exists {
		return errors.New("authority pin is duplicated")
	}
	(*p)[parts[0]] = ed25519.PublicKey(raw)
	return nil
}

type tokenAuthorizer struct{ readHash, writeHash [32]byte }

func (a tokenAuthorizer) Authorize(header string, write bool) error {
	if !strings.HasPrefix(header, "Bearer ") || len(header) > 8192 {
		return os.ErrPermission
	}
	got := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
	want := a.readHash
	if write {
		want = a.writeHash
	}
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return os.ErrPermission
	}
	return nil
}

func main() {
	state := flag.String("state", "", "absolute private Carrier state directory")
	carrierID := flag.String("carrier-id", "", "source-local stable Carrier identifier")
	listen := flag.String("listen", "127.0.0.1:8091", "HTTP listen address")
	readToken := flag.String("read-token-file", "", "absolute mode-0600 bearer token file")
	writeToken := flag.String("write-token-file", "", "absolute mode-0600 relay token file")
	tlsCert := flag.String("tls-cert", "", "TLS certificate PEM (required outside loopback)")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM (required outside loopback)")
	maxEntries := flag.Uint64("max-entries", 100000, "maximum retained operations")
	maxActorEntries := flag.Uint64("max-actor-entries", 1000, "maximum retained publications per issuer")
	check := flag.Bool("check", false, "validate configuration and state without listening")
	pins := pinsFlag{}
	flag.Var(&pins, "authority", "pinned writer-fence authority AUTHORITY_ID=ed25519:HEX (repeat)")
	flag.Parse()
	if *maxEntries > 1_000_000 || *maxActorEntries > 1_000_000 {
		fatal(errors.New("retention limit is too large"))
	}
	if err := run(*state, *carrierID, *listen, *readToken, *writeToken, *tlsCert, *tlsKey,
		uint32(*maxEntries), uint32(*maxActorEntries), pins, *check); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "tos-service-intent-carrierd:", err)
	os.Exit(1)
}

func run(state, carrierID, listen, readTokenPath, writeTokenPath, certPath, keyPath string,
	maxEntries, maxActorEntries uint32, pins pinsFlag, check bool) error {
	if !filepath.IsAbs(state) || carrierID == "" || len(pins) == 0 || maxEntries == 0 || maxActorEntries == 0 {
		return errors.New("incomplete Carrier configuration")
	}
	readToken, err := loadToken(readTokenPath)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	defer zero(readToken)
	writeToken, err := loadToken(writeTokenPath)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	defer zero(writeToken)
	if string(readToken) == string(writeToken) {
		return errors.New("read and write bearer tokens must be distinct")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("listen address is invalid")
	}
	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	if !loopback && (certPath == "" || keyPath == "") {
		return errors.New("TLS is mandatory outside loopback")
	}
	store, err := intentcarrier.Open(state, carrierID, maxEntries, maxActorEntries,
		intentcarrier.PinnedAuthorities(map[string]ed25519.PublicKey(pins)))
	if err != nil {
		return err
	}
	defer store.Close()
	if check {
		fmt.Printf("configuration_valid=true carrier_id=%s independent_store=gateway-journal outcome_receipt_public_key=%s\n", carrierID, store.ReceiptPublicKey())
		return nil
	}
	authorizer := tokenAuthorizer{readHash: sha256.Sum256(readToken), writeHash: sha256.Sum256(writeToken)}
	server := &http.Server{Addr: listen, Handler: intentcarrier.Handler(store, authorizer), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if certPath != "" {
			done <- server.ServeTLS(listener, certPath, keyPath)
		} else {
			done <- server.Serve(listener)
		}
	}()
	fmt.Printf("ready=true carrier_id=%s listen=%s profile=gateway-intent independent_store=true outcome_receipt_public_key=%s\n",
		carrierID, listen, store.ReceiptPublicKey())
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		err = <-done
	case err = <-done:
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func loadToken(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("token path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 32 || info.Size() > 8192 {
		return nil, errors.New("token must be a bounded mode-0600 regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) < 32 {
		return nil, errors.New("bearer token must contain at least 32 bytes")
	}
	return raw, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
