package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/collector"
	"github.com/CAOShurong/opaquedrop/internal/core"
	"github.com/CAOShurong/opaquedrop/internal/model"
	"github.com/CAOShurong/opaquedrop/internal/server"
	"github.com/CAOShurong/opaquedrop/internal/store"
)

var version = "dev"

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "init":
		return initCommand(args[1:])
	case "request":
		return requestCommand(args[1:])
	case "serve":
		return serveCommand(args[1:])
	case "collect":
		return collectCommand(args[1:])
	case "doctor":
		return doctorCommand(args[1:])
	case "purge":
		return purgeCommand(args[1:])
	case "version", "--version", "-version":
		fmt.Printf("opaquedrop %s\n", version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func initCommand(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	data := flags.String("data", "opaquedrop-data", "server data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	s := store.New(*data)
	if err := s.Init(); err != nil {
		return err
	}
	abs, _ := filepath.Abs(*data)
	fmt.Println("Initialized OpaqueDrop data directory:", abs)
	return nil
}

func requestCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("request requires make, import, or create")
	}
	switch args[0] {
	case "make":
		return requestMake(args[1:], false)
	case "create":
		return requestMake(args[1:], true)
	case "import":
		return requestImport(args[1:])
	default:
		return fmt.Errorf("unknown request command %q", args[0])
	}
}

func requestMake(args []string, importToStore bool) error {
	name := "request make"
	if importToStore {
		name = "request create"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	baseURL := flags.String("base-url", "", "public HTTPS base URL (localhost HTTP allowed)")
	label := flags.String("label", "", "request label shown to uploaders")
	expires := flags.Duration("expires", 24*time.Hour, "request lifetime")
	maxFiles := flags.Int("max-files", 10, "maximum submitted files")
	maxBytesText := flags.String("max-bytes", "2GiB", "maximum total plaintext bytes")
	deleteAfter := flags.Bool("delete-after-collect", false, "delete server ciphertext after a verified collection acknowledgement")
	bundleOut := flags.String("bundle-out", "", "public bundle output path")
	keyOut := flags.String("key-out", "", "private recipient key output path")
	data := flags.String("data", "opaquedrop-data", "server data directory (create only)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	maxBytes, err := core.ParseBytes(*maxBytesText)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	bundle, key, err := core.MakeRequest(*baseURL, *label, now, now.Add(*expires), *maxFiles, maxBytes, *deleteAfter)
	if err != nil {
		return err
	}
	if *bundleOut == "" {
		*bundleOut = "opaquedrop-" + bundle.ID + ".bundle.json"
	}
	if *keyOut == "" {
		*keyOut = "opaquedrop-" + bundle.ID + ".key.json"
	}
	keyBytes, err := core.MarshalPretty(key)
	if err != nil {
		return err
	}
	if err := writeNewFile(*keyOut, keyBytes, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	bundleBytes, err := core.MarshalPretty(bundle)
	if err != nil {
		return err
	}
	if err := writeNewFile(*bundleOut, bundleBytes, 0o600); err != nil {
		return fmt.Errorf("write public bundle: %w", err)
	}
	if importToStore {
		s := store.New(*data)
		if err := s.ImportRequest(bundle); err != nil {
			return fmt.Errorf("import request: %w", err)
		}
	}
	fmt.Println("Request ID:   ", bundle.ID)
	fmt.Println("Upload link:  ", key.SubmitURL)
	fmt.Println("Public bundle:", absolute(*bundleOut))
	fmt.Println("Private key:  ", absolute(*keyOut))
	if importToStore {
		fmt.Println("Server data:  ", absolute(*data))
	}
	fmt.Println("Keep the private key off the server if the host administrator must remain unable to decrypt submissions.")
	return nil
}

func requestImport(args []string) error {
	flags := flag.NewFlagSet("request import", flag.ContinueOnError)
	data := flags.String("data", "opaquedrop-data", "server data directory")
	bundlePath := flags.String("bundle", "", "public request bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return errors.New("--bundle is required")
	}
	var bundle model.RequestBundle
	if err := readJSON(*bundlePath, &bundle); err != nil {
		return err
	}
	if err := store.New(*data).ImportRequest(bundle); err != nil {
		return err
	}
	fmt.Printf("Imported request %s into %s\n", bundle.ID, absolute(*data))
	return nil
}

func serveCommand(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := flags.String("data", "opaquedrop-data", "server data directory")
	listen := flags.String("listen", "127.0.0.1:8080", "listen address")
	var trustedProxyValues repeatedStringFlag
	flags.Var(&trustedProxyValues, "trusted-proxy", "trusted reverse-proxy IP or CIDR for X-Forwarded-For (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	trustedProxies, err := server.ParseTrustedProxies(trustedProxyValues)
	if err != nil {
		return err
	}
	s := store.New(*data)
	if err := s.Init(); err != nil {
		return err
	}
	if _, err := s.Doctor(); err != nil {
		return err
	}
	err = server.New(s, log.New(os.Stdout, "", log.LstdFlags|log.LUTC), server.WithTrustedProxies(trustedProxies)).Listen(*listen)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func collectCommand(args []string) error {
	flags := flag.NewFlagSet("collect", flag.ContinueOnError)
	keyPath := flags.String("key", "", "private recipient key file")
	out := flags.String("out", "received", "output directory")
	noAck := flags.Bool("no-ack", false, "do not acknowledge successful collection")
	failFast := flags.Bool("fail-fast", false, "stop after the first failed submission")
	listOnly := flags.Bool("list", false, "list completed submissions without downloading file content")
	includeAcknowledged := flags.Bool("all", false, "with --list, include acknowledged submissions")
	readRetries := flags.Int("read-retries", collector.DefaultReadRetries, "retries after a temporary list, manifest, or chunk read failure (0-10)")
	var uploadIDs repeatedStringFlag
	flags.Var(&uploadIDs, "upload", "collect only this completed upload ID (repeatable; acknowledged uploads may be re-collected)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *readRetries < 0 || *readRetries > collector.MaxReadRetries {
		return fmt.Errorf("--read-retries must be between 0 and %d", collector.MaxReadRetries)
	}
	if *includeAcknowledged && !*listOnly {
		return errors.New("--all requires --list")
	}
	for _, uploadID := range uploadIDs {
		if !core.ValidID(uploadID) {
			return fmt.Errorf("invalid upload ID %q", uploadID)
		}
	}
	if *keyPath == "" {
		return errors.New("--key is required")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	client := collector.New(key)
	client.ReadRetries = *readRetries
	client.RetryLog = os.Stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *listOnly {
		inspections, inspectErr := client.Inspect(ctx, collector.InspectOptions{
			UploadIDs: uploadIDs, IncludeAcknowledged: *includeAcknowledged, FailFast: *failFast,
		})
		var outputErr error
		if len(inspections) == 0 && inspectErr == nil {
			if *includeAcknowledged {
				_, outputErr = fmt.Fprintln(os.Stdout, "No completed submissions.")
			} else {
				_, outputErr = fmt.Fprintln(os.Stdout, "No unacknowledged submissions.")
			}
		}
		if outputErr == nil {
			outputErr = writeInspections(os.Stdout, inspections)
		}
		return errors.Join(inspectErr, outputErr)
	}
	results, collectErr := client.Collect(ctx, *out, collector.CollectOptions{
		Acknowledge: !*noAck,
		UploadIDs:   uploadIDs,
		FailFast:    *failFast,
	})
	if len(results) == 0 && collectErr == nil {
		fmt.Println("No unacknowledged submissions.")
	}
	for _, result := range results {
		fmt.Printf("Collected %s\n  path: %s\n  bytes: %d\n  plaintext sha256: %s\n  receipt sha256:   %s\n", result.UploadID, result.Path, result.PlainBytes, result.PlainSHA256, result.ReceiptSHA256)
	}
	return collectErr
}

func writeInspections(writer io.Writer, inspections []collector.Inspection) error {
	for _, inspection := range inspections {
		state := "pending"
		if inspection.Acknowledged {
			state = "acknowledged"
		}
		name := inspection.Name
		if inspection.MetadataVerified {
			name = strconv.Quote(name)
		}
		if _, err := fmt.Fprintf(writer, "Upload %s\n  state: %s\n  completed: %s\n  bytes: %d\n  name: %s\n",
			inspection.UploadID, state, inspection.CompletedAt.UTC().Format(time.RFC3339), inspection.PlainBytes, name); err != nil {
			return err
		}
	}
	return nil
}

func doctorCommand(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	data := flags.String("data", "opaquedrop-data", "server data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	checks, err := store.New(*data).Doctor()
	for _, check := range checks {
		fmt.Println("ok  ", check)
	}
	if err != nil {
		return err
	}
	fmt.Println("ok   OpaqueDrop data directory is ready")
	return nil
}

func purgeCommand(args []string) error {
	flags := flag.NewFlagSet("purge", flag.ContinueOnError)
	data := flags.String("data", "opaquedrop-data", "server data directory")
	apply := flags.Bool("apply", false, "actually delete matched ciphertext; otherwise dry run")
	stale := flags.Duration("stale-incomplete", 24*time.Hour, "age for incomplete uploads")
	if err := flags.Parse(args); err != nil {
		return err
	}
	result, err := store.New(*data).Purge(*apply, *stale)
	if err != nil {
		return err
	}
	action := "Would remove"
	if *apply {
		action = "Removed"
	}
	fmt.Printf("%s %d upload directories (%d bytes).\n", action, len(result.UploadDirs), result.Bytes)
	for _, path := range result.UploadDirs {
		fmt.Println(" ", path)
	}
	if !*apply && len(result.UploadDirs) > 0 {
		fmt.Println("Dry run only. Re-run with --apply to delete these ciphertext directories.")
	}
	return nil
}

func loadKey(path string) (model.KeyFile, error) {
	var key model.KeyFile
	if err := readJSON(path, &key); err != nil {
		return key, err
	}
	if key.SchemaVersion != model.SchemaVersion || !core.ValidID(key.RequestID) || key.CollectToken == "" || key.ServerURL == "" {
		return key, errors.New("private key file is invalid")
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(key.PrivateKey)
	if err != nil {
		return key, errors.New("private key encoding is invalid")
	}
	privateKey, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return key, errors.New("private key is invalid")
	}
	derivedPublic := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if derivedPublic != key.PublicKey {
		return key, errors.New("private and public keys do not match")
	}
	return key, nil
}

func readJSON(path string, target any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("JSON file exceeds 1 MiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func writeNewFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func absolute(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func usage() {
	fmt.Print(`OpaqueDrop — server-blind inbound file requests

Usage:
  opaquedrop init --data DIR
  opaquedrop request make --base-url URL --label TEXT [options]
  opaquedrop request import --data DIR --bundle FILE
  opaquedrop request create --data DIR --base-url URL --label TEXT [options]
  opaquedrop serve --data DIR [--listen 127.0.0.1:8080] [--trusted-proxy IP_OR_CIDR]
  opaquedrop collect --key FILE --out DIR [--upload ID] [--fail-fast] [--read-retries N]
  opaquedrop collect --key FILE --list [--all] [--upload ID] [--fail-fast] [--read-retries N]
  opaquedrop doctor --data DIR
  opaquedrop purge --data DIR [--apply]
  opaquedrop version
`)
}
