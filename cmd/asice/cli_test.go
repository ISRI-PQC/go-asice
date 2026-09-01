// Unit tests for the cmd/asice cobra layer (the e2e binary tests live
// in acceptance/cli_test.go).
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/isri-pqc/asice/testutil"
)

var cliT = time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)

func newSink() *bytes.Buffer { return &bytes.Buffer{} }

// TestExecuteDispatch pins the top-level dispatch and exit codes.
func TestExecuteDispatch(t *testing.T) {
	if code := execute(newSink(), newSink(), nil); code != exitUsageErr {
		t.Errorf("no args: exit %d, want %d", code, exitUsageErr)
	}
	code, _, serr := runExecuteChecked(t, []string{"frobnicate"})
	if code != exitUsageErr {
		t.Errorf("unknown command: exit %d, want %d (stderr: %s)", code, exitUsageErr, serr)
	}
}

// runExecuteChecked runs the CLI entry point and returns (exit code,
// stdout, stderr).
func runExecuteChecked(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	o, e := newSink(), newSink()
	code := execute(o, e, args)
	return code, o.String(), e.String()
}

func TestExecuteHelpAndVersion(t *testing.T) {
	// --help: exit 0, lists both subcommands.
	code, out, _ := runExecuteChecked(t, []string{"--help"})
	if code != exitOK {
		t.Fatalf("--help: exit %d, want 0", code)
	}
	for _, want := range []string{"create", "verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help output lacks %q:\n%s", want, out)
		}
	}
	// help subcommand: exit 0.
	if code, _, _ := runExecuteChecked(t, []string{"help"}); code != exitOK {
		t.Errorf("help: exit %d, want 0", code)
	}
	// --version: exit 0, reports the version.
	code, out, _ = runExecuteChecked(t, []string{"--version"})
	if code != exitOK {
		t.Fatalf("--version: exit %d, want 0", code)
	}
	if !strings.Contains(out, appVersion) {
		t.Errorf("--version output %q lacks %q", out, appVersion)
	}
}

// TestExecuteUsageErrors pins the exit 2 contract: unknown command,
// unknown flag, and a flag missing its argument.
func TestExecuteUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown command", []string{"frobnicate"}, "unknown command"},
		{"unknown flag", []string{"create", "--frobnicate", "doc.txt"}, "unknown flag"},
		{"flag missing argument", []string{"create", "--cert"}, "flag needs an argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, serr := runExecuteChecked(t, tc.args)
			if code != exitUsageErr {
				t.Fatalf("exit %d, want %d (stderr: %s)", code, exitUsageErr, serr)
			}
			if !strings.Contains(serr, tc.want) {
				t.Errorf("stderr %q lacks %q", serr, tc.want)
			}
		})
	}
}

// writePEM writes the given PEM blocks to a file and returns the path.
func writePEM(t *testing.T, dir, name string, blocks ...[]byte) string {
	t.Helper()
	var b []byte
	for _, blk := range blocks {
		b = append(b, blk...)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// signerFilePEM renders the --cert file for the signer cert: the
// certificate PEM block plus the private key as a PKCS#8 PEM block.
func signerFilePEM(t *testing.T, c *testutil.Cert) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return append(append([]byte{}, c.PEM...), key...)
}

// newCLIContainer builds a one-file BES container through execute
// (the CLI entry point) and writes the trust files; returns the
// container, roots, and intermediates paths.
func newCLIContainer(t *testing.T) (container, roots, intermediates string) {
	t.Helper()
	p, err := testutil.NewPKI(testutil.Options{Now: cliT})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	docPath := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(docPath, []byte("cli unit data"), 0o644); err != nil {
		t.Fatal(err)
	}
	signerPath := writePEM(t, dir, "signer.pem", signerFilePEM(t, p.Signer))

	containerPath := filepath.Join(dir, "out.asice")
	if code, _, serr := runExecuteChecked(t, []string{
		"create",
		"-o", containerPath,
		"--cert", signerPath,
		"--signing-time", cliT.Format(time.RFC3339),
		docPath,
	}); code != exitOK {
		t.Fatalf("create exited %d, want 0 (stderr: %s)", code, serr)
	}
	if _, err := os.Stat(containerPath); err != nil {
		t.Fatalf("container not written: %v", err)
	}

	rootsPath := writePEM(t, dir, "root.pem", p.Root.PEM)
	intermediatesPath := writePEM(t, dir, "issuer.pem", p.Issuer.PEM)
	return containerPath, rootsPath, intermediatesPath
}

// TestExecuteCreateVerify pins the create→verify exit codes and the
// positional/flag mixing (the container path first or last).
func TestExecuteCreateVerify(t *testing.T) {
	container, roots, intermediates := newCLIContainer(t)

	// Container path FIRST (the old documented order).
	stdout, stderr := newSink(), newSink()
	if code := execute(stdout, stderr, []string{
		"verify", container, "--roots", roots, "--intermediates", intermediates,
	}); code != exitOK {
		t.Fatalf("verify (path first) exited %d, want 0 (report: %s)", code, stdout.String())
	}
	if s := stdout.String(); !strings.Contains(s, "S0") || !strings.Contains(s, "OK") {
		t.Errorf("verify report %q lacks S0/OK", s)
	}

	// Container path LAST (flags first) must also work.
	stdout, stderr = newSink(), newSink()
	if code := execute(stdout, stderr, []string{
		"verify", "--roots", roots, "--intermediates", intermediates, container,
	}); code != exitOK {
		t.Fatalf("verify (path last) exited %d, want 0 (report: %s)", code, stdout.String())
	}

	// Missing --roots: usage error.
	if code := execute(newSink(), newSink(), []string{"verify", container}); code != exitUsageErr {
		t.Errorf("verify without --roots: exit %d, want %d", code, exitUsageErr)
	}

	// No container path: usage error.
	if code := execute(newSink(), newSink(), []string{"verify", "--roots", roots}); code != exitUsageErr {
		t.Errorf("verify without a container path: exit %d, want %d", code, exitUsageErr)
	}

	// Unknown profile: usage error.
	if code := execute(newSink(), newSink(), []string{"verify", container, "--roots", roots, "--profile", "lt"}); code != exitUsageErr {
		t.Errorf("verify with unknown profile: exit %d, want %d", code, exitUsageErr)
	}
}

// TestRunCreateValidation pins the create input contract errors.
func TestRunCreateValidation(t *testing.T) {
	cases := []struct {
		name string
		in   createInput
		want string
	}{
		{"no output", createInput{certFile: "c", docs: []string{"d"}}, "-o"},
		{"no cert", createInput{out: "o", docs: []string{"d"}}, "--cert"},
		{"no docs", createInput{out: "o", certFile: "c"}, "document"},
		{"bad profile", createInput{out: "o", certFile: "c", docs: []string{"d"}, profile: "lt"}, "profile"},
		{"ts missing ocsp", createInput{out: "o", certFile: "c", docs: []string{"d"}, profile: "ts"}, "ocsp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runCreateCmd(context.Background(), newSink(), tc.in)
			if err == nil {
				t.Fatalf("runCreateCmd succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
