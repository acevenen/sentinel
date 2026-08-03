package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the reverso command tree in-process and returns combined output.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func initProject(t *testing.T, dir string, permits string) {
	t.Helper()
	_, err := run(t,
		"scope", "init", "--dir", dir,
		"--project-id", "demo", "--owner", "ace@example.test",
		"--asset-id", "ecu-lab-01", "--asset-type", "firmware_image",
		"--ownership-evidence", "receipt on file",
		"--permit", permits, "--expires-in", "72h",
	)
	if err != nil {
		t.Fatalf("scope init: %v", err)
	}
}

func sampleFirmware(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "fw.bin")
	body := append([]byte{0x7f, 'E', 'L', 'F'}, []byte(
		"BusyBox v1.31.1\nOpenSSL 1.0.2u\ntelnetd -l /bin/login\n"+
			"-----BEGIN CERTIFICATE-----\nMIIBfoo\n-----END CERTIFICATE-----\n")...)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write firmware: %v", err)
	}
	return path
}

func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	initProject(t, dir, "artifact_ingestion,firmware_metadata_analysis,trust_mapping,report_generation")

	// scope verify passes.
	if out, err := run(t, "scope", "verify", "--dir", dir); err != nil {
		t.Fatalf("scope verify: %v\n%s", err, out)
	}

	fw := sampleFirmware(t, dir)

	if out, err := run(t, "ingest", "--dir", dir, fw); err != nil {
		t.Fatalf("ingest: %v\n%s", err, out)
	}

	out, err := run(t, "firmware", "inspect", "--dir", dir, fw)
	if err != nil {
		t.Fatalf("firmware inspect: %v\n%s", err, out)
	}
	if !strings.Contains(out, "busybox") || !strings.Contains(out, "telnet-service") {
		t.Fatalf("inspect output missing expected content:\n%s", out)
	}

	// report build in JSON is valid and names the project.
	out, err = run(t, "report", "build", "--dir", dir, "--format", "json")
	if err != nil {
		t.Fatalf("report build: %v\n%s", err, out)
	}
	var report map[string]any
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("report JSON invalid: %v\n%s", jerr, out)
	}
	if report["project_id"] != "demo" {
		t.Fatalf("report project_id = %v", report["project_id"])
	}

	// audit trail verifies.
	if out, err := run(t, "audit", "verify", "--dir", dir); err != nil {
		t.Fatalf("audit verify: %v\n%s", err, out)
	} else if !strings.Contains(out, "VERIFIED") {
		t.Fatalf("audit verify output: %s", out)
	}
}

// A capability the manifest does not permit is refused at the CLI, and the
// refusal is recorded in the audit trail.
func TestCLIRefusesUnpermittedCapability(t *testing.T) {
	dir := t.TempDir()
	initProject(t, dir, "artifact_ingestion,report_generation") // no binary_analysis
	fw := sampleFirmware(t, dir)

	out, err := run(t, "binary", "map", "--dir", dir, fw)
	if err == nil {
		t.Fatalf("binary map should be refused; output:\n%s", out)
	}
	if !strings.Contains(err.Error(), "not in the manifest's permitted set") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The refusal must appear in the verified audit trail.
	auditOut, aerr := run(t, "audit", "verify", "--dir", dir)
	if aerr != nil {
		t.Fatalf("audit verify: %v", aerr)
	}
	if !strings.Contains(auditOut, "denied: 1") {
		t.Fatalf("expected a denied audit record, got:\n%s", auditOut)
	}
}

// Firmware inspect against an expired manifest is refused (scope expiry).
func TestCLIRefusesExpiredScope(t *testing.T) {
	dir := t.TempDir()
	// Initialize, then rewrite the manifest with a past expiry and re-sign is
	// not possible without the key; instead init with a tiny lifetime is not
	// deterministic. So we init normally then hand-expire by editing config is
	// out of scope. Use a 1-second lifetime is racy. Instead, verify expiry via
	// the manifest path check: init with expires-in in the past is rejected by
	// flag? DurationVar allows negatives.
	_, err := run(t,
		"scope", "init", "--dir", dir,
		"--project-id", "demo", "--owner", "ace@example.test",
		"--asset-id", "ecu-lab-01", "--asset-type", "firmware_image",
		"--ownership-evidence", "receipt", "--permit", "firmware_metadata_analysis",
		"--expires-in", "-1h",
	)
	if err != nil {
		t.Fatalf("scope init: %v", err)
	}
	fw := sampleFirmware(t, dir)
	_, err = run(t, "firmware", "inspect", "--dir", dir, fw)
	if err == nil {
		t.Fatal("firmware inspect should be refused for an expired manifest")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry refusal, got: %v", err)
	}
}
