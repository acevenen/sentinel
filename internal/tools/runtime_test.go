package tools

import (
	"errors"
	"runtime"
	"testing"
)

func TestDetectRuntimeIsInformational(t *testing.T) {
	status := DetectRuntime()
	if status.GOOS != runtime.GOOS || status.GOARCH != runtime.GOARCH {
		t.Fatalf("runtime status = %s/%s, want %s/%s", status.GOOS, status.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if len(status.Tools) != len(KaliRequirements) {
		t.Fatalf("tool statuses = %d, want %d", len(status.Tools), len(KaliRequirements))
	}
	if !status.Ready && status.Instruction == "" {
		t.Fatal("non-ready runtime omitted recovery instruction")
	}
}

func TestRequireKaliExplainsRecoveryOutsideKali(t *testing.T) {
	if inKali() {
		t.Skip("running inside Kali")
	}
	if err := RequireKaliForActive(); !errors.Is(err, ErrKaliRuntimeRequired) {
		t.Fatalf("RequireKaliForActive() error = %v", err)
	}
}
