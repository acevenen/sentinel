package tools

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOSExecutorRefusesShell(t *testing.T) {
	_, err := (OSExecutor{}).Execute(context.Background(), Command{Path: "sh", Args: []string{"-c", "echo unsafe"}})
	if !errors.Is(err, ErrShellForbidden) {
		t.Fatalf("Execute() error = %v, want ErrShellForbidden", err)
	}
}

func TestOSExecutorCapsOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX printf utility")
	}
	result, err := (OSExecutor{}).Execute(context.Background(), Command{
		Path:        "printf",
		Args:        []string{"0123456789"},
		OutputLimit: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Stdout) != "0123" || !result.Truncated {
		t.Fatalf("result = stdout %q, truncated %v", result.Stdout, result.Truncated)
	}
}

func TestOSExecutorHonorsTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the POSIX sleep utility")
	}
	_, err := (OSExecutor{}).Execute(context.Background(), Command{
		Path:    "sleep",
		Args:    []string{"5"},
		Timeout: 10 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("Execute() error = %v, want deadline exceeded", err)
	}
}

func TestRedactArgs(t *testing.T) {
	got := RedactArgs([]string{"--token=secret-value", "plain"}, []string{"secret-value"})
	if got[0] != "--token=[REDACTED]" || got[1] != "plain" {
		t.Fatalf("RedactArgs() = %#v", got)
	}
}
