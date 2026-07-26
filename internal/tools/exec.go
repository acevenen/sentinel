package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultExecTimeout = 2 * time.Minute
	defaultOutputLimit = int64(8 << 20)
)

// ErrShellForbidden means a caller attempted to route argv through a shell.
var ErrShellForbidden = errors.New("shell execution is forbidden; provide an executable and argv directly")

// Command is an argv-safe external process description.
type Command struct {
	Path        string
	Args        []string
	Env         []string
	Dir         string
	Timeout     time.Duration
	OutputLimit int64
}

// Execution is the bounded output and status from one external process.
type Execution struct {
	Command   []string
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// Executor makes adapters testable without launching live binaries.
type Executor interface {
	Execute(context.Context, Command) (Execution, error)
}

// OSExecutor launches direct argv processes without a shell.
type OSExecutor struct{}

// Execute runs a bounded, context-cancelable subprocess.
func (OSExecutor) Execute(ctx context.Context, spec Command) (Execution, error) {
	if err := validateCommand(spec); err != nil {
		return Execution{}, err
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultExecTimeout
	}
	limit := spec.OutputLimit
	if limit <= 0 {
		limit = defaultOutputLimit
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	if len(spec.Env) > 0 {
		cmd.Env = append(os.Environ(), spec.Env...)
	}
	stdout := &cappedBuffer{limit: limit}
	stderr := &cappedBuffer{limit: limit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	err := cmd.Run()
	result := Execution{
		Command:   append([]string{spec.Path}, spec.Args...),
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		ExitCode:  0,
		Duration:  time.Since(start),
		Truncated: stdout.Truncated() || stderr.Truncated(),
	}
	if err == nil {
		return result, nil
	}
	if runCtx.Err() != nil {
		return result, fmt.Errorf("external command stopped: %w", runCtx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("external command exited with status %d", result.ExitCode)
	}
	result.ExitCode = -1
	return result, fmt.Errorf("starting external command: %w", err)
}

func validateCommand(spec Command) error {
	path := strings.TrimSpace(spec.Path)
	if path == "" {
		return errors.New("external command path is required")
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh":
		return ErrShellForbidden
	}
	for i, value := range spec.Env {
		if !strings.Contains(value, "=") || strings.HasPrefix(value, "=") {
			return fmt.Errorf("environment entry %d must be KEY=VALUE", i)
		}
	}
	return nil
}

type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(p)
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func (b *cappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// RedactArgs removes known secret values from argv before audit/log output.
func RedactArgs(args, secrets []string) []string {
	out := append([]string(nil), args...)
	for i, arg := range out {
		for _, secret := range secrets {
			if secret != "" {
				arg = strings.ReplaceAll(arg, secret, "[REDACTED]")
			}
		}
		out[i] = arg
	}
	return out
}

// ParseExitCode is useful to parser adapters that receive an encoded status.
func ParseExitCode(raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("parsing exit code: %w", err)
	}
	return value, nil
}

var _ io.Writer = (*cappedBuffer)(nil)
