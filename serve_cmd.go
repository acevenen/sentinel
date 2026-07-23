package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/acevenen/sentinel/internal/webui"
)

func newServeCmd() *cobra.Command {
	var (
		port   int
		noOpen bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Open the Sentinel desktop app (local UI in its own window)",
		Long: "Serve starts a local, loopback-only web server and opens the Sentinel app in its own " +
			"window. The UI drives the same scan/guard/evaluate/hunt engine in-process — nothing is sent " +
			"anywhere except the targets you explicitly authorize. The server binds to 127.0.0.1 and its " +
			"API is gated by a per-launch token, so no other page on your machine can drive it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			srv, err := webui.New(version)
			if err != nil {
				return err
			}

			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return fmt.Errorf("starting local server: %w", err)
			}
			url := fmt.Sprintf("http://%s/", ln.Addr().String())

			httpSrv := &http.Server{
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}

			// Shut down cleanly on Ctrl+C.
			go func() {
				<-cmd.Context().Done()
				shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = httpSrv.Shutdown(shutCtx)
			}()

			fmt.Fprintf(os.Stderr, "Sentinel is running at %s\n", url)
			fmt.Fprintln(os.Stderr, "Close this terminal (or press Ctrl+C) to stop the app.")
			if !noOpen {
				openApp(url)
			}

			if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "port to listen on (0 = pick a free port)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not open a window automatically")
	return cmd
}

// openApp opens the UI in its own app-style window when a Chromium browser is
// available (a chromeless window, not a browser tab), falling back to the
// default browser.
func openApp(url string) {
	if runtime.GOOS == "windows" {
		for _, exe := range chromiumPaths() {
			if _, err := os.Stat(exe); err == nil {
				if err := exec.Command(exe, "--app="+url, "--new-window").Start(); err == nil {
					return
				}
			}
		}
		_ = exec.Command("cmd", "/c", "start", "", url).Start()
		return
	}
	// macOS / Linux: try an app-mode Chrome/Chromium, else the default opener.
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge"} {
		if path, err := exec.LookPath(name); err == nil {
			if err := exec.Command(path, "--app="+url).Start(); err == nil {
				return
			}
		}
	}
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	_ = exec.Command(opener, url).Start()
}

// chromiumPaths returns common Edge/Chrome install locations on Windows.
func chromiumPaths() []string {
	var out []string
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
		if base == "" {
			continue
		}
		out = append(out,
			base+`\Microsoft\Edge\Application\msedge.exe`,
			base+`\Google\Chrome\Application\chrome.exe`,
		)
	}
	return out
}
