package tools_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/acevenen/sentinel/internal/tools"
	"github.com/acevenen/sentinel/internal/tools/aircrack"
	"github.com/acevenen/sentinel/internal/tools/hashcat"
	"github.com/acevenen/sentinel/internal/tools/hping"
	"github.com/acevenen/sentinel/internal/tools/kali"
	"github.com/acevenen/sentinel/internal/tools/metasploit"
	"github.com/acevenen/sentinel/internal/tools/setoolkit"
	"github.com/acevenen/sentinel/internal/tools/skipfish"
	"github.com/acevenen/sentinel/internal/tools/sqlmap"
	"github.com/acevenen/sentinel/internal/tools/tshark"
)

func TestAdapterParsersGoldenFiles(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		parse     func([]byte) ([]tools.Finding, error)
		targetDir string
	}{
		{
			name: "hping3", output: "output.txt", targetDir: "hping3",
			parse: func(data []byte) ([]tools.Finding, error) { return hping.ParseOutput(data), nil },
		},
		{
			name: "tshark", output: "output.json", targetDir: "tshark",
			parse: tshark.ParseJSON,
		},
		{
			name: "skipfish", output: "output.txt", targetDir: "skipfish",
			parse: func(data []byte) ([]tools.Finding, error) { return skipfish.ParseSummary(data), nil },
		},
		{
			name: "sqlmap", output: "output.txt", targetDir: "sqlmap",
			parse: func(data []byte) ([]tools.Finding, error) {
				return sqlmap.ParseOutput(data, "https://lab.local/item?id=1"), nil
			},
		},
		{
			name: "metasploit", output: "output.txt", targetDir: "metasploit",
			parse: func(data []byte) ([]tools.Finding, error) {
				return metasploit.ParseOutput(data, "192.0.2.10"), nil
			},
		},
		{
			name: "hashcat", output: "output.txt", targetDir: "hashcat",
			parse: func(data []byte) ([]tools.Finding, error) { return hashcat.ParseShow(data), nil },
		},
		{
			name: "aircrack-ng", output: "output.txt", targetDir: "aircrack-ng",
			parse: func(data []byte) ([]tools.Finding, error) {
				return aircrack.ParseOutput(data, "AA:BB:CC:DD:EE:FF"), nil
			},
		},
		{
			name: "set", output: "output.csv", targetDir: "set",
			parse: setoolkit.ParseResults,
		},
		{
			name: "kali-utils", output: "output.txt", targetDir: "kali-utils",
			parse: func(data []byte) ([]tools.Finding, error) {
				return kali.ParseOutput(data, "https://lab.local"), nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := os.ReadFile(toolFixture(test.targetDir, test.output))
			if err != nil {
				t.Fatal(err)
			}
			got, err := test.parse(output)
			if err != nil {
				t.Fatal(err)
			}
			expectedData, err := os.ReadFile(toolFixture(test.targetDir, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var want []tools.Finding
			if err := json.Unmarshal(expectedData, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parser result = %#v, want %#v", got, want)
			}
		})
	}
}

func toolFixture(directory, name string) string {
	return filepath.Join("..", "..", "testdata", "tools", directory, name)
}
