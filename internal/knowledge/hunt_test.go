package knowledge

import (
	"reflect"
	"testing"
)

func TestLookupParameter(t *testing.T) {
	tests := []struct {
		parameter string
		want      []VulnerabilityClass
	}{
		{"user_id", []VulnerabilityClass{ClassIDOR, ClassSQLI}},
		{"callbackURL", []VulnerabilityClass{ClassSSRF, ClassXSS}},
		{"upload_filename", []VulnerabilityClass{ClassLFI, ClassRFI, ClassUpload}},
		{"ordinary", nil},
	}
	for _, test := range tests {
		t.Run(test.parameter, func(t *testing.T) {
			got := LookupParameter(test.parameter).Classes
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("LookupParameter(%q).Classes = %v, want %v", test.parameter, got, test.want)
			}
		})
	}
}
