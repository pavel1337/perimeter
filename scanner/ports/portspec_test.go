package ports

import (
	"slices"
	"testing"
)

func TestParsePorts(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want []int
	}{
		{"22", []int{22}},
		{"1-3", []int{1, 2, 3}},
		{" 80 , 443,8080-8081 ", []int{80, 443, 8080, 8081}},
		{"443,80,80,79-81", []int{79, 80, 81, 443}}, // sorted, no duplicates
		{"65535", []int{65535}},
		{"1-1,", []int{1}},
	} {
		got, err := ParsePorts(tc.spec)
		if err != nil {
			t.Errorf("ParsePorts(%q): %v", tc.spec, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", tc.spec, got, tc.want)
		}
	}
}

func TestParsePortsRejects(t *testing.T) {
	for _, spec := range []string{"", ",", "0", "65536", "-5", "80-", "9-3", "http", "1-2-3", "22,abc"} {
		if got, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) = %v, want an error", spec, got)
		}
	}
}

// The default is nmap's top 1000 plus the infrastructure ports the issue
// named, and "default" can be extended (issue #64).
func TestDefaultPorts(t *testing.T) {
	def, err := ParsePorts(DefaultSpec)
	if err != nil {
		t.Fatalf("ParsePorts(default): %v", err)
	}
	top, err := ParsePorts(nmapTop1000)
	if err != nil {
		t.Fatalf("ParsePorts(nmapTop1000): %v", err)
	}
	if len(top) != 1000 {
		t.Errorf("nmapTop1000 has %d ports, want 1000", len(top))
	}
	for _, p := range []int{22, 80, 443, 3000, 3306, 5432, 6379, 6443, 8080, 27017} {
		if !slices.Contains(def, p) {
			t.Errorf("default ports miss %d", p)
		}
	}
	more, err := ParsePorts("default,61234")
	if err != nil {
		t.Fatalf("ParsePorts(default,61234): %v", err)
	}
	if len(more) != len(def)+1 || !slices.Contains(more, 61234) {
		t.Errorf("default,61234 has %d ports, want %d including 61234", len(more), len(def)+1)
	}
}
