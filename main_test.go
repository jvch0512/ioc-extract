package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func exec(args []string, in string) (int, string, string) {
	var o, e bytes.Buffer
	c := run(args, strings.NewReader(in), &o, &e)
	return c, o.String(), e.String()
}

func TestTextFilterAndDefang(t *testing.T) {
	_, out, _ := exec([]string{"-type", "ipv4", "-defang", "samples/report.txt"}, "")
	if !strings.Contains(out, "203[.]0[.]113[.]45 (x2)") || strings.Contains(out, "sha256") {
		t.Fatalf("\n%s", out)
	}
}

func TestJSONAndStdin(t *testing.T) {
	code, out, _ := exec([]string{"-format", "json"}, "see CVE-2023-4863")
	var v []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil || len(v) != 1 || v[0]["type"] != "cve" {
		t.Fatalf("%d %s", code, out)
	}
	_, out, _ = exec([]string{"-format", "json"}, "nothing here")
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("empty result must be [] not null: %q", out)
	}
}

func TestCSVFormulaInjection(t *testing.T) {
	_, out, _ := exec([]string{"-format", "csv"}, "=cmd|'/c calc'!A1 and mail -x@evil.example")
	for _, line := range strings.Split(out, "\n")[1:] {
		fields := strings.Split(line, ",")
		if len(fields) > 1 && strings.ContainsAny(fields[1][:min(1, len(fields[1]))], "=+-@") {
			t.Fatalf("unsafe CSV cell: %q", line)
		}
	}
}

func TestErrors(t *testing.T) {
	if c, _, _ := exec([]string{"-format", "xml"}, "x"); c != 2 {
		t.Error("bad format")
	}
	if c, _, _ := exec([]string{"missing.txt"}, ""); c != 2 {
		t.Error("missing file")
	}
}
