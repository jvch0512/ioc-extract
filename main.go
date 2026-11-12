package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jvch0512/ioc-extract/ioc"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ioc-extract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text, json or csv")
	only := fs.String("type", "", "comma separated types to keep (ipv4,domain,url,sha256,...)")
	defang := fs.Bool("defang", false, "defang values in the output so they are safe to paste")
	private := fs.Bool("keep-private", false, "keep private, loopback and link-local IPs")
	files := fs.Bool("keep-filenames", false, "keep file-like names such as evil.exe as domains")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var data []byte
	var err error
	if fs.NArg() == 0 || fs.Arg(0) == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(fs.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	keep := map[string]bool{}
	for _, t := range strings.Split(*only, ",") {
		if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
			keep[t] = true
		}
	}
	var out []ioc.Indicator
	for _, i := range ioc.Extract(string(data), ioc.Options{KeepPrivate: *private, KeepFilenames: *files}) {
		if len(keep) > 0 && !keep[string(i.Type)] {
			continue
		}
		if *defang {
			i.Value = ioc.Defang(i.Value)
		}
		out = append(out, i)
	}
	switch *format {
	case "json":
		if out == nil {
			out = []ioc.Indicator{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	case "csv":
		w := csv.NewWriter(stdout)
		_ = w.Write([]string{"type", "value", "count"})
		for _, i := range out {
			_ = w.Write([]string{string(i.Type), safeCell(i.Value), fmt.Sprint(i.Count)})
		}
		w.Flush()
	case "text":
		for _, i := range out {
			fmt.Fprintf(stdout, "%-7s %s (x%d)\n", i.Type, i.Value, i.Count)
		}
	default:
		fmt.Fprintln(stderr, "-format must be text, json or csv")
		return 2
	}
	return 0
}

// safeCell neutralises spreadsheet formula injection from attacker-controlled report text.
func safeCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
