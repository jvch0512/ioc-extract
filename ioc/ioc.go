// Package ioc extracts indicators of compromise (IPs, domains, URLs, hashes, emails, CVEs) from free text
// such as threat reports and phishing emails. It understands "defanged" notation (hxxp, [.], (dot)).
package ioc

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type Type string

const (
	IPv4   Type = "ipv4"
	IPv6   Type = "ipv6"
	Domain Type = "domain"
	URL    Type = "url"
	Email  Type = "email"
	MD5    Type = "md5"
	SHA1   Type = "sha1"
	SHA256 Type = "sha256"
	CVE    Type = "cve"
)

type Indicator struct {
	Type  Type   `json:"type"`
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Refang converts common defanging back to normal form.
func Refang(s string) string {
	r := strings.NewReplacer("[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", " dot ", ".",
		"[:]", ":", "[://]", "://", "[@]", "@", "(at)", "@", "[at]", "@")
	s = r.Replace(s)
	s = regexp.MustCompile(`(?i)\bhxxps?://`).ReplaceAllStringFunc(s, func(m string) string { return "http" + strings.ToLower(m[4:]) })
	s = regexp.MustCompile(`(?i)\bfxp://`).ReplaceAllString(s, "ftp://")
	return s
}

// Defang makes an indicator safe to paste into chat or tickets.
func Defang(v string) string {
	v = strings.Replace(v, "http", "hxxp", 1)
	return strings.NewReplacer(".", "[.]", "@", "[@]").Replace(v)
}

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"'\)\]]+`)
	reEmail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\b`)
	reIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?\b`)
	reDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	reHash   = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b`)
	reCVE    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

// File extensions that look like TLDs but are almost always filenames in reports.
var fileLike = map[string]bool{"exe": true, "dll": true, "txt": true, "doc": true, "docx": true, "pdf": true, "png": true, "jpg": true, "js": true, "py": true, "sh": true, "bat": true, "ps1": true, "zip": true, "json": true, "xml": true, "log": true, "tmp": true, "sys": true, "lnk": true, "vbs": true, "md": true}

type Options struct {
	// KeepPrivate keeps RFC 1918, loopback and link-local addresses (dropped by default).
	KeepPrivate bool
	// KeepFilenames keeps strings like evil.exe as domains.
	KeepFilenames bool
}

// Extract finds indicators in text, deduplicates them and counts occurrences.
// Indicators inside URLs or emails are not repeated as separate domains.
func Extract(text string, opt Options) []Indicator {
	text = Refang(text)
	counts := map[Indicator]int{}
	add := func(t Type, v string) { counts[Indicator{Type: t, Value: v}]++ }
	masked := text

	for _, u := range reURL.FindAllString(text, -1) {
		u = strings.TrimRight(u, ".,;:!?")
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			add(URL, u)
			masked = strings.Replace(masked, u, " ", 1)
			if h := p.Hostname(); net.ParseIP(h) != nil {
				add(ipType(h), h)
			} else {
				add(Domain, strings.ToLower(h))
			}
		}
	}
	for _, e := range reEmail.FindAllString(masked, -1) {
		e = strings.ToLower(e)
		add(Email, e)
		add(Domain, e[strings.Index(e, "@")+1:])
		masked = strings.Replace(masked, e, " ", 1)
	}
	for _, h := range reHash.FindAllString(masked, -1) {
		h = strings.ToLower(h)
		add(map[int]Type{32: MD5, 40: SHA1, 64: SHA256}[len(h)], h)
		masked = strings.Replace(masked, h, " ", 1)
	}
	for _, c := range reCVE.FindAllString(masked, -1) {
		add(CVE, strings.ToUpper(c))
	}
	for _, ip := range reIPv4.FindAllString(masked, -1) {
		if p := net.ParseIP(ip); p != nil && p.To4() != nil && !strings.Contains(ip, "00") && validOctets(ip) {
			add(IPv4, ip)
			masked = strings.Replace(masked, ip, " ", 1)
		}
	}
	for _, ip := range reIPv6.FindAllString(masked, -1) {
		if p := net.ParseIP(ip); p != nil && p.To4() == nil {
			add(IPv6, strings.ToLower(ip))
		}
	}
	for _, d := range reDomain.FindAllString(masked, -1) {
		d = strings.ToLower(d)
		tld := d[strings.LastIndex(d, ".")+1:]
		if net.ParseIP(d) != nil || (!opt.KeepFilenames && fileLike[tld]) {
			continue
		}
		add(Domain, d)
	}

	var out []Indicator
	for k, n := range counts {
		if !opt.KeepPrivate && isPrivate(k) {
			continue
		}
		k.Count = n
		out = append(out, k)
	}
	order := map[Type]int{URL: 0, Domain: 1, IPv4: 2, IPv6: 3, Email: 4, SHA256: 5, SHA1: 6, MD5: 7, CVE: 8}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return order[out[i].Type] < order[out[j].Type]
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func ipType(h string) Type {
	if p := net.ParseIP(h); p != nil && p.To4() == nil {
		return IPv6
	}
	return IPv4
}

func validOctets(ip string) bool {
	for _, o := range strings.Split(ip, ".") {
		if len(o) > 1 && o[0] == '0' {
			return false
		}
	}
	return true
}

func isPrivate(i Indicator) bool {
	if i.Type != IPv4 && i.Type != IPv6 {
		return false
	}
	p := net.ParseIP(i.Value)
	return p != nil && (p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified())
}
