package ioc

import "testing"

func find(in []Indicator, t Type, v string) *Indicator {
	for i := range in {
		if in[i].Type == t && in[i].Value == v {
			return &in[i]
		}
	}
	return nil
}

const sample = `Mail from billing@invoice-secure[.]example linked to hxxps://login.invoice-secure[.]example/verify?id=7 .
Loader evil.exe sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 beacons to 203.0.113.45 and
2001:db8::1 and 203[.]0[.]113[.]45. Internal 10.1.2.3. MD5 d41d8cd98f00b204e9800998ecf8427e.
CVE-2024-3094 and cve-2024-3094. Version 1.2.3.4.5 and 999.1.1.1.`

func TestRefang(t *testing.T) {
	for in, want := range map[string]string{"hxxp://a[.]b": "http://a.b", "HXXPS://x(dot)com": "https://x.com", "a[@]b[.]c": "a@b.c", "fxp://h": "ftp://h"} {
		if got := Refang(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestExtractSample(t *testing.T) {
	got := Extract(sample, Options{})
	checks := []struct {
		t Type
		v string
	}{
		{URL, "https://login.invoice-secure.example/verify?id=7"},
		{Domain, "login.invoice-secure.example"},
		{Domain, "invoice-secure.example"},
		{Email, "billing@invoice-secure.example"},
		{IPv4, "203.0.113.45"},
		{IPv6, "2001:db8::1"},
		{SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{MD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{CVE, "CVE-2024-3094"},
	}
	for _, c := range checks {
		if find(got, c.t, c.v) == nil {
			t.Errorf("missing %s %s in %+v", c.t, c.v, got)
		}
	}
	if ip := find(got, IPv4, "203.0.113.45"); ip == nil || ip.Count != 2 {
		t.Errorf("defanged and plain forms of one IP should count twice: %+v", ip)
	}
	if c := find(got, CVE, "CVE-2024-3094"); c == nil || c.Count != 2 {
		t.Errorf("CVE case-insensitive merge: %+v", c)
	}
}

func TestFalsePositivesAreDropped(t *testing.T) {
	got := Extract(sample, Options{})
	for _, bad := range []string{"10.1.2.3", "999.1.1.1", "1.2.3.4.5", "evil.exe"} {
		for _, i := range got {
			if i.Value == bad {
				t.Errorf("%s should not be reported: %+v", bad, i)
			}
		}
	}
	if find(Extract(sample, Options{KeepPrivate: true}), IPv4, "10.1.2.3") == nil {
		t.Error("KeepPrivate should keep 10.1.2.3")
	}
	if find(Extract("run evil.exe now", Options{KeepFilenames: true}), Domain, "evil.exe") == nil {
		t.Error("KeepFilenames should keep evil.exe")
	}
}

func TestEmailDomainNotDuplicatedFromMaskedText(t *testing.T) {
	got := Extract("contact a@corp.example", Options{})
	if len(got) != 2 {
		t.Fatalf("want email + its domain only: %+v", got)
	}
}

func TestHashLengthsClassified(t *testing.T) {
	got := Extract("da39a3ee5e6b4b0d3255bfef95601890afd80709 d41d8cd98f00b204e9800998ecf8427e", Options{})
	if find(got, SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == nil || find(got, MD5, "d41d8cd98f00b204e9800998ecf8427e") == nil {
		t.Fatalf("%+v", got)
	}
}

func TestDefang(t *testing.T) {
	if got := Defang("https://evil.example/a"); got != "hxxps://evil[.]example/a" {
		t.Error(got)
	}
	if got := Defang("a@b.example"); got != "a[@]b[.]example" {
		t.Error(got)
	}
}

func TestEmptyAndSortedOutput(t *testing.T) {
	if len(Extract("", Options{})) != 0 {
		t.Fatal("empty")
	}
	a := Extract(sample, Options{})
	b := Extract(sample, Options{})
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("output must be deterministic")
		}
	}
}
