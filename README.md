# ioc-extract

Pull indicators of compromise out of threat reports, phishing emails and tickets: IPv4/IPv6, domains, URLs, emails, MD5/SHA1/SHA256 hashes and CVE IDs. It understands defanged notation (`hxxp`, `[.]`, `(dot)`, `[@]`), deduplicates, counts occurrences and can re-defang the output so it is safe to paste into chat. Go standard library only.

> Built with AI assistance (Claude) as part of a security portfolio. The sample report is fictional and uses documentation address ranges.

## Usage

```bash
go run . samples/report.txt
go run . -type ipv4,sha256 -format json samples/report.txt
cat mail.txt | go run . -defang -format csv -
```

Exit codes: 0 ok, 2 usage or file error.

## Design choices

- Defanged and plain forms of the same indicator merge into one entry with a combined count.
- Hosts inside URLs and email domains are reported as domains once; text already consumed by a URL, email or hash is masked so it cannot produce false positives.
- Private, loopback and link-local IPs are dropped by default (`-keep-private` keeps them). File-like names such as `evil.exe` are not domains (`-keep-filenames` keeps them). Invalid IPs (`999.1.1.1`), version strings (`1.2.3.4.5`) and zero-padded octets are rejected.
- CSV output prefixes cells starting with `=`, `+`, `-` or `@` with a quote, because report text is attacker-controlled and can carry spreadsheet formulas.
- Output order is deterministic.

## Tests

`go test -race ./...` covers refanging, each indicator type, false positives, masking, hash classification, defanging, determinism and the CLI. CI runs on Linux, macOS and Windows.

MIT licensed.
