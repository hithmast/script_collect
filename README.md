# Th3 Collect0r

A parallelized recon and fuzzing toolkit for bug bounty and penetration testing, supporting advanced proxy options and robust reporting.

## Features

- **Parallel domain processing** for speed
- **Multiple URL collection tools**: waybackurls, gau, katana, hakrawler
- **Flexible Nuclei fuzzing** with custom template support
- **HTML report generation**
- **Flexible proxy support**:
  - Single proxy via CLI
  - Multiple proxies via file, with random selection per request (supports `http`, `https`, `socks4`, `socks5`)
- **Shodan IP lookup with proxy**
- **Extensible and robust error handling**

## Usage

```sh
go run th3collect0r.go -f domains.txt [OPTIONS]
go run th3collect0r.go -d example.com [OPTIONS]
```

### Options

| Option           | Description                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------|
| `-f FILE_PATH`   | Path to the file containing a list of domains to process.                                           |
| `-d DOMAIN`      | Perform scans on a single target domain.                                                            |
| `-p PARALLEL`    | Number of domains to process in parallel. Default: 4                                                |
| `-nf FLAGS`      | Custom Nuclei flags to use for all scans.                                                           |
| `-t TEMPLATE`    | Specify custom Nuclei templates (repeatable). Default: built-in templates.                          |
| `-tp PATH`       | Path to custom Nuclei templates. Default: `/fuzzing-templates/`                                     |
| `-proxy URL`     | Use a (single) proxy for HTTP and tool requests. Supports all types: `http`, `https`, `socks4`, `socks5` |
| `-proxyfile FILE`| File with a list of proxies (one per line; all types supported; randomized selection per request)   |
| `-h, --help`     | Print help message and exit.                                                                        |

**Note:**  
- If both `-proxy` and `-proxyfile` are set, proxies from the file will be used (randomized per request/tool run).
- Most CLI tools and HTTP requests will use the selected proxy.  
- Proxy file example (one per line):  
  ```
  http://127.0.0.1:8080
  socks5://127.0.0.1:9050
  ```

## Output

- All results and reports are stored in the `Results/` directory and as HTML reports in the current working directory.
- Shodan results are stored in `shodan_results.txt`.

## Requirements

- Go 1.17+
- External tools installed and in `$PATH`: `waybackurls`, `gau`, `katana`, `hakrawler`, `nuclei`
- Nuclei templates in the specified directory

## Example

```sh
go run th3collect0r.go -f targets.txt -p 5 -proxyfile proxies.txt
```

## License

MIT

---

**Disclaimer:**  
Make sure you have proper authorization to scan the domains you test. This tool is for educational and authorized testing only.
