package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"math/rand"
)

const toolVersion = "v1.0.2"

var (
	templatesPath = ""
	proxyURL      = ""
	proxyList     []string
)

// Entry point
func main() {
	fmt.Printf("       Th3 Collect0r %s \n", toolVersion)
	fmt.Printf("By : Mohamed Ashraf & Ali Emara\n")
	fmt.Printf("Don't forget to include fuzzing-template/ directory in %s \n", os.Getenv("HOME")+"/nuclei-templates")
	printASCIIArt()

	args := os.Args[1:]
	if len(args) < 1 {
		printShortUsage()
		return
	}

	var (
		filePath          string
		parallelProcesses = 4
		customNucleiFlags string
		templateNames     = []string{
			"fuzzing-templates/lfi",
			"fuzzing-templates/xss",
			"fuzzing-templates/sqli",
			"fuzzing-templates/redirect",
			"fuzzing-templates/ssrf",
		}
		domain    string
		proxyFile string
	)
	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-d":
			i++
			if i < len(args) {
				domain = args[i]
				i++
			} else {
				fmt.Println("Error: Missing domain after -d option")
				return
			}
		case "-p":
			i++
			if i < len(args) {
				parallelProcesses = parseInt(args[i], parallelProcesses)
				i++
			} else {
				fmt.Println("Error: Missing value after -p option")
				return
			}
		case "-nf":
			i++
			if i < len(args) {
				customNucleiFlags = args[i]
				i++
			} else {
				fmt.Println("Error: Missing value after -nf option")
				return
			}
		case "-t":
			i++
			for i < len(args) && !strings.HasPrefix(args[i], "-") {
				templateNames = append(templateNames, args[i])
				i++
			}
		case "-f":
			i++
			if i < len(args) {
				filePath = args[i]
				i++
			} else {
				fmt.Println("Error: Missing file path after -f option")
				return
			}
		case "-proxy":
			i++
			if i < len(args) {
				proxyURL = args[i]
				i++
			} else {
				fmt.Println("Error: Missing value after -proxy option")
				return
			}
		case "-proxyfile":
			i++
			if i < len(args) {
				proxyFile = args[i]
				i++
			} else {
				fmt.Println("Error: Missing value after -proxyfile option")
				return
			}
		case "-h":
			printShortUsage()
			return
		case "--help":
			printFullUsage()
			return
		case "-tp":
			i++
			if i < len(args) {
				templatesPath = args[i]
				i++
			} else {
				fmt.Println("Error: Missing templates path after -tp option")
				return
			}
		default:
			fmt.Printf("Unrecognized option: %s\n", arg)
			return
		}
	}

	if proxyFile != "" {
		var err error
		proxyList, err = readProxiesFromFile(proxyFile)
		if err != nil {
			log.Fatalf("Error reading proxies from file: %v", err)
		}
	}
	rand.Seed(time.Now().UnixNano())

	if domain != "" {
		processDomain(domain, customNucleiFlags, templateNames)
		return
	}
	domains, err := readDomainsFromFile(filePath)
	if err != nil {
		log.Fatalf("Error reading domains from file: %v", err)
	}
	processDomains(domains, parallelProcesses, customNucleiFlags, templateNames)
}

func printASCIIArt() {
	fmt.Println(`
                    .::::.                    
                   .::..::.                   
                   ::.  .::                   
                  :::    :::                  
     :.::::::... ....    .... ....::::..:     
     .:::::::::. :..      ..: .:::::::::.     
       ::::::::  ...      ...  ::::::::       
        .::::.. ....      .... ..::::.        
         .:.... :..  ....  ..: ....:.         
            .:. .   .:..:.   . .:.            
         .::...      ....      ...::.         
        .:::.                    .:::.        
       ::.          ......          .::       
     .::.  ...:. ::..    ..:: .:...  .::.     
     :.:::::::.. ............ ..::::::..:     
                  ::::::::::                  
                   ::::::::                   
                   .::::::.                   
                    .::::.                    
                      ..                      
	`)
}

func printShortUsage() {
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
	fmt.Println("Use --help for a full list of available options.")
}

func printFullUsage() {
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
	fmt.Println("Scan a list of domains for security vulnerabilities using various tools.")
	fmt.Println("Options:")
	fmt.Println("  -f FILE_PATH    Path to the file containing a list of domains to process.")
	fmt.Println("  -s             Silence mode. Run the script in the background.")
	fmt.Println("  -p PARALLEL    Number of processes to run in parallel using GNU Parallel. Default: 4.")
	fmt.Println("  -nf FLAGS      Custom Nuclei flags to use for all scans.")
	fmt.Println("  -t TEMPLATE    Specify custom Nuclei template(s) for scans. Default: built-in templates.")
	fmt.Println("  -tp TEMPLATES_PATH   Path to the custom Nuclei templates. Default: /fuzzing-templates/")
	fmt.Println("  -proxy URL     Use a (single) proxy for HTTP and tool requests (supports http, https, socks4, socks5 etc.)")
	fmt.Println("  -proxyfile FILE  File with a list of proxies (one per line, all types supported; random selection per request)")
	fmt.Println("  -h, --help     Print this help message and exit.")
	fmt.Println("")
	fmt.Println("Single Target Testing:")
	fmt.Println("  -d DOMAIN      Perform scans on a single target domain.")
	fmt.Println("")
	fmt.Println("Note: Make sure you have proper authorization to perform security scans on the provided domains.")
}

func parseInt(s string, defaultValue int) int {
	value := defaultValue
	n, err := fmt.Sscanf(s, "%d", &value)
	if err != nil || n != 1 {
		return defaultValue
	}
	return value
}

func readDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func readProxiesFromFile(filePath string) ([]string, error) {
	var proxies []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	return proxies, scanner.Err()
}

func pickProxy() string {
	// If a proxy list is set, pick randomly from it
	if len(proxyList) > 0 {
		return proxyList[rand.Intn(len(proxyList))]
	}
	return proxyURL
}

func processDomains(domains []string, parallelProcesses int, customNucleiFlags string, templateNames []string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, parallelProcesses)
	for i := 0; i < len(domains); i += parallelProcesses {
		batchSize := min(parallelProcesses, len(domains)-i)
		for j := 0; j < batchSize; j++ {
			domain := domains[i+j]
			semaphore <- struct{}{}
			wg.Add(1)
			go func(domain string) {
				defer wg.Done()
				defer func() { <-semaphore }()
				processDomain(domain, customNucleiFlags, templateNames)
			}(domain)
		}
		wg.Wait()
	}
	close(semaphore)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func processDomain(domain, customNucleiFlags string, templateNames []string) {
	fmt.Printf("Processing %s...\n", domain)
	domainName := strings.TrimPrefix(domain, "http://")
	domainName = strings.TrimPrefix(domainName, "https://")

	if err := os.MkdirAll("Results", 0750); err != nil {
		log.Fatalf("Error creating Results directory: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "scan-temp-")
	if err != nil {
		log.Printf("Error creating temporary directory: %v", err)
		return
	}
	defer os.RemoveAll(tempDir)

	urls := make(map[string]bool)
	urlCollectWg := &sync.WaitGroup{}
	collectFuncs := []struct {
		name string
		fn   func(string, string) ([]byte, error)
	}{
		{"waybackurls", runWaybackurls},
		{"gau", runGau},
		{"katana", runKatana},
		{"hakrawler", runHakrawler},
	}

	urlsChan := make(chan string, 1000)
	for _, tool := range collectFuncs {
		urlCollectWg.Add(1)
		go func(toolName string, toolFn func(string, string) ([]byte, error)) {
			defer urlCollectWg.Done()
			output, err := toolFn(domainName, tempDir)
			if err != nil {
				log.Printf("Error running %s for %s: %v", toolName, domainName, err)
				return
			}
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				url := scanner.Text()
				if !strings.Contains(url, "://") {
					url = "https://" + url
				}
				urlsChan <- url
			}
		}(tool.name, tool.fn)
	}
	go func() {
		urlCollectWg.Wait()
		close(urlsChan)
	}()
	for url := range urlsChan {
		urls[url] = true
	}

	urlsFile := filepath.Join(tempDir, "urls.txt")
	if err := saveURLsToFile(urlsFile, urls); err != nil {
		log.Printf("Error saving URLs: %v", err)
		return
	}

	var scanWg sync.WaitGroup
	for _, templatePath := range templateNames {
		scanWg.Add(1)
		go func(tp string) {
			defer scanWg.Done()
			if err := performNucleiScan(urlsFile, tp, domain); err != nil {
				log.Printf("Error performing Nuclei scan for %s with template %s: %v", domainName, tp, err)
				return
			}
			fmt.Printf("Success: Nuclei scan completed for %s with template %s\n", domainName, tp)
		}(templatePath)
	}
	scanWg.Wait()

	if err := generateHTMLReport(domain, templateNames); err != nil {
		log.Printf("Error generating HTML report for %s: %v", domainName, err)
	} else {
		fmt.Printf("Success: HTML report generated for %s\n", domainName)
	}

	if err := findRealIPAddress(domain); err != nil {
		log.Printf("Error finding real IP address: %v", err)
	}
	realIPFile := fmt.Sprintf("Results/%s_real_ip.txt", sanitizeFileName(domain))
	realIP, err := os.ReadFile(realIPFile)
	if err != nil {
		log.Printf("Error reading real IP address file: %v", err)
	} else {
		if err := requestShodanData(strings.TrimSpace(string(realIP))); err != nil {
			log.Printf("Error requesting Shodan data: %v", err)
		}
	}

	fmt.Printf("Done processing %s\n", domainName)
}

// ---- Proxy-aware tool runners and HTTP ----

func setCmdProxyEnv(cmd *exec.Cmd) {
	proxy := pickProxy()
	if proxy == "" {
		return
	}
	// HTTP_PROXY and HTTPS_PROXY are respected by most CLI tools, SOCKS proxies by some (e.g. with ALL_PROXY)
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
	)
}

func runWaybackurls(domain, tempDir string) ([]byte, error) {
	cmd := exec.Command("waybackurls", domain)
	setCmdProxyEnv(cmd)
	return cmd.Output()
}

func runGau(domain, tempDir string) ([]byte, error) {
	cmd := exec.Command("gau", domain)
	setCmdProxyEnv(cmd)
	return cmd.Output()
}

func runKatana(domain, tempDir string) ([]byte, error) {
	cmd := exec.Command("katana", "-u", domain)
	setCmdProxyEnv(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), err
}

func runHakrawler(domain, tempDir string) ([]byte, error) {
	cmd := exec.Command("hakrawler")
	setCmdProxyEnv(cmd)
	cmd.Stdin = strings.NewReader(domain)
	return cmd.Output()
}

func saveURLsToFile(filePath string, urls map[string]bool) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	for url := range urls {
		_, err := file.WriteString(url + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// Nuclei function with proxy support
func performNucleiScan(urlsFile, templatePath, domain string) error {
	templateName := filepath.Base(templatePath)
	outputFile := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templateName)
	proxy := pickProxy()
	var nucleiCmd *exec.Cmd
	if proxy != "" {
		// Try to detect the proxy type and build the command accordingly.
		if strings.HasPrefix(proxy, "socks5") || strings.HasPrefix(proxy, "socks4") {
			nucleiCmd = exec.Command("sh", "-c",
				fmt.Sprintf("ALL_PROXY=%s nuclei -l %s -t %s -o %s", proxy, urlsFile, templatePath, outputFile))
		} else {
			nucleiCmd = exec.Command("sh", "-c",
				fmt.Sprintf("HTTP_PROXY=%s HTTPS_PROXY=%s nuclei -l %s -t %s -o %s", proxy, proxy, urlsFile, templatePath, outputFile))
		}
	} else {
		nucleiCmd = exec.Command("sh", "-c",
			fmt.Sprintf("nuclei -l %s -t %s -o %s", urlsFile, templatePath, outputFile))
	}
	nucleiCmd.Stdout = os.Stdout
	nucleiCmd.Stderr = os.Stderr
	return nucleiCmd.Run()
}

// Proxy-aware HTTP for Shodan
func requestShodanData(ipAddress string) error {
	apiUrl := fmt.Sprintf("https://internetdb.shodan.io/%s", ipAddress)
	client := &http.Client{}
	proxy := pickProxy()
	if proxy != "" {
		proxyParsed, err := url.Parse(proxy)
		if err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyParsed)}
		}
	}
	response, err := client.Get(apiUrl)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request to Shodan API failed with status code: %d", response.StatusCode)
	}
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	outputFile := "shodan_results.txt"
	err = os.WriteFile(outputFile, data, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Success: Shodan data for IP %s saved to %s\n", ipAddress, outputFile)
	return nil
}

// DNS lookup (no proxy, direct)
func findRealIPAddress(domain string) error {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return err
	}
	realIPAddress := ips[0]
	outputFile := fmt.Sprintf("Results/%s_real_ip.txt", sanitizeFileName(domain))
	err = os.WriteFile(outputFile, []byte(realIPAddress), 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Success: Real IP address for %s is %s\n", domain, realIPAddress)
	return nil
}

// ---- Utilities and HTML ----

func generateHTMLReport(domain string, templateNames []string) error {
	reportFileName := fmt.Sprintf("%s.html", sanitizeFileName(domain))
	reportFile, err := os.Create(reportFileName)
	if err != nil {
		return err
	}
	defer reportFile.Close()

	reportTemplate := `
<!DOCTYPE html>
<html>
<head>
  <title>Security Scan Report for %s</title>
  <style>
    %s
  </style>
  <script>
    %s
  </script>
</head>
<body>
  <h1>Security Scan Report for %s</h1>
  <h2>Results:</h2>
  %s
</body>
</html>
`
	cssContent, _ := loadFileContents("styles.css")
	jsContent, _ := loadFileContents("script.js")
	var sections []string
	for i, templatePath := range templateNames {
		sectionID := fmt.Sprintf("template%d", i+1)
		sectionTitle := fmt.Sprintf("Template %d Results:", i+1)
		outputFilePath := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templatePath)
		output, err := readOutputFile(outputFilePath)
		if err != nil {
			output = fmt.Sprintf("Error reading output: %v", err)
		}
		escapedOutput := html.EscapeString(output)
		sections = append(sections, fmt.Sprintf(`<h2 id="%s">%s</h2><pre>%s</pre>`, sectionID, sectionTitle, escapedOutput))
	}
	reportContent := fmt.Sprintf(reportTemplate, domain, cssContent, jsContent, domain, strings.Join(sections, "\n"))
	_, err = reportFile.WriteString(reportContent)
	if err != nil {
		return err
	}
	fmt.Printf("HTML report generated: %s\n", reportFileName)
	return nil
}

func loadFileContents(filePath string) (string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func readOutputFile(filePath string) (string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func sanitizeFileName(fileName string) string {
	return strings.ReplaceAll(fileName, ".", "_")
}
