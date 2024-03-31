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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const toolVersion = "v1.0.1"

var templatesPath = ""

func main() {
	// Print tool version and ASCII art
	fmt.Printf("       Th3 Collect0r %s \n", toolVersion)
	fmt.Printf("By : Mohamed Ashraf & Ali Emara\n")
	fmt.Printf("Don't forget to include fuzzing-template/ directory in %s \n", os.Getenv("HOME")+"/nuclei-templates")
	printASCIIArt()

	// Parse command-line arguments
	args := os.Args[1:]
	if len(args) < 1 {
		printShortUsage()
		return
	}

	// Default values
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
		domain string // Store the domain if -d option is used
	)

	// Process arguments
	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-d":
			i++
			if i < len(args) {
				domain = args[i]
				i++ // Move to the next argument
			} else {
				fmt.Println("Error: Missing domain after -d option")
				return
			}
		case "-p":
			i++
			if i < len(args) {
				parallelProcesses = parseInt(args[i], parallelProcesses)
				i++ // Move to the next argument
			} else {
				fmt.Println("Error: Missing value after -p option")
				return
			}
		case "-nf":
			i++
			if i < len(args) {
				customNucleiFlags = args[i]
				i++ // Move to the next argument
			} else {
				fmt.Println("Error: Missing value after -nf option")
				return
			}
		case "-t":
			i++
			for i < len(args) && !strings.HasPrefix(args[i], "-") {
				templateNames = append(templateNames, args[i])
				i++ // Move to the next argument
			}
		case "-f":
			i++
			if i < len(args) {
				filePath = args[i]
				i++ // Move to the next argument
			} else {
				fmt.Println("Error: Missing file path after -f option")
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
				i++ // Move to the next argument
			} else {
				fmt.Println("Error: Missing templates path after -tp option")
				return
			}
		default:
			fmt.Printf("Unrecognized option: %s\n", arg)
			return
		}
	}

	// ... (Validate input file existence and readability)

	// If -d option is used, process the specific domain
	if domain != "" {
		processDomain(domain, customNucleiFlags, templateNames)
		return
	}

	// Read the list of domains from the input file
	domains, err := readDomainsFromFile(filePath)
	if err != nil {
		log.Fatalf("Error reading domains from file: %v", err)
	}

	// Process domains and perform fuzzing scans
	processDomains(domains, parallelProcesses, customNucleiFlags, templateNames)
}

// ASCII art for the start
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

// Print short usage instructions
func printShortUsage() {
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
	fmt.Println("Use --help for a full list of available options.")
}

// Print full usage instructions
func printFullUsage() {
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
	fmt.Println("Scan a list of domains for security vulnerabilities using various tools.")
	fmt.Println("Options:")
	fmt.Println("  -f FILE_PATH    Path to the file containing a list of domains to process.")
	fmt.Println("  -s             Silence mode. Run the script in the background.")
	fmt.Println("  -p PARALLEL    Number of processes to run in parallel using GNU Parallel. Default: 4.")
	fmt.Println("  -nf FLAGS      Custom Nuclei flags to use for all scans.")
	fmt.Println("  -t TEMPLATE   Specify the custom Nuclei template for the first scan. Default: /fuzzing-templates/lfi")
	fmt.Println("  -t TEMPLATE   Specify the custom Nuclei template for the second scan. Default: /fuzzing-templates/xss/reflected-xss.yaml")
	fmt.Println("  -t TEMPLATE   Specify the custom Nuclei template for the third scan. Default: /fuzzing-templates/sqli/error-based.yaml")
	fmt.Println("  -t TEMPLATE   Specify the custom Nuclei template for the fourth scan. Default: /fuzzing-templates/redirect")
	fmt.Println("  -t TEMPLATE   Specify the custom Nuclei template for the fifth scan. Default: /fuzzing-templates/ssrf")
	fmt.Println("  -tp TEMPLATES_PATH   Path to the custom Nuclei templates. Default: /fuzzing-templates/")
	fmt.Println("  -h, --help     Print this help message and exit.")
	fmt.Println("")
	fmt.Println("Single Target Testing:")
	fmt.Println("  -d DOMAIN      Perform scans on a single target domain.")
	fmt.Println("")
	fmt.Println("Note: Make sure you have proper authorization to perform security scans on the provided domains.")
}

// Find IP Func
func findRealIPAddress(domain string) error {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return err
	}

	realIPAddress := ips[0] // Take the first IP address
	outputFile := fmt.Sprintf("Results/%s_real_ip.txt", sanitizeFileName(domain))

	err = os.WriteFile(outputFile, []byte(realIPAddress), 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Success: Real IP address for %s is %s\n", domain, realIPAddress)
	return nil
}

// SHODAN Func
func requestShodanData(ipAddress string) error {
	apiUrl := fmt.Sprintf("https://internetdb.shodan.io/%s", ipAddress)

	response, err := http.Get(apiUrl)
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

// Parseint func
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

func processDomains(domains []string, parallelProcesses int, customNucleiFlags string, templateNames []string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, parallelProcesses) // Allow up to 'parallelProcesses' goroutines in parallel

	// Iterate through domains in batches
	for i := 0; i < len(domains); i += parallelProcesses {
		// Determine the number of domains to process in this batch
		batchSize := min(parallelProcesses, len(domains)-i)

		// Launch goroutines for this batch
		for j := 0; j < batchSize; j++ {
			domain := domains[i+j]
			semaphore <- struct{}{} // Acquire a slot in the semaphore
			wg.Add(1)
			go func(domain string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release a slot in the semaphore
				processDomain(domain, customNucleiFlags, templateNames)
			}(domain)
		}

		// Wait for the batch to complete before moving to the next
		wg.Wait()
	}

	close(semaphore) // Close the semaphore channel
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func processDomain(domain, customNucleiFlags string, templateNames []string) {
	fmt.Printf("Processing %s...\n", domain)

	// Extract domain name from the URL
	domainName := strings.TrimPrefix(domain, "http://")
	domainName = strings.TrimPrefix(domainName, "https://")
	// Create Result dir
	err := os.Mkdir("Results", 0750)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Error creating Results directory: %v", err)
		log.Fatal(err)

	}
	defer os.Exit(0)
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "scan-temp-")
	if err != nil {
		log.Printf("Error creating temporary directory: %v", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// Declare and initialize the 'urls' map
	urls := make(map[string]bool)

	var wg sync.WaitGroup

	// Run waybackurls
	wg.Add(1)
	go func() {
		defer wg.Done()
		waybackFilePath := filepath.Join(tempDir, "wayback.txt")
		waybackCmd := exec.Command("waybackurls", domainName)
		waybackOutput, err := waybackCmd.Output()
		if err != nil {
			log.Printf("Error running waybackurls for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(waybackFilePath, waybackOutput, 0644)
		if err != nil {
			log.Printf("Error writing wayback output file: %v", err)
			return
		}
		fmt.Printf("Success: waybackurls output written to %s\n", waybackFilePath)
		addURLsFromFile(waybackFilePath, urls)
	}()

	// Run gau
	wg.Add(1)
	go func() {
		defer wg.Done()
		gauFilePath := filepath.Join(tempDir, "gau.txt")
		gauCmd := exec.Command("gau", domainName)
		gauOutput, err := gauCmd.Output()
		if err != nil {
			log.Printf("Error running gau for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(gauFilePath, gauOutput, 0644)
		if err != nil {
			log.Printf("Error writing gau output file: %v", err)
			return
		}
		fmt.Printf("Success: gau output written to %s\n", gauFilePath)
		addURLsFromFile(gauFilePath, urls)
	}()

	// Run katana
	wg.Add(1)
	go func() {
		defer wg.Done()
		katanaFilePath := filepath.Join(tempDir, "katana.txt")
		katanaCmd := exec.Command("katana", "-u", domain, "-d", "6", "-jc")
		var stdout, stderr bytes.Buffer
		katanaCmd.Stdout = &stdout
		katanaCmd.Stderr = &stderr

		if err := katanaCmd.Run(); err != nil {
			log.Printf("Error running katana for %s: %v\nStderr: %s", domainName, err, stderr.String())
			return
		}

		katanaOutput := stdout.Bytes()
		err := os.WriteFile(katanaFilePath, katanaOutput, 0644)
		if err != nil {
			log.Printf("Error writing katana output file: %v", err)
			return
		}
		fmt.Printf("Success: katana output written to %s\n", katanaFilePath)
		addURLsFromFile(katanaFilePath, urls)
	}()

	// Run hakrawler
	wg.Add(1)
	go func() {
		defer wg.Done()
		hakrawlerFilePath := filepath.Join(tempDir, "hakrawler.txt")
		hakrawlerCmd := exec.Command("hakrawler")
		hakrawlerCmd.Stdin = strings.NewReader(domain)
		hakrawlerOutput, err := hakrawlerCmd.Output()
		if err != nil {
			log.Printf("Error running hakrawler for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(hakrawlerFilePath, hakrawlerOutput, 0644)
		if err != nil {
			log.Printf("Error writing hakrawler output file: %v", err)
			return
		}
		fmt.Printf("Success: hakrawler output written to %s\n", hakrawlerFilePath)
		addURLsFromFile(hakrawlerFilePath, urls)
	}()

	// Wait for all tasks to complete
	wg.Wait()

	// Perform fuzzing scans
	urlsFile := filepath.Join(tempDir, "urls.txt")
	fuzzingFile, err := os.Create(urlsFile)
	if err != nil {
		log.Printf("Error creating URLs file: %v", err)
		return
	}
	for url := range urls {
		_, _ = fuzzingFile.WriteString(url + "\n")
	}
	_ = fuzzingFile.Close()

	// Declare and initialize the WaitGroup for Nuclei scans
	var wgNuclei sync.WaitGroup
	semaphoreNuclei := make(chan struct{}, len(templateNames))

	var wgHTML sync.WaitGroup
	semaphoreHTML := make(chan struct{}, len(templateNames))

	for _, templatePath := range templateNames {
		semaphoreNuclei <- struct{}{}
		wgNuclei.Add(1)

		go func(templatePath string) {
			defer wgNuclei.Done()
			defer func() { <-semaphoreNuclei }()
			if err := performNucleiScan(urlsFile, templatePath, domain); err != nil {
				log.Printf("Error performing Nuclei scan for %s with template %s: %v", domainName, templatePath, err)
			} else {
				fmt.Printf("Success: Nuclei scan completed for %s with template %s\n", domainName, templatePath)
			}
		}(templatePath)
		semaphoreHTML <- struct{}{}
		wgHTML.Add(1)

		go func(templatePath string) {
			defer wgHTML.Done()
			defer func() { <-semaphoreNuclei }()
			if err := generateHTMLReport(domain, strings.Fields(templatePath)); err != nil {
				log.Printf("Error Generate HTML for %s with template %s: %v", domainName, templatePath, err)
			} else {
				fmt.Printf("Success: HTML  completed for %s with template %s\n", domainName, templatePath)
			}
		}(templatePath)
	}

	wgNuclei.Wait()
	wgHTML.Wait()

	// Generate HTML report using Nuclei results
	if err := generateHTMLReport(domain, templateNames); err != nil {
		log.Printf("Error generating HTML report for %s: %v", domain, err)
	}
	// Find real IP address and save it to a file
	if err := findRealIPAddress(domain); err != nil {
		log.Printf("Error finding real IP address: %v", err)
	}

	// Request Shodan data for the real IP address
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

// Nuclei function
func performNucleiScan(urlsFile, templatePath, domain string) error {
	templateName := filepath.Base(templatePath)
	outputFile := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templateName)

	nucleiCmd := exec.Command("sh", "-c", fmt.Sprintf("nuclei -l %s -t %s -o %s", urlsFile, templatePath, outputFile))
	nucleiCmd.Stdout = os.Stdout
	nucleiCmd.Stderr = os.Stderr

	if err := nucleiCmd.Run(); err != nil {
		return err
	}

	return nil
}
func addURLsFromFile(filePath string, urls map[string]bool) {
	// Open the file and create a scanner.
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	// Iterate over the lines in the file.
	for scanner.Scan() {
		// Get the URL from the current line.
		url := scanner.Text()

		// Check if the URL contains a protocol.
		if !strings.Contains(url, "://") {
			// If not, prepend the `https://` protocol.
			url = "https://" + url
		}

		// Add the URL to the map.
		urls[url] = true
	}

	// Check for errors reading the file.
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}
}

// Generate HTML Function
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
    /* Add your custom CSS styles here */
    %s
  </style>
  <script>
    // Add your custom JavaScript here
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

	// Load CSS and JavaScript files
	cssContent, err := loadFileContents("styles.css") // Load your custom CSS file
	if err != nil {
		return err
	}
	jsContent, err := loadFileContents("script.js") // Load your custom JavaScript file
	if err != nil {
		return err
	}

	var sections []string
	for i, templatePath := range templateNames {
		sectionID := fmt.Sprintf("template%d", i+1)
		sectionTitle := fmt.Sprintf("Template %d Results:", i+1)

		outputFilePath := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templatePath)
		output, err := readOutputFile(outputFilePath)
		if err != nil {
			return err
		}

		// Escape HTML characters in the output
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
