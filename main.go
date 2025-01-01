package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ShodanResponse struct {
	Ports     []int    `json:"ports"`
	ASN       string   `json:"asn"`
	Hostnames []string `json:"hostnames"`
}

const (
	shodanRateLimit = time.Second // 1 request per second
)

// Fetch IPs using Shodan facets with AllOrigins proxy
func fetchIPsUsingFacets(query string) ([]string, error) {
	proxyURL := fmt.Sprintf("https://api.allorigins.win/get?url=%s", url.QueryEscape(fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", query)))
	resp, err := http.Get(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from Shodan facets via AllOrigins: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AllOrigins proxy API error (%d): %s", resp.StatusCode, string(body))
	}

	var proxyResponse struct {
		Contents string `json:"contents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&proxyResponse); err != nil {
		return nil, fmt.Errorf("failed to parse AllOrigins proxy response: %w", err)
	}

	re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
	matches := re.FindAllStringSubmatch(proxyResponse.Contents, -1)

	ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	var ips []string
	for _, match := range matches {
		if len(match) > 1 && ipRe.MatchString(match[1]) {
			ips = append(ips, match[1])
		}
	}

	return removeDuplicates(ips), nil
}

// Remove duplicate IPs
func removeDuplicates(ips []string) []string {
	uniqueIPs := make(map[string]struct{})
	for _, ip := range ips {
		uniqueIPs[ip] = struct{}{}
	}

	var dedupedIPs []string
	for ip := range uniqueIPs {
		dedupedIPs = append(dedupedIPs, ip)
	}
	return dedupedIPs
}

// Fetch Shodan data for an IP
func fetchShodanData(ipAddress, apiKey string) (*ShodanResponse, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ipAddress, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from Shodan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		delay, err := time.ParseDuration(retryAfter + "s")
		if err == nil {
			time.Sleep(delay)
			return fetchShodanData(ipAddress, apiKey)
		}
		return nil, errors.New("rate limit reached, retry later")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Shodan API error (%d): %s", resp.StatusCode, string(body))
	}

	var shodanResponse ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&shodanResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan response: %w", err)
	}

	return &shodanResponse, nil
}

// Helper function to build Shodan queries
func buildShodanQuery(domain, query, additionalQueries string, sslFlag bool) string {
	domainQuery := fmt.Sprintf("hostname:%s", url.QueryEscape(domain))
	if sslFlag {
		domainQuery = fmt.Sprintf("ssl.cert.subject.cn:\"%s\"", domain)
	}
	if query != "" {
		domainQuery = fmt.Sprintf("%s+%s", domainQuery, url.QueryEscape(query))
	}
	if additionalQueries != "" {
		domainQuery = fmt.Sprintf("%s+%s", domainQuery, additionalQueries)
	}
	return domainQuery
}

func main() {
	var sslFlag bool
	flag.BoolVar(&sslFlag, "ssl", false, "Use SSL certificate search")
	flag.Usage = func() {
		fmt.Println("Usage: cat input | ./portscanner [options] <Shodan_API_Key>")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Check for API key in environment variables
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" && flag.NArg() > 0 {
		apiKey = flag.Arg(0)
	}

	if apiKey == "" {
		fmt.Println("Error: Shodan API key not provided.")
		fmt.Println("Set it using the SHODAN_API_KEY environment variable or pass it as a command-line argument.")
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nGracefully shutting down...")
		cancel()
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	var wg sync.WaitGroup
	throttle := time.Tick(shodanRateLimit)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			query := buildShodanQuery(domain, "", "", sslFlag)

			ips, err := fetchIPsUsingFacets(query)
			if err != nil {
				log.Printf("Error fetching IPs for %s: %v\n", domain, err)
				return
			}

			for _, ip := range ips {
				<-throttle

				data, err := fetchShodanData(ip, apiKey)
				if err != nil {
					log.Printf("Error processing %s: %v\n", ip, err)
					continue
				}

				fmt.Printf("IP: %s\n", ip)
				fmt.Printf("Open Ports: %v\n", data.Ports)
				if len(data.Hostnames) > 0 {
					fmt.Printf("Hostnames: %s\n", strings.Join(data.Hostnames, ", "))
				}
				if data.ASN != "" {
					fmt.Printf("ASN: %s\n", data.ASN)
				}
				fmt.Println()
			}
		}(input)
	}

	wg.Wait()

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v\n", err)
	}
}
