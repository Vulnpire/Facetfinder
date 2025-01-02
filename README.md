# Facetfinder

is a lightweight Go-based tool designed for passive scanning of IPs, domains, and SSL certificates using Shodan's API. It leverages the AllOrigins proxy to query Shodan's web facets, fetches open ports and associated metadata, and ensures compliance with rate limits.

> **Note:** This script is featured in my article *Dive into Go: A Full Guide for Penetration Testers, Bounty Hunters, and Developers*. If you're interested in learning more about how this tool works, its development process, and practical applications, check out the [article](https://medium.com/@v1xtron/dive-into-go-a-full-guide-for-penetration-testers-bounty-hunters-and-developers-5cc013d3f5c6).

## Features

- Fetch IPs using Shodan facets with AllOrigins proxy.
- Passive port scanning using Shodan's host API.
- Supports SSL certificate queries (`ssl.cert.subject.cn`).
- Graceful shutdown on interrupts.
- Automatic removal of duplicate IPs.
- Shodan API rate-limit compliance.

## Usage

Usage: cat input | ./portscanner [options] <Shodan_API_Key>

Options:
  -ssl  Use SSL certificate search

## How It Works

    Shodan Facets Query:
    The tool queries Shodan facets (via AllOrigins proxy) to fetch unique IPs associated with the input domain or hostname.

    IP Scanning:
    For each IP, the tool fetches detailed information from Shodan's host API, including:
        Open ports
        Associated hostnames
        ASN (Autonomous System Number)

    Rate-Limit Handling:
    The tool respects Shodan's rate limit of 1 request per second to avoid being blocked.

