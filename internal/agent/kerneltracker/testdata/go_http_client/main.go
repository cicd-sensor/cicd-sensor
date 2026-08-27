package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: go_http_client (client|transport) URL [HOST]")
		os.Exit(2)
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // test server only
	}
	mode := os.Args[1]
	if mode != "client" && mode != "transport" {
		fmt.Fprintln(os.Stderr, "mode must be client or transport")
		os.Exit(2)
	}
	requestCount := 1
	if os.Getenv("GO_HTTP_TEST_BURST") == "1" {
		requestCount = 20
	}
	client := &http.Client{Transport: transport}
	for i := 0; i < requestCount; i++ {
		request, err := http.NewRequest(http.MethodGet, os.Args[2], nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(os.Args) == 4 {
			request.Host = os.Args[3]
		}
		var response *http.Response
		if mode == "client" {
			response, err = client.Do(request)
		} else {
			response, err = transport.RoundTrip(request)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = response.Body.Close()
		if i+1 < requestCount {
			time.Sleep(100 * time.Millisecond)
		}
	}
}
