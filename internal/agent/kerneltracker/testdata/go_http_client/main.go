package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
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
	request, err := http.NewRequest(http.MethodGet, os.Args[2], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(os.Args) == 4 {
		request.Host = os.Args[3]
	}
	var response *http.Response
	switch os.Args[1] {
	case "client":
		response, err = (&http.Client{Transport: transport}).Do(request)
	case "transport":
		response, err = transport.RoundTrip(request)
	default:
		fmt.Fprintln(os.Stderr, "mode must be client or transport")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = response.Body.Close()
}
