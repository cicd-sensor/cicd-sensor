package main

import (
	"fmt"
	"os"

	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

const (
	defaultSocketPath                = "/run/cicd-sensor/agent.sock"
	defaultGitHubK8sRunnerSocketPath = "/run/cicd-sensor/github-k8s/runner.sock"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "--version", "-v":
		fmt.Fprintln(os.Stdout, version.Current)
	case "agent":
		runAgentSubcommand(os.Args[2:])
	case "host":
		runHostSubcommand(os.Args[2:])
	case "job":
		runJobSubcommand(os.Args[2:])
	case "project":
		runProjectSubcommand(os.Args[2:])
	case "proxy":
		runProxySubcommand(os.Args[2:])
	case "nri":
		runNRISubcommand(os.Args[2:])
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  cicd-sensor agent start [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor host start [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor host end [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor job health [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor project start [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor project result [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor proxy dockerd [flags]")
	fmt.Fprintln(os.Stderr, "  cicd-sensor nri [flags]")
}
