package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

type reportIOOptions struct {
	outputFile string
	help       bool
}

func parseReportIOArgs(command string, args []string, stderr io.Writer, outputLabel string) (reportIOOptions, error) {
	var opts reportIOOptions
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: cicd-sensorctl %s [flags]\n", command)
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Input:")
		fmt.Fprintln(fs.Output(), "  Reads summary_log JSON from stdin.")
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Optional:")
		fmt.Fprintln(fs.Output(), "  --output-file FILE")
		fmt.Fprintf(fs.Output(), "        File to write %s to. Writes to stdout when empty.\n", outputLabel)
	}
	fs.StringVar(&opts.outputFile, "output-file", "", "File to write output to.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.help = true
			return opts, nil
		}
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, newUsageError(2, fmt.Sprintf("%s: too many arguments", command))
	}
	return opts, nil
}

func readReportInput(stdin io.Reader) ([]byte, error) {
	return io.ReadAll(stdin)
}

func writeReportOutput(opts reportIOOptions, body []byte, stdout io.Writer) error {
	if opts.outputFile == "" {
		_, err := stdout.Write(body)
		return err
	}
	return os.WriteFile(opts.outputFile, body, 0o644)
}
