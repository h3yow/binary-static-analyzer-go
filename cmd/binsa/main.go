// Command binsa is the CLI for the local binary static analyzer.
//
// It parses one or more executable files, evaluates them against an optional
// versioned rule set, and emits a JSON report. Exit status:
//
//	0  every target parsed (findings may still be present)
//	1  one or more targets failed to parse or were rejected/terminated
//	2  usage/configuration error (bad flags, unreadable rule set/file list)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/h3yow/binary-static-analyzer-go/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("binsa", flag.ContinueOnError)
	rulesPath := fs.String("rules", "", "path to a versioned JSON rule set (optional: structure-only scan when omitted)")
	concurrency := fs.Int("concurrency", 4, "maximum number of concurrent target scans")
	maxFileMB := fs.Int64("max-file-mb", 256, "reject input files larger than this many MiB")
	maxTargets := fs.Int("max-targets", 10000, "reject batches with more than this many files")
	timeout := fs.Duration("timeout", 0, "per-target scan timeout, e.g. 5s (0 disables)")
	pretty := fs.Bool("pretty", false, "pretty-print the JSON report")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: binsa [flags] <file> [file...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fs.Usage()
		return 2
	}

	var ruleJSON []byte
	if *rulesPath != "" {
		b, err := os.ReadFile(*rulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "binsa: cannot read rules: %v\n", err)
			return 2
		}
		ruleJSON = b
	}

	s, err := scan.New(scan.Config{
		Concurrency: *concurrency,
		MaxFileSize: *maxFileMB << 20,
		MaxTargets:  *maxTargets,
		Timeout:     *timeout,
		Cache:       scan.NewMemoryCache(),
	}, ruleJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "binsa: %v\n", err)
		return 2
	}

	// Read every file up front; an unreadable file is a configuration-level
	// failure with exit code 2 rather than a parse verdict.
	targets := make([]scan.Target, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "binsa: cannot read %s: %v\n", p, err)
			return 2
		}
		targets = append(targets, scan.Target{Name: p, Data: b})
	}

	results := s.ScanBatch(context.Background(), targets)

	report := struct {
		RuleSetHash string        `json:"rule_set_hash,omitempty"`
		Results     []scan.Result `json:"results"`
	}{
		RuleSetHash: s.RuleSetHash(),
		Results:     results,
	}
	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "binsa: report encode failed: %v\n", err)
		return 2
	}

	for _, r := range results {
		if r.Status != scan.StatusOK {
			return 1
		}
	}
	return 0
}
