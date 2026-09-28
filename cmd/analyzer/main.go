// Command analyzer runs local static detection over executable files.
//
// Usage:
//
//	analyzer -rules rules.json [flags] file [file...]
//
// It parses each executable into the unified model, evaluates one versioned
// rule set, and emits a deterministic JSON report. Parse failures are
// classified (truncated / corrupt / unknown / oversized), never fatal to the
// whole run.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
	"github.com/h3yow/binary-static-analyzer-go/internal/scan"
)

func main() {
	var (
		rulesPath  = flag.String("rules", "rules.json", "path to versioned JSON rule set")
		jobs       = flag.Int("jobs", 4, "maximum concurrent scans")
		maxSize    = flag.Int64("max-size", 256<<20, "reject targets larger than this many bytes")
		perTimeout = flag.Duration("per-target-timeout", 0, "deadline for one target (0 = none)")
		allTimeout = flag.Duration("overall-timeout", 0, "deadline for the whole run (0 = none)")
		noCache    = flag.Bool("no-cache", false, "disable verdict caching")
		pretty     = flag.Bool("pretty", false, "pretty-print JSON output")
	)
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "analyzer: at least one target file is required")
		flag.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyzer: load rules: %v\n", err)
		os.Exit(2)
	}
	set, err := rules.LoadSet(context.Background(), raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyzer: invalid rules: %v\n", err)
		os.Exit(2)
	}
	engine, err := rules.NewEngine(set)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyzer: compile rules: %v\n", err)
		os.Exit(2)
	}

	cfg := scan.Config{
		MaxConcurrency:   *jobs,
		MaxTargetSize:    *maxSize,
		PerTargetTimeout: scan.Duration(*perTimeout),
		OverallTimeout:   scan.Duration(*allTimeout),
		CacheEnabled:     !*noCache,
	}
	targets := make([]scan.Target, 0, flag.NArg())
	for _, name := range flag.Args() {
		targets = append(targets, scan.Target{Name: name})
	}

	scanner := scan.New(engine, cfg)
	report, callErr := scanner.Scan(context.Background(), targets)
	if report == nil {
		fmt.Fprintf(os.Stderr, "analyzer: %v\n", callErr)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "analyzer: encode report: %v\n", err)
		os.Exit(1)
	}
	if callErr != nil {
		// Report already emitted; signal the bounded run via exit status.
		os.Exit(3)
	}
	// Nonzero exit when any target has a finding (useful in pipelines), but
	// parse failures do not by themselves force a nonzero status.
	for _, r := range report.Results {
		if len(r.Findings) > 0 {
			os.Exit(10)
		}
	}
}
