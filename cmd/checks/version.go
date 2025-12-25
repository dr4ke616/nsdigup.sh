package main

import (
	"flag"
	"fmt"
	"os"
)

// Version information (set via ldflags during build)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func DisplayVersionIfFlagged() {
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("checks version %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built: %s\n", BuildTime)
		os.Exit(0)
	}
}
