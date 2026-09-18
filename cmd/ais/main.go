package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/xBen-Harveyx/average-ip-scanner/internal/config"
	"github.com/xBen-Harveyx/average-ip-scanner/internal/run"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		// -h and -version are requests for information, not failures.
		var early *config.EarlyExit
		if errors.As(err, &early) {
			fmt.Fprint(os.Stdout, early.Output)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if err := run.Execute(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
