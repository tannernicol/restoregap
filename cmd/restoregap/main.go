// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tannernicol/restoregap/internal/cli"
)

func main() {
	err := cli.Execute(os.Args[1:])
	if err == nil {
		return
	}
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Message != "" {
			fmt.Fprintln(os.Stderr, "error: "+exitErr.Message)
		}
		os.Exit(exitErr.Code)
	}
	// Contract: one-line human error on stderr, exit 2, never a stack trace.
	fmt.Fprintln(os.Stderr, "error: "+err.Error())
	os.Exit(2)
}
