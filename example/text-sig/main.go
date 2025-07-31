/* main.go - text-sig example for the gpgme.go library
 * Copyright (C) 2025-2025 g10 Code GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-2.1-or-later
 */

 package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/gnupg-com/gpggohigh"
)

func main() {

	for i, a := range os.Args {
		fmt.Fprintf(os.Stderr, "os.Args[%d] = %s\n", i, a)
	}

	// check if there is exactly one argument
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: text-sig SIGNER < CLEAR_TEXT\n")
		os.Exit(1)
	}

	// read clear text from stdin
	clearText := make([]string, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		/* if line == "." {
			break // stop reading on line with just a dot
		} */
		clearText = append(clearText, line)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}
	if len(clearText) == 0 {
		fmt.Fprintf(os.Stderr, "No clear text provided. Please enter text to sign.\n")
		os.Exit(1)
	}

	clearTextBytes := gpggohigh.TextArrayToBytes(clearText)
	// fmt.Println("=== clear text ===")
	// fmt.Println(string(clearTextBytes))

	res, n, sigFP, err := gpggohigh.SignBytes(clearTextBytes, os.Args[1], true)
	switch err {
	case io.EOF:
		fmt.Fprintf(os.Stderr, "SignBytes read until EOF\n")
	case nil:
		fmt.Fprintf(os.Stderr, "SignBytes failed: %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "SignBytes no error\n")
	}
	if res == nil {
		fmt.Fprintf(os.Stderr, "SignBytes failed: res is nil\n")
		os.Exit(1)
	}

	// fmt.Fprintf(os.Stderr, "=== signed ===\n")
	fmt.Println(string(res))

	fmt.Fprintf(os.Stderr, "=== signing info ===\n")
	fmt.Fprintf(os.Stderr, "Read last %d bytes\n", n)
	fmt.Fprintf(os.Stderr, "Result %d bytes\n", len(res))
	fmt.Fprintf(os.Stderr, "Signature Fingerprint: %s\n", sigFP)
}

// EOF
