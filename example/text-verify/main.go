/* main.go - text-verify example for the gpgme.go library
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
	"github.com/kulbartsch/gpgme"
)

func main() {

	// check if there is exactly one argument
	if len(os.Args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: text-verify < SIGNED_TEXT\n")
		os.Exit(1)
	}

	// read signed text from stdin
	signedText := make([]string, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		/* if line == "." {
			break // stop reading on line with just a dot
		} */
		signedText = append(signedText, line)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}
	if len(signedText) == 0 {
		fmt.Fprintf(os.Stderr, "No signed text provided. Please enter text to verify.\n")
		os.Exit(1)
	}

	signedTextBytes := gpggohigh.TextArrayToBytes(signedText)

	plainText, signatures, filename, err := gpggohigh.VerifyBytes(signedTextBytes)
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "VerifyBytes failed: %v\n", err)
		os.Exit(1)
	}
	if plainText == nil {
		fmt.Fprintf(os.Stderr, "VerifyBytes failed: plainText is nil\n")
		os.Exit(1)
	}

	fmt.Println(string(plainText))

	fmt.Fprintf(os.Stderr, "=== verification info ===\n")
	fmt.Fprintf(os.Stderr, "Signatures found: %d\n", len(signatures))
	fmt.Fprintf(os.Stderr, "Filename        : %s\n", filename)
	var valResult string
	for i, sig := range signatures {
		if sig.Summary&gpgme.SigSumValid != 0 {
			valResult = "OK"
		} else {
			valResult = "NOT OK"
		}
		fmt.Fprintf(os.Stderr, "Signature[%d]: fingerprint=%s, summary=%d, status=%v Validity=%s\n",
			i, sig.Fingerprint, sig.Summary, sig.Status, valResult)
	}

	/*
		type Signature struct {
		Summary     SigSum
		Fingerprint string
		Status      error
		// TODO: notations
		Timestamp      time.Time
		ExpTimestamp   time.Time
		WrongKeyUsage  bool
		PKATrust       uint
		ChainModel     bool
		Validity       Validity
		ValidityReason error
		PubkeyAlgo     PubkeyAlgo
		HashAlgo       HashAlgo
	*/
}

// EOF
