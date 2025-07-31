/* main.go - encrypt-file example for the gpgme.go library
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
	"fmt"
	"os"

	"github.com/gnupg-com/gpggohigh"
	"github.com/kulbartsch/gpgme"
)

const actionEncrypt = false
const actionDecrypt = true

func main() {

	var dr gpgme.DecryptResultType
	var decFilename string
	var sigs []gpgme.SignatureType
	var err error

	// check if there ar least 2 arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: encrypt-file <encrypt|decrypt> <filename> <recipient1> [<recipient2> ...]")
		os.Exit(1)
	}

	// get the operation
	var op bool
	switch os.Args[1] {
	case "encrypt":
		op = actionEncrypt
	case "decrypt", "d":
		op = actionDecrypt
	default:
		fmt.Println("Usage: encrypt-file [encrypt <filename> <recipient1> [<recipient2> ...] | decrypt <filename>]")
		os.Exit(1)
	}

	// get the filename
	filename := os.Args[2]

	// get the recipients
	recipients := os.Args[3:]

	// encrypt the file
	if op == actionEncrypt {
		toFile := filename + ".gpg"
		err = gpggohigh.EncryptFile(filename, toFile, recipients, true)
	} else {
		dr, decFilename, sigs, err = gpggohigh.DecryptFile(filename, "")
	}
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if op == actionDecrypt {

		fmt.Println("== DECRYPT RESULT ==")
		fmt.Println("Unsupported algorithm: ", dr.UnsupportedAlgorithm)
		fmt.Println("Wrong key usage:       ", gpggohigh.Bool2str(dr.WrongKeyUsage))
		fmt.Println("Legacy cipher no MDC:  ", gpggohigh.Bool2str(dr.LegacyCipherNoMDC))
		fmt.Println("Is MIME:               ", gpggohigh.Bool2str(dr.IsMIME))
		fmt.Println("Is Restricted (DE VS): ", gpggohigh.Bool2str(dr.IsDEVS))
		fmt.Println("Beta compliance:       ", gpggohigh.Bool2str(dr.BetaCompliance))
		fmt.Println("File name:             ", dr.Filename)
		fmt.Println("Session key:           ", dr.SessionKey)
		fmt.Println("Symkey algo:           ", dr.SymkeyAlgo)
		for _, r := range dr.Recipients {
			fmt.Println("  - Recipient Key ID:  ", r.KeyID)
			fmt.Println("              Status:  ", gpggohigh.CondErrStr(r.Status, "(none)"))
			fmt.Println("         Pubkey algo:  ", r.PubkeyAlgo)
		}

		fmt.Println("== VERIFY RESULT ==")
		fmt.Println("Filename:   ", decFilename)
		for _, s := range sigs {
			fmt.Println("  - Fingerprint:       ", s.Fingerprint)
			fmt.Println("    Summary:           ", s.Summary)
			fmt.Println("    Status:            ", gpggohigh.CondErrStr(s.Status, "(none)"))
			fmt.Println("    Timestamp:         ", s.Timestamp)
			fmt.Println("    Expire timestamp:  ", s.ExpTimestamp)
			fmt.Println("    Wrong key usage:   ", gpggohigh.Bool2str(s.WrongKeyUsage))
			fmt.Println("    PKA trust:         ", s.PKATrust)
			fmt.Println("    Chain model:       ", gpggohigh.Bool2str(s.ChainModel))
			fmt.Println("    Validity:          ", s.Validity)
			fmt.Println("    Validity reason:   ", gpggohigh.CondErrStr(s.ValidityReason, "(none)"))
			fmt.Println("    Pubkey algo:       ", s.PubkeyAlgo)
			fmt.Println("    Hash algo:         ", s.HashAlgo)
		}

	}
}

// EOF
