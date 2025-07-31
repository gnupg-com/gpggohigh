/* main.go - add-recipient example for the gpgme.go library
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

func main() {

	// check if there ar least 2 arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: add-recipient <add|change> <filename> <recipient1> [<recipient2> ...]")
		os.Exit(1)
	}

	// get the operation
	var op gpgme.EncryptFlag
	switch os.Args[1] {
	case "add":
		op = gpgme.EncryptAddRecp
	case "change":
		op = gpgme.EncryptChgRecp
	default:
		fmt.Println("Usage: add-recipient <add|change> <filename> <recipient1> [<recipient2> ...]")
		os.Exit(1)
	}

	// get the filename
	filename := os.Args[2]

	// get the recipients
	recipients := os.Args[3:]

	// add the recipients
	err := gpggohigh.ModRecipients(op, filename, ".bak", recipients)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

}

// EOF
