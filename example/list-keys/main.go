/* main.go - list-keys example for the gpgme.go library
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
)

func main() {

	var searchFor string
	switch len(os.Args) {
	case 1:
		searchFor = ""
	case 2:
		searchFor = os.Args[1]
	default:
		fmt.Println("Usage: list-keys [<search-string>|-h]")
		os.Exit(1)
	}
	if searchFor == "-h" || searchFor == "--help" {
		fmt.Println("Usage: list-keys [<search-string>|-h]")
		fmt.Println("List all keys in the keyring, optionally filtered by a search string.")
		fmt.Println("Only the fingerprints and user IDs of the keys are printed.")
		os.Exit(0)
	}

	keys, err := gpggohigh.KeyList(searchFor)
	if err != nil {
		fmt.Printf("KeyList failed: %v\n", err)
		return
	}

	for _, k := range keys {
		fmt.Printf("Fingerprint: %s\n", k.Fingerprint)
		if k.HasUserIDs {
			for _, u := range k.UserIDs {
				fmt.Printf("  %s\n", u.UserID)
			}
		}
	}
}

// EOF
