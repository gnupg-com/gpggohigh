/* main.go - high-level functions for gpgme.go library
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

package gpggohigh

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime/debug"

	"github.com/kulbartsch/gpgme"
)

// --- general information ---

const (
	ExitFail    = 1 // exitFail is the exit code if the program fails.
	Program     = "gpggohigh"
	Description = "high-level functions for gpgme.go library"
	Copyright   = "Copyright: (C) 2025-2025 g10 Code GmbH"
	License     = "LPL-2.1 (GNU General Public License 3)"
	Source      = "https://github.com/gnupg-com/gpggohigh"
)

var Version = "na"

func getAuthors() []string {
	return []string{
		"Alexander Kulbartsch  2025-2025 - g10 Code GmbH",
	}
}

func ListAbout(verbose bool) (out []string) {
	out = append(out, Description)
	out = append(out, "Version  : "+Version)
	out = append(out, Copyright)
	if len(getAuthors()) > 0 {
		out = append(out, "Authors  :")
		for _, a := range getAuthors() {
			out = append(out, " - "+a)
		}
	}
	out = append(out, "License  : "+License)
	out = append(out, "Website  : "+Source)

	// ReadBuildInfo shows information provided by go's compiler,
	// which should be sufficient to reproduce the build. So no
	// variable user/system/time specific data is provided.
	if verbose {
		buildInfo, ok := debug.ReadBuildInfo()
		if !ok {
			out = append(out, "Build Info not available")
			return
		}
		out = append(out, "Build Info:")
		out = append(out, " - Go version          : "+buildInfo.GoVersion)
		out = append(out, " - Package path        : "+buildInfo.Path)
		// out = append(out, AboutModule(&buildInfo.Main, " - Module main")...)
		out = append(out, "Build Settings:")
		for _, kv := range buildInfo.Settings {
			out = append(out, " - "+kv.Key+" : "+kv.Value)
		}

		if len(buildInfo.Deps) == 0 {
			out = append(out, "No Dependency Modules")
			return
		}
		/* out = append(out, "Dependency Modules:")
		for _, m := range buildInfo.Deps {
			out = append(out, AboutModule(m, " - Module")...)
		} */

	}
	return
}

// --- general functions ---

// GpgEngineInfo makes a test connect to gpgme and displays GnuPG information.
// If show is true, the information is displayed.
func GpgEngineInfo() (engine, homedir, requiredVersion, version string, err error) {
	err = gpgme.EngineCheckVersion(gpgme.ProtocolOpenPGP)
	if err != nil {
		return "", "", "", "", fmt.Errorf("GetEngineInfo CheckVersion failed: %v", err)
	}
	myEngineInfo, err := gpgme.GetEngineInfo()
	if err != nil {
		return "", "", "", "", fmt.Errorf("GetEngineInfo failed: %v", err)
	}
	return myEngineInfo.FileName(), myEngineInfo.HomeDir(),
		myEngineInfo.RequiredVersion(), myEngineInfo.Version(),
		nil
}

// Identify a file
func IdentifyFile(filename string) (GDType gpgme.DataType, err error) {
	fh, err := os.Open(filename)
	if err != nil {
		return gpgme.TypeInvalid, fmt.Errorf("IdentifyFile - Open failed: %w", err)
	}
	defer fh.Close()
	dataIn, err := gpgme.NewDataFile(fh)
	if err != nil {
		return gpgme.TypeInvalid, fmt.Errorf("IdentifyFile - NewData (in) failed: %w", err)
	}
	defer dataIn.Close()

	return dataIn.Identify(), nil
}

var DataTypeMapString = map[gpgme.DataType]string{
	gpgme.TypeInvalid:      "invalid",
	gpgme.TypeUnknown:      "unknown",
	gpgme.TypePGPSigned:    "PGP-signed",
	gpgme.TypePGPEncrypted: "PGP-encrypted",
	gpgme.TypePGPSignature: "PGP-signature",
	gpgme.TypePGPOther:     "PGP-other",
	gpgme.TypePGPKey:       "PGP-key",
	gpgme.TypeCMSSigned:    "CMS-signed",
	gpgme.TypeCMSEncrypted: "CMS-encrypted",
	gpgme.TypeCMSOther:     "CMS-other",
	gpgme.TypeX509Cert:     "X509-cert",
	gpgme.TypePKCS12:       "PKCS12",
}

// --- Helper functions ---

// RandomString generates a string of chars and nums with length n.
// If n is less than 1, an empty string is returned.
// The character set is [a-z,A-Z,0-9] => 62 characters.
func RandomString(n int) string {
	if n < 1 {
		return ""
	}
	var charSet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	l := big.NewInt(int64(len(charSet)))
	for i := range s {
		r, err := rand.Int(rand.Reader, l)
		if err != nil { // Can't happen by definition of crypto/rand, just paranoia
			log.Fatalf("Can't generate random string: %v\n", err)
		}
		s[i] = charSet[int(r.Int64())]
	}
	return string(s)
}

// Bool2str returns "true" if b is true, otherwise "false".
func Bool2str(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// CondErrStr returns a given default value isNil or the error string.
// This is a ternary operator for strings.
func CondErrStr(e error, isNil string) string {
	if e == nil {
		return isNil
	}
	return e.Error()
}

// EOF
