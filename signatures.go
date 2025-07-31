/* signatures.go - high-level signature handling for the gpgme.go library
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
	"fmt"
	"io"

	"github.com/kulbartsch/gpgme"
)

// SignBytes signs a memory buffer and returns a memory buffer with the signature.
//
//   - plainText: the data to be signed
//   - signWith: the key to sign with, can be a fingerprint or a user ID
//   - armored: if true, the output will be ASCII armored
//   - cipherText: the signed data, which may include the signature
//   - n: the number of bytes written to cipherText
//   - signingFingerPrints: a slice of fingerprints of the keys used for signing
//   - err: an error if the signing fails
func SignBytes(plainText []byte, signWith string, armored bool) (
	cipherText []byte, n int, signingFingerPrints []string, err error) {

	myContext, err := gpgme.New()
	if err != nil {
		err = fmt.Errorf("SignBytes - gpgme.New failed: %w", err)
		return
	}
	defer myContext.Release()

	err = myContext.SetProtocol(gpgme.ProtocolOpenPGP)
	if err != nil {
		err = fmt.Errorf("SignBytes - SetProtocol failed: %w", err)
		return
	}

	myContext.SetArmor(armored)

	dataIn, err := gpgme.NewDataBytes(plainText)
	if err != nil {
		err = fmt.Errorf("SignBytes - NewData (in) failed: %w", err)
		return
	}
	defer dataIn.Close()

	dataOut, err := gpgme.NewData()
	if err != nil {
		err = fmt.Errorf("SignBytes - NewData (out) failed: %w", err)
		return
	}
	defer dataOut.Close()

	var thisRecipients []*gpgme.Key
	keys, err := gpgme.FindKeys(signWith, true)
	if err != nil {
		err = fmt.Errorf("SignBytes - FindKeys (out) failed: %w", err)
		return
	}
	thisRecipients = append(thisRecipients, keys...)

	for _, key := range thisRecipients {
		signingFingerPrints = append(signingFingerPrints, key.Fingerprint())
	}

	err = myContext.Sign(thisRecipients, dataIn, dataOut, gpgme.SigModeNormal)
	if err != nil {
		err = fmt.Errorf("SignBytes - Encrypt failed: %w", err)
		return
	}

	// dt := dataOut.Identify() // debug
	// fmt.Printf("Identify: %s\n", DataTypeMapString[dt]) // debug
	err = dataOut.Rewind()
	if err != nil {
		err = fmt.Errorf("SignBytes - Rewind failed: %w", err)
		return
	}

	cipherTextPart := make([]byte, 10240) // , 10240)
	cipherText = make([]byte, 0)          // , 10240)
	// read cipher text in chunks and append to cipherText until io.EOF is reached
	for {
		n, err = dataOut.Read(cipherTextPart)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("SignBytes - Read failed: %w", err)
			return
		}
		cipherText = append(cipherText, cipherTextPart[:n]...)
		if err == io.EOF {
			break
		}
	}

	return
}

// VerifyBytes verifies a signature on a memory buffer and returns the verification result.
//
//   - cipherText: the signed data, which may include the signature
//   - plainText: the original data without the signature
//   - signatures: a slice of gpgme.Signature containing the verification results
//   - err: an error if the verification fails
func VerifyBytes(cipherText []byte) (plainText []byte, signatures []gpgme.SignatureType,
	filename string, err error) {

	myContext, err := gpgme.New()
	if err != nil {
		err = fmt.Errorf("VerifyBytes - gpgme.New failed: %w", err)
		return
	}
	defer myContext.Release()

	err = myContext.SetProtocol(gpgme.ProtocolOpenPGP)
	if err != nil {
		err = fmt.Errorf("VerifyBytes - SetProtocol failed: %w", err)
		return
	}

	dataIn, err := gpgme.NewDataBytes(cipherText)
	if err != nil {
		err = fmt.Errorf("VerifyBytes - NewData (in) failed: %w", err)
		return
	}
	defer dataIn.Close()

	dataOut, err := gpgme.NewData()
	if err != nil {
		err = fmt.Errorf("VerifyBytes - NewData (out) failed: %w", err)
		return
	}
	defer dataOut.Close()

	filename, signatures, err = myContext.Verify(dataIn, nil, dataOut)
	if err != nil {
		err = fmt.Errorf("VerifyBytes - Verify failed: %w", err)
		return
	}

	err = dataOut.Rewind()
	if err != nil {
		err = fmt.Errorf("VerifyBytes - Rewind failed: %w", err)
		return
	}

	var n int
	plainTextPart := make([]byte, 10240)
	for {
		n, err = dataOut.Read(plainTextPart)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("VerifyBytes - Read failed: %w", err)
			return
		}
		if n > 0 {
			plainText = append(plainText, plainTextPart[:n]...)
		}
		if err == io.EOF {
			break
		}
	}

	return
}

// TextArrayToBytes converts a slice of strings to a byte slice separated by newlines.
func TextArrayToBytes(text []string) []byte {
	var result []byte
	for _, line := range text {
		result = append(result, []byte(line+"\n")...)
	}
	return result
}

// BytesToTextArray converts a byte slice to a slice of strings split by newlines.
func BytesToTextArray(data []byte) []string {
	lines := make([]string, 0)
	currentLine := make([]byte, 0)

	for _, b := range data {
		if b == '\n' {
			lines = append(lines, string(currentLine))
			currentLine = make([]byte, 0)
		} else {
			currentLine = append(currentLine, b)
		}
	}

	if len(currentLine) > 0 {
		lines = append(lines, string(currentLine))
	}

	return lines
}

// EOF
