/* encrypt.go - high-level encryption handling for the gpgme.go library
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
	"os"

	"github.com/kulbartsch/gpgme"
)

// ModRecipient adds or changes recipients to an encrypted file.
// operation is the task to perform and should be one of EncryptAddRecp or
// EncryptChgRecp.
// filename is the file to modify.
// The encrypted file is saved with the extension `.gpg`.
// backupExtension is the extension for the backup of the original file.
// the backup extension is prefixed with some random characters to avoid
// possible conflicts with existing files.
// If backupExtension is empty, no backup is made.
// recipients is a slice of texts to select recipients.
func ModRecipients(operation gpgme.EncryptFlag, filename, backupExtension string,
	recipients []string) (err error) {

	// check the operation
	if operation != gpgme.EncryptAddRecp && operation != gpgme.EncryptChgRecp {
		return fmt.Errorf("ModRecipients - invalid operation: %v", operation)
	}

	// check the filename does exist and is a readable file
	fileStat, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("ModRecipients - file does not exist: %w", err)
	}
	if fileStat.IsDir() {
		return fmt.Errorf("ModRecipients - file is a directory: %w", err)
	}

	// prepare the gpgme context

	myContext, err := gpgme.New()
	if err != nil {
		return fmt.Errorf("ModRecipients - gpgme.New failed: %w", err)
	}
	defer myContext.Release()

	err = myContext.SetProtocol(gpgme.ProtocolOpenPGP)
	if err != nil {
		return fmt.Errorf("ModRecipients - SetProtocol failed: %w", err)
	}

	dataIn, err := gpgme.NewData()
	if err != nil {
		return fmt.Errorf("ModRecipients - NewData (in) failed: %w", err)
	}
	defer dataIn.Close()

	err = dataIn.SetFileName(filename)
	if err != nil {
		return fmt.Errorf("ModRecipients - SetFileName (in) failed: %w", err)
	}

	dataOut, err := gpgme.NewData()
	if err != nil {
		return fmt.Errorf("ModRecipients - NewData (out) failed: %w", err)
	}
	defer dataOut.Close()

	randomFilePart := "." + RandomString(8)
	// the random string collision probability is 1/62^8 = 4.58e-15
	outFilename := filename + randomFilePart + ".tmp"
	err = dataOut.SetFileName(outFilename)
	if err != nil {
		return fmt.Errorf("ModRecipients - SetFileName (out) failed: %w", err)
	}

	var thisRecipients []*gpgme.Key
	for _, r := range recipients {
		keys, err := gpgme.FindKeys(r, false)
		if err != nil {
			return fmt.Errorf("ModRecipients - FindKeys failed: %w", err)
		}
		thisRecipients = append(thisRecipients, keys...)
	}

	// do the recipient modification
	err = myContext.Encrypt(thisRecipients,
		operation|gpgme.EncryptFile,
		dataIn, dataOut)
	if err != nil {
		return fmt.Errorf("ModRecipients - Encrypt failed: %w", err)
	}

	// rename the files
	err = dataOut.Close()
	if err != nil {
		return fmt.Errorf("ModRecipients - Close (out) failed: %w", err)
	}
	err = dataIn.Close()
	if err != nil {
		return fmt.Errorf("ModRecipients - Close (in) failed: %w", err)
	}
	if backupExtension != "" {
		err = os.Rename(filename, filename+randomFilePart+backupExtension)
		if err != nil {
			return fmt.Errorf("ModRecipients - file rename (1) failed: %w", err)
		}
	} else { // no backup
		err = os.Remove(filename)
		if err != nil {
			return fmt.Errorf("ModRecipients - file remove failed: %w", err)
		}
	}
	err = os.Rename(outFilename, filename)
	if err != nil {
		return fmt.Errorf("ModRecipients - file rename (2) failed: %w", err)
	}

	return nil
}

// EncryptFile encrypts a file with the recipients.
// sourceFilename is the file to encrypt, it will not be deleted.
// destinationFilename is the file to save the encrypted file.
// If the destinationFilename is empty, the sourceFilename is used
// with an added `.gpg` extension.
// recipients is a slice of texts to select recipients.
// If sign is true to sign the file.
// The user to sign with should be configured in gpg.conf
func EncryptFile(sourceFilename, destinationFilename string,
	recipients []string, sign bool) (err error) {

	myContext, err := gpgme.New()
	if err != nil {
		return fmt.Errorf("EncryptFile - gpgme.New failed: %w", err)
	}
	defer myContext.Release()

	err = myContext.SetProtocol(gpgme.ProtocolOpenPGP)
	if err != nil {
		return fmt.Errorf("EncryptFile - SetProtocol failed: %w", err)
	}

	dataIn, err := gpgme.NewData()
	if err != nil {
		return fmt.Errorf("EncryptFile - NewData (in) failed: %w", err)
	}
	defer dataIn.Close()

	err = dataIn.SetFileName(sourceFilename)
	if err != nil {
		return fmt.Errorf("EncryptFile - SetFileName (in) failed: %w", err)
	}

	dataOut, err := gpgme.NewData()
	if err != nil {
		return fmt.Errorf("EncryptFile - NewData (out) failed: %w", err)
	}
	defer dataOut.Close()

	var destination string
	if destinationFilename == "" {
		destination = sourceFilename + ".gpg"
	} else {
		destination = destinationFilename
	}
	err = dataOut.SetFileName(destination)
	if err != nil {
		return fmt.Errorf("EncryptFile - SetFileName (out) failed: %w", err)
	}

	var thisRecipients []*gpgme.Key
	for _, r := range recipients {
		keys, err := gpgme.FindKeys(r, false)
		if err != nil {
			return fmt.Errorf("EncryptFile - FindKeys (out) failed: %w", err)
		}
		thisRecipients = append(thisRecipients, keys...)
	}

	if sign {
		err = myContext.EncryptSign(thisRecipients,
			gpgme.EncryptAlwaysTrust|gpgme.EncryptFile,
			dataIn, dataOut)
	} else {
		err = myContext.Encrypt(thisRecipients,
			gpgme.EncryptAlwaysTrust|gpgme.EncryptFile,
			dataIn, dataOut)
	}
	if err != nil {
		return fmt.Errorf("EncryptFile - Encrypt failed: %w", err)
	}
	return err

}

// DecryptFile decrypts the named in cypherFilename file to clearFilename.
// If clearFilename is empty, the decrypted file is saved with the
// extension `.gpg`, `.pgp` or `.asc` removed. If the file does not end with
// one of these extensions, an error is returned.
// If the cypherFilename does not exist, an error is returned.
// If the clearFilename exists, an error is returned.
func DecryptFile(cypherFilename, clearFilename string) (decryptionResult gpgme.DecryptResultType,
	filename string, signatures []gpgme.Signature, warning string, err error) {
	warning = ""
	err = nil

	fileStat, err := os.Stat(cypherFilename)
	if err != nil {
		err = fmt.Errorf("DecryptFile - file does not exist: %w", err)
		return
	}
	if fileStat.IsDir() {
		err = fmt.Errorf("DecryptFile - file is a directory: %w", err)
		return
	}

	myContext, err := gpgme.New()
	if err != nil {
		err = fmt.Errorf("DecryptFile - gpgme.New failed: %w", err)
		return
	}
	defer myContext.Release()

	err = myContext.SetProtocol(gpgme.ProtocolOpenPGP)
	if err != nil {
		err = fmt.Errorf("DecryptFile - SetProtocol failed: %w", err)
		return
	}

	dataIn, err := gpgme.NewData()
	if err != nil {
		err = fmt.Errorf("DecryptFile - NewData (in) failed: %w", err)
		return
	}
	defer dataIn.Close()

	err = dataIn.SetFileName(cypherFilename)
	if err != nil {
		err = fmt.Errorf("DecryptFile - SetFileName (in) failed: %w", err)
		return
	}

	dataOut, err := gpgme.NewData()
	if err != nil {
		err = fmt.Errorf("DecryptFile - NewData (out) failed: %w", err)
		return
	}
	defer dataOut.Close()

	var destination string
	if clearFilename == "" {
		// check if the cypherFilename has a `.gpg` extension
		if len(cypherFilename) > 4 && (cypherFilename[len(cypherFilename)-4:] == ".gpg" ||
			cypherFilename[len(cypherFilename)-4:] == ".pgp" ||
			cypherFilename[len(cypherFilename)-4:] == ".asc") {
			destination = cypherFilename[:len(cypherFilename)-4]
		} else {
			err = fmt.Errorf("DecryptFile - no destination filename given, and no `.gpg` or `.pgp` or `.asc` extension found")
			return
		}
	} else {
		destination = clearFilename
	}
	_, err = os.Stat(destination)
	if err == nil {
		err = fmt.Errorf("DecryptFile - destination file exists: %s", destination)
		return
	}

	err = dataOut.SetFileName(destination)
	if err != nil {
		err = fmt.Errorf("DecryptFile - SetFileName (out) failed: %w", err)
		return
	}

	err = myContext.DecryptVerify(dataIn, dataOut)
	if err != nil {
		// continue on "No data" error (but note it), end otherwise
		if err.Error() == "No data" {
			warning = "DecryptFile - DecryptVerify: no encrypted data"
		} else {
			err = fmt.Errorf("DecryptFile - DecryptVerify failed: %w", err)
			return
		}
	}

	decryptionResult, err = myContext.DecryptResult()
	if err != nil {
		err = fmt.Errorf("DecryptFile - DecryptResult failed: %w", err)
		return
	}
	// if dr == nil {
	//	return fmt.Errorf("DecryptFile - DecryptResult failed")
	// }

	filename, signatures, err = myContext.VerifyResult()
	if err != nil {
		err = fmt.Errorf("DecryptFile - VerifyResult failed: %w", err)
		return
	}

	return
}

// EOF
