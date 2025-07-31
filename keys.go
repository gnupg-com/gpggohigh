/* keys.go - high-level key handling for the gpgme.go library
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

// This is planned to become a high level interface to the gpgme library,
// without the need to know the gpgme library itself.

package gpggohigh

import "C"
import (
	"fmt"
	"slices"
	"time"

	"github.com/kulbartsch/gpgme"
)

/* mapping types from gpgme.go to gpggohigh.go would need lots
   of mapping, just to hide the gpgme.go library which is
   needed anyway. So, we just use the gpgme.go types directly.
   I case we change our mind later, we can still add the
   mapping like this:

type ValidityType gpgme.Validity

const (
	ValidityUnknown   = ValidityType(gpgme.ValidityUnknown)
	ValidityUndefined = ValidityType(gpgme.ValidityUndefined)
	ValidityNever     = ValidityType(gpgme.ValidityNever)
	ValidityMarginal  = ValidityType(gpgme.ValidityMarginal)
	ValidityFull      = ValidityType(gpgme.ValidityFull)
	ValidityUltimate  = ValidityType(gpgme.ValidityUltimate)
)
*/

type KeyType struct {
	Fingerprint     string
	CanAuthenticate bool
	CanCertify      bool
	CanEncrypt      bool
	CanSign         bool
	ChainID         string
	Disabled        bool
	Expired         bool
	HasUserIDs      bool
	Invalid         bool
	IsQualified     bool
	IssuerName      string
	IssuerSerial    string
	KeyListMode     gpgme.KeyListMode
	OwnerTrust      gpgme.Validity
	Protocol        gpgme.Protocol
	// Release
	Revoked bool
	Secret  bool
	// SubKeys *SubKey
	UserIDs []KeyUserIDsType
}

// KeyUserIDs is a structure for each user ID (UID) of a key.
type KeyUserIDsType struct {
	UserID        string
	Name          string
	Invalid       bool
	Revoked       bool
	Validity      gpgme.Validity
	Address       string
	HasSignatures bool
	Signatures    KeyUidSignaturesType
}

// KeyUidIssuerSignatureType is a structure for each signature of
// a user ID (UID) of a key.
type KeyUidIssuerSignatureType struct {
	CreationTime   time.Time
	ExpirationTime time.Time
	Expires        bool
	IssuerKeyID    string
	Revoked        bool
	Expired        bool
	Invalid        bool
	Exportable     bool
	UID            string
	Name           string
	Email          string
	Comment        string
	TrustScope     string
	HasNotations   bool
	// Notations []NotationType
}

// KeyUidSignaturesType is a map for each issuers KeyID with
// a slice of KeyUidIssuerSignatureType for each signature of the issuer.
type KeyUidSignaturesType map[string][]KeyUidIssuerSignatureType

// KeyList returns a list of keys that match the lookFor string.
func KeyList(lookFor string) (keys []KeyType, err error) {

	ctx, err := gpgme.New()
	if err != nil {
		return nil, fmt.Errorf("KeyList -Create context failed - %w", err)
	}
	defer ctx.Release()

	err = ctx.SetKeyListMode(gpgme.KeyListModeLocal | gpgme.KeyListModeSigs |
		gpgme.KeyListModeSigNotations)
	if err != nil {
		return nil, fmt.Errorf("KeyList -SetKeyListMode failed - %w", err)
	}

	if err := ctx.KeyListStart(lookFor, false); err != nil {
		return nil, fmt.Errorf("KeyList -SetKeyListStart failed - %w", err)
	}
	defer func() { _ = ctx.KeyListEnd() }()

	for ctx.KeyListNext() {
		keys = append(keys, fillKey(ctx.Key))
	}
	if ctx.KeyError != nil {
		return keys, fmt.Errorf("KeyList -KeyListNext failed - %w", ctx.KeyError)
	}
	return keys, nil
}

//// Key Information

func fillKey(k *gpgme.Key) (key KeyType) {

	key.Fingerprint = k.Fingerprint()
	key.CanAuthenticate = k.CanAuthenticate()
	key.CanCertify = k.CanCertify()
	key.CanEncrypt = k.CanEncrypt()
	key.CanSign = k.CanSign()
	key.ChainID = k.ChainID()
	key.Disabled = k.Disabled()
	key.Expired = k.Expired()
	key.HasUserIDs = k.HasUserIDs()
	key.Invalid = k.Invalid()
	key.IsQualified = k.IsQualified()
	key.IssuerName = k.IssuerName()
	key.IssuerSerial = k.IssuerSerial()
	key.KeyListMode = k.KeyListMode()
	key.OwnerTrust = k.OwnerTrust()
	key.Protocol = k.Protocol()
	// key.// Release  = kRelease()
	key.Revoked = k.Revoked()
	key.Secret = k.Secret()
	// key.// SubKeys *SubKey  //TODO: implement SubKey

	//key.UserIDs []KeyUserIDsType
	if key.HasUserIDs {
		key.UserIDs = fillUserIDs(k.UserIDs())
	} else {
		key.UserIDs = nil
	}

	return key
}

func fillUserIDs(uid *gpgme.UserID) (uids []KeyUserIDsType) {

	for uid != nil {
		var oneUid KeyUserIDsType
		oneUid.UserID = uid.UID()
		oneUid.Name = uid.Name()
		oneUid.Invalid = uid.Invalid()
		oneUid.Revoked = uid.Revoked()
		oneUid.Validity = uid.Validity()
		oneUid.Address = uid.Address()
		oneUid.HasSignatures = uid.HasSig()
		if oneUid.HasSignatures {
			oneUid.Signatures = fillUidSignatures(uid)
		} else {
			oneUid.Signatures = nil
		}
		uids = append(uids, oneUid)
		uid = uid.Next()
	}
	return
}

//// Key Signatures

// fillUidSignatures returns a map of issuers with a slice of their signatures.
// The signatures are sorted reversed by creation time, so the most recent one
// is the first in the slice.
func fillUidSignatures(uid *gpgme.UserID) (sigs KeyUidSignaturesType) {

	sigs = make(KeyUidSignaturesType)

	for sig := uid.Signatures(); sig != nil; sig = sig.Next() {
		var oneSig KeyUidIssuerSignatureType
		keyID := sig.KeyID()

		oneSig.Revoked = sig.Revoked()
		oneSig.Expired = sig.Expired()
		oneSig.IssuerKeyID = keyID
		oneSig.Invalid = sig.Invalid()
		oneSig.Exportable = sig.Exportable()
		oneSig.CreationTime = sig.Created()
		oneSig.ExpirationTime = sig.Expires()
		oneSig.Expires = sig.DoesExpire()
		oneSig.UID = sig.UID()
		oneSig.Name = sig.Name()
		oneSig.Email = sig.Email()
		oneSig.Comment = sig.Comment()
		oneSig.TrustScope = sig.TrustScope()
		oneSig.HasNotations = sig.HasNotation()
		// TODO: add notations ...

		sigs[keyID] = append(sigs[keyID], oneSig)
	}
	// sort signatures by creation time in reverse order
	for _, s := range sigs {
		slices.SortFunc(s, func(a, b KeyUidIssuerSignatureType) int {
			// b is compared to a and not the other way round, so the
			// most recent signature is the first in the slice.
			return b.CreationTime.Compare(a.CreationTime)
		})
	}

	return
}

//// Tools

func GnuPGValidity2String(v gpgme.Validity) string {
	switch v {
	case gpgme.ValidityUnknown:
		return "unknown"
	case gpgme.ValidityUndefined:
		return "undefined"
	case gpgme.ValidityNever:
		return "never"
	case gpgme.ValidityMarginal:
		return "marginal"
	case gpgme.ValidityFull:
		return "full"
	case gpgme.ValidityUltimate:
		return "ultimate"
	}
	return "unknown"
}

// EOF
