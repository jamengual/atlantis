// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// minSecretLength keeps short, guessable secrets out of the keyring.
const minSecretLength = 32

// ErrInvalidToken is returned for values that are malformed, were sealed
// with an unknown key or for another purpose, or have expired.
var ErrInvalidToken = errors.New("invalid or expired token")

// Keyring seals and opens small JSON values with AES-256-GCM. The first key
// seals; every key opens, so secrets can be rotated by adding the new one in
// front and removing the old one after the longest session has expired.
// Every replica must use the same secrets.
type Keyring struct {
	aeads []cipher.AEAD
}

// NewKeyring derives one AES-256 key from each secret.
func NewKeyring(secrets []string) (*Keyring, error) {
	if len(secrets) == 0 {
		return nil, errors.New("at least one session secret is required")
	}
	k := &Keyring{}
	for i, s := range secrets {
		if len(s) < minSecretLength {
			return nil, fmt.Errorf("session secret %d is %d characters; use at least %d random characters", i+1, len(s), minSecretLength)
		}
		key, err := hkdf.Key(sha256.New, []byte(s), nil, "atlantis web session v1", 32)
		if err != nil {
			return nil, fmt.Errorf("deriving session key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("creating GCM: %w", err)
		}
		k.aeads = append(k.aeads, aead)
	}
	return k, nil
}

// envelope wraps a sealed value with its expiry.
type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"d"`
}

// Seal encrypts v for the given purpose until exp. The purpose is bound as
// additional data, so a value sealed for one cookie cannot be replayed as
// another.
func (k *Keyring) Seal(purpose string, v any, exp time.Time) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("encoding token: %w", err)
	}
	plain, err := json.Marshal(envelope{Exp: exp.Unix(), Data: data})
	if err != nil {
		return "", fmt.Errorf("encoding token: %w", err)
	}
	aead := k.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("reading random nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value sealed for purpose into v. It returns
// ErrInvalidToken when no key opens it or it has expired at now.
func (k *Keyring) Open(purpose, token string, now time.Time, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidToken
	}
	for _, aead := range k.aeads {
		if len(raw) < aead.NonceSize() {
			return ErrInvalidToken
		}
		plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(purpose))
		if err != nil {
			continue
		}
		var env envelope
		if err := json.Unmarshal(plain, &env); err != nil {
			return ErrInvalidToken
		}
		if now.Unix() >= env.Exp {
			return ErrInvalidToken
		}
		if err := json.Unmarshal(env.Data, v); err != nil {
			return ErrInvalidToken
		}
		return nil
	}
	return ErrInvalidToken
}
