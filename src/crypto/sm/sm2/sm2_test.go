// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"crypto/sm/sm3"
)

func TestSignVerify(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}

	hfunc := sha256.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
}

func TestKeyGeneration(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")
	priv, _ := GenerateKey(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testintestintestintestintestintestinggggggtesting")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf(" error signing: %s", err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf(" Verify failed")
	}

	//hashed[0] ^= 0xff
	hashed[0] = 0x53
	for i := 0; i < len(hashed); i++ {
		hashed[i] = byte(i)
	}
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

