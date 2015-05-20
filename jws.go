/*
	Copyright 2015 Palm Stone Games, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package connect

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gregjones/httpcache"
	"golang.org/x/oauth2"
)

type JwsHandler struct {
	url    string
	client *http.Client
}

type JwsInfo struct {
	Keys []JwsKey `json:"keys"`
}

type JwsKey struct {
	Kty string
	Alg string
	Use string
	Kid string
	N   []byte
	E   []byte
}

const quote byte = byte('"')

func (k *JwsKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jwsKeyMarshal{
		Kty: k.Kty,
		Alg: k.Alg,
		Use: k.Use,
		Kid: k.Kid,
		N:   k.N,
		E:   k.E,
	})
}

func (k *JwsKey) UnmarshalJSON(raw []byte) error {
	var m jwsKeyMarshal
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}

	k.Kty = m.Kty
	k.Alg = m.Alg
	k.Use = m.Use
	k.Kid = m.Kid
	k.N = m.N
	k.E = m.E
	return nil
}

type encodedByteSlice []byte

// jwsKeyMarshal is a helper struct used for marshalling
type jwsKeyMarshal struct {
	Kty string           `json:"kty"`
	Alg string           `json:"alg"`
	Use string           `json:"use"`
	Kid string           `json:"kid"`
	N   encodedByteSlice `json:"n"`
	E   encodedByteSlice `json:"e"`
}

func (d *encodedByteSlice) MarshalJSON() ([]byte, error) {
	rawStr := jwt.EncodeSegment(*d)
	return json.Marshal(rawStr)
}

func (d *encodedByteSlice) UnmarshalJSON(raw []byte) error {
	var rawStr string
	var err error
	if err = json.Unmarshal(raw, &rawStr); err != nil {
		return err
	}

	*d, err = jwt.DecodeSegment(rawStr)
	return err
}

func NewJwsHandler(URL string, transport http.RoundTripper, cache httpcache.Cache) *JwsHandler {
	t := &httpcache.Transport{
		Cache:               cache,
		MarkCachedResponses: true,
		Transport:           transport,
	}

	return &JwsHandler{
		url:    URL,
		client: t.Client(),
	}
}

// KeyData returns the raw key information structure
// Usually, This method does not need to be called and Verify can be called directly
func (h *JwsHandler) Info() (*JwsInfo, error) {
	resp, err := h.client.Get(h.url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info JwsInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// Verify verifies the passed token and, if valid, returns a validated jwt.Token
// Which can then be used to fetch the claims and other data from it
// this is a cryptographic operation and only needs to be done once, after initial verification, a call to token.Valid() to ensure it isn't expired is enough
func (h *JwsHandler) Verify(token *oauth2.Token) (*jwt.Token, *rsa.PublicKey, error) {
	if !token.Valid() {
		return nil, nil, errors.New("Passed token is invalid")
	}

	// Grab the id token string from the oauth2 token object
	idTokenStr, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, errors.New("Token did not have a valid id token")
	}

	// Grab the jws key information
	info, err := h.Info()
	if err != nil {
		return nil, nil, fmt.Errorf("Error while getting jws key info: %v", err)
	}

	// Parse it
	var key *rsa.PublicKey
	idToken, err := jwt.Parse(idTokenStr, func(tok *jwt.Token) (interface{}, error) {
		kidRaw, ok := tok.Header["kid"]
		if !ok {
			return nil, errors.New("Token header did not contain a kid")
		}

		kid, ok := kidRaw.(string)
		if !ok {
			return nil, fmt.Errorf("Expected kid to be a string, but was %t", kidRaw)
		}

		for _, k := range info.Keys {
			if k.Kid == kid {
				key = &rsa.PublicKey{
					N: new(big.Int).SetBytes(k.N),
					E: int(new(big.Int).SetBytes(k.E).Int64()),
				}

				return key, nil
			}
		}

		return nil, errors.New("Key not found")
	})

	if err != nil {
		return nil, key, fmt.Errorf("Error while parsing JWT token: %v", err)
	}

	return idToken, key, nil
}
