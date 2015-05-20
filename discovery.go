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
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gregjones/httpcache"
	"golang.org/x/oauth2"
)

// DiscoveryHandler takes care of recovering DiscoveryInformation with caching
type DiscoveryHandler struct {
	url    string
	client *http.Client
}

// DiscoveryInformation taken from the URL in a discovery handler
type DiscoveryInfo struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenAlgValuesSupported         []string `json:"id_token_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// NewDiscoveryHandler creates a new handler using the passed url, http transport and http cache
func NewDiscoveryHandler(URL string, transport http.RoundTripper, cache httpcache.Cache) *DiscoveryHandler {
	t := &httpcache.Transport{
		Cache:               cache,
		MarkCachedResponses: true,
		Transport:           transport,
	}

	return &DiscoveryHandler{
		url:    URL,
		client: t.Client(),
	}
}

func (h *DiscoveryHandler) Info() (*DiscoveryInfo, error) {
	resp, err := h.client.Get(h.url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info DiscoveryInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// JwsHandler creates a new JWS handler using information from discovery, fetching it if necessary
// The http client of the discovery handler is reused
func (h *DiscoveryHandler) JwsHandler() (*JwsHandler, error) {
	i, err := h.Info()
	if err != nil {
		return nil, err
	}

	return &JwsHandler{
		client: h.client,
		url:    i.JwksURI,
	}, nil
}

func (i *DiscoveryInfo) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  i.AuthorizationEndpoint,
		TokenURL: i.TokenEndpoint,
	}
}
