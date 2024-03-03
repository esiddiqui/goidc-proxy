package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/esiddiqui/goidc-proxy/types"
)

type OpenIdMetadata struct {
	types.AuthServerMetadata
	IdTokenSigningAlgorithmValuesSupported string `json:"id_token_signing_alg_values_supported" yaml:"id_token_signing_alg_values_supported"`
}

// ParseFromUrl fetches the authorization server metadata from the supplied metadata/well-know url
func NewFromMetadataUrl(url string) (*types.AuthServerMetadata, error) {
	req, _ := http.NewRequest("GET", url, bytes.NewReader([]byte("")))
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	metadata := &types.AuthServerMetadata{}
	err = json.Unmarshal(body, metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}
