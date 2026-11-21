package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCP is a tiny REST client for IAM, STS (Workload Identity Federation) and
// Cloud KMS. Each API has its own base URL so it can point at floci-gcp
// (one port for everything) or at the real *.googleapis.com hosts.
type GCP struct {
	IAMURL  string // real: https://iam.googleapis.com
	STSURL  string // real: https://sts.googleapis.com
	KMSURL  string // real: https://cloudkms.googleapis.com
	Project string
	HTTP    *http.Client
}

// GCPFromEnv reads GCP_ENDPOINT_URL (default for all APIs), optional per-API
// overrides GCP_IAM_URL / GCP_STS_URL / GCP_KMS_URL, and GCP_PROJECT.
func GCPFromEnv() *GCP {
	base := strings.TrimRight(envOr("GCP_ENDPOINT_URL", "http://floci-gcp:4588"), "/")
	return &GCP{
		IAMURL:  strings.TrimRight(envOr("GCP_IAM_URL", base), "/"),
		STSURL:  strings.TrimRight(envOr("GCP_STS_URL", base), "/"),
		KMSURL:  strings.TrimRight(envOr("GCP_KMS_URL", base), "/"),
		Project: envOr("GCP_PROJECT", "wimse-lab"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// ServiceAccountEmail builds the email for an account id in this project.
func (g *GCP) ServiceAccountEmail(accountID string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", accountID, g.Project)
}

// CreateServiceAccount creates a service account (idempotent).
func (g *GCP) CreateServiceAccount(accountID, displayName string) error {
	err := g.json("POST", fmt.Sprintf("%s/v1/projects/%s/serviceAccounts", g.IAMURL, g.Project), "",
		map[string]any{"accountId": accountID, "serviceAccount": map[string]string{"displayName": displayName}}, nil)
	return ignoreExists(ignoreConflict(err))
}

// GetServiceAccount checks a service account exists and returns its unique id.
func (g *GCP) GetServiceAccount(email string) (string, error) {
	var out struct {
		Email    string `json:"email"`
		UniqueID string `json:"uniqueId"`
	}
	if err := g.json("GET", fmt.Sprintf("%s/v1/projects/%s/serviceAccounts/%s", g.IAMURL, g.Project, email), "", nil, &out); err != nil {
		return "", err
	}
	return out.UniqueID, nil
}

// STSExchange performs the Workload Identity Federation token exchange
// (RFC 8693) at Google STS: external JWT -> federated access token.
func (g *GCP) STSExchange(subjectToken, audience string) (string, error) {
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {audience},
		"scope":                {"https://www.googleapis.com/auth/cloud-platform"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {subjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
	}
	req, _ := http.NewRequest("POST", g.STSURL+"/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := g.do(req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("STS returned no access_token")
	}
	return out.AccessToken, nil
}

func (g *GCP) keyPath(ring, key string) string {
	return fmt.Sprintf("projects/%s/locations/global/keyRings/%s/cryptoKeys/%s", g.Project, ring, key)
}

// EnsureCryptoKey creates a key ring and symmetric key (idempotent).
func (g *GCP) EnsureCryptoKey(ring, key string) error {
	parent := fmt.Sprintf("%s/v1/projects/%s/locations/global", g.KMSURL, g.Project)
	if err := ignoreExists(ignoreConflict(g.json("POST", parent+"/keyRings?keyRingId="+ring, "", map[string]any{}, nil))); err != nil {
		return err
	}
	return ignoreExists(ignoreConflict(g.json("POST", fmt.Sprintf("%s/keyRings/%s/cryptoKeys?cryptoKeyId=%s", parent, ring, key), "",
		map[string]any{"purpose": "ENCRYPT_DECRYPT"}, nil)))
}

// Encrypt encrypts plaintext with Cloud KMS using a (federated) access token.
func (g *GCP) Encrypt(accessToken, ring, key string, plaintext []byte) (string, error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
	}
	err := g.json("POST", fmt.Sprintf("%s/v1/%s:encrypt", g.KMSURL, g.keyPath(ring, key)), accessToken,
		map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}, &out)
	return out.Ciphertext, err
}

func (g *GCP) json(method, u, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return g.do(req, out)
}

func (g *GCP) do(req *http.Request, out any) error {
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s -> %d: %s", req.Method, req.URL.Path, resp.StatusCode, snippet(b))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s: %w (%s)", req.URL.Path, err, snippet(b))
		}
	}
	return nil
}

func ignoreConflict(err error) error {
	if err != nil && (strings.Contains(err.Error(), "-> 409") || strings.Contains(err.Error(), "ALREADY_EXISTS")) {
		return nil
	}
	return err
}
