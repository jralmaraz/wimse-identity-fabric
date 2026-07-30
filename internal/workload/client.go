package workload

import (
	"crypto/ecdsa"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/example/wimse-identity-fabric/pkg/wpt"
)

// Client wraps an mTLS http.Client and automatically attaches WIT+WPT on each request.
type Client struct {
	httpClient  *http.Client
	wit         string
	workloadKey *ecdsa.PrivateKey
}

// NewClient creates a workload HTTP client with the given TLS config, WIT, and signing key.
func NewClient(tlsConfig *tls.Config, witToken string, key *ecdsa.PrivateKey) *Client {
	transport := &http.Transport{}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		httpClient:  &http.Client{Transport: transport},
		wit:         witToken,
		workloadKey: key,
	}
}

// Get issues a GET request with WIT+WPT headers attached.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if err := c.attachHeaders(req, url); err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// Post issues a POST request with WIT+WPT headers attached.
func (c *Client) Post(url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.attachHeaders(req, url); err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// attachHeaders generates a fresh WPT and adds both WIMSE headers to the request.
func (c *Client) attachHeaders(req *http.Request, targetURL string) error {
	wptToken, err := wpt.Generate(wpt.GenerateOptions{
		TargetURI:   targetURL,
		WIT:         c.wit,
		WorkloadKey: c.workloadKey,
	})
	if err != nil {
		return err
	}
	req.Header.Set(HeaderWIT, c.wit)
	req.Header.Set(HeaderWPT, wptToken)
	return nil
}
