package httpsig

import (
	"fmt"
	"net/http"
	"strings"
)

// coveredComponents returns the ordered list of component IDs this
// implementation always covers for a WIMSE request signature.
// @authority is intentionally excluded (draft-ietf-wimse-http-signature §4.1)
// to tolerate TLS-terminating proxies.
func coveredComponents(r *http.Request) []string {
	comps := []string{"@method", "@path", "@query", "workload-identity-token"}
	if r.Header.Get("Content-Digest") != "" {
		comps = append(comps, "content-digest")
	}
	return comps
}

// componentValue returns the value to include in the signature base for the
// given component ID, or an error if the component cannot be derived.
func componentValue(id string, r *http.Request) (string, error) {
	switch id {
	case "@method":
		return r.Method, nil
	case "@path":
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@query":
		q := r.URL.RawQuery
		if q == "" {
			return "?", nil
		}
		return "?" + q, nil
	default:
		// Treat as a lowercase header name.
		v := r.Header.Get(http.CanonicalHeaderKey(id))
		if v == "" {
			return "", fmt.Errorf("missing header %q in request", id)
		}
		return strings.TrimSpace(v), nil
	}
}

// sigParamsLine constructs the @signature-params value string:
//
//	("comp1" "comp2" ...);created=T;expires=T;nonce="N";tag="...";wimse-aud="..."
func sigParamsLine(comps []string, p sigParams) string {
	var sb strings.Builder
	sb.WriteByte('(')
	for i, c := range comps {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte('"')
		sb.WriteString(c)
		sb.WriteByte('"')
	}
	sb.WriteByte(')')
	fmt.Fprintf(&sb, ";created=%d;expires=%d", p.created, p.expires)
	fmt.Fprintf(&sb, `;nonce=%q`, p.nonce)
	fmt.Fprintf(&sb, `;tag=%q`, wimseTag)
	fmt.Fprintf(&sb, `;wimse-aud=%q`, p.aud)
	return sb.String()
}

// buildSignatureBase constructs the RFC 9421 signature base string.
func buildSignatureBase(r *http.Request, comps []string, p sigParams) (string, error) {
	var sb strings.Builder
	for _, id := range comps {
		v, err := componentValue(id, r)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "%q: %s\n", id, v)
	}
	fmt.Fprintf(&sb, "%q: %s", "@signature-params", sigParamsLine(comps, p))
	return sb.String(), nil
}

type sigParams struct {
	created int64
	expires int64
	nonce   string
	aud     string
}
