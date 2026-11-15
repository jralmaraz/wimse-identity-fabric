// Package cloud holds minimal, dependency-free clients for the AWS and GCP
// APIs the lab uses. They target the Floci emulators by default
// (https://floci.io) but speak the real wire protocols, so they also work
// against real endpoints with real credentials.
package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Creds are AWS credentials (SessionToken is set for temporary credentials).
type Creds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

const (
	sigAlg        = "AWS4-HMAC-SHA256"
	amzDateFormat = "20060102T150405Z"
	emptySHA256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// SignRequest adds SigV4 Authorization (header signing) to req.
func SignRequest(req *http.Request, payload []byte, c Creds, region, service string, t time.Time) {
	t = t.UTC()
	amzDate := t.Format(amzDateFormat)
	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.Join(trimAll(vs), ",")
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	payloadHash := hexSHA256(payload)

	canonical := strings.Join([]string{req.Method, canonicalURI(req.URL), canonicalQuery(req.URL.Query()),
		canonHeaders.String(), signedHeaders, payloadHash}, "\n")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", t.Format("20060102"), region, service)
	sig := signature(c.SecretAccessKey, t, region, service, stringToSign(amzDate, scope, canonical))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigAlg, c.AccessKeyID, scope, signedHeaders, sig))
}

// Presign returns a SigV4 query-string presigned URL (only `host` is signed).
// unsignedPayload selects "UNSIGNED-PAYLOAD" (S3 style) instead of the empty-body hash.
func Presign(method, rawURL string, c Creds, region, service string, t time.Time, expires time.Duration,
	unsignedPayload bool) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	t = t.UTC()
	amzDate := t.Format(amzDateFormat)
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", t.Format("20060102"), region, service)
	q := u.Query()
	q.Set("X-Amz-Algorithm", sigAlg)
	q.Set("X-Amz-Credential", c.AccessKeyID+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", fmt.Sprint(int(expires.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")
	if c.SessionToken != "" {
		q.Set("X-Amz-Security-Token", c.SessionToken)
	}
	payloadHash := emptySHA256
	if unsignedPayload {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	canonical := strings.Join([]string{method, canonicalURI(u), canonicalQuery(q),
		"host:" + u.Host + "\n", "host", payloadHash}, "\n")
	sig := signature(c.SecretAccessKey, t, region, service, stringToSign(amzDate, scope, canonical))
	u.RawQuery = canonicalQuery(q) + "&X-Amz-Signature=" + sig
	return u.String(), nil
}

func stringToSign(amzDate, scope, canonical string) string {
	return strings.Join([]string{sigAlg, amzDate, scope, hexSHA256([]byte(canonical))}, "\n")
}

func signature(secret string, t time.Time, region, service, sts string) string {
	k := hmacSHA256([]byte("AWS4"+secret), t.Format("20060102"))
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	return hex.EncodeToString(hmacSHA256(k, sts))
}

func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEscape(k)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything except RFC 3986 unreserved characters.
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func trimAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strings.Join(strings.Fields(v), " ")
	}
	return out
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
