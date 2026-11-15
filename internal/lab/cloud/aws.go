package cloud

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AWS is a tiny client for STS, IAM and DynamoDB against a single endpoint
// (Floci listens on :4566 for every service, like the real "edge" pattern).
type AWS struct {
	Endpoint string // e.g. http://floci-aws:4566
	Region   string
	Static   Creds // bootstrap credentials (Floci accepts test/test)
	HTTP     *http.Client
}

// AWSFromEnv reads AWS_ENDPOINT_URL, AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
func AWSFromEnv() *AWS {
	return &AWS{
		Endpoint: strings.TrimRight(envOr("AWS_ENDPOINT_URL", "http://floci-aws:4566"), "/"),
		Region:   envOr("AWS_REGION", "us-east-1"),
		Static:   Creds{AccessKeyID: envOr("AWS_ACCESS_KEY_ID", "test"), SecretAccessKey: envOr("AWS_SECRET_ACCESS_KEY", "test")},
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Host returns host:port of the endpoint (used to pin presigned URLs).
func (a *AWS) Host() string {
	u, _ := url.Parse(a.Endpoint)
	return u.Host
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
}

// AssumeRole calls sts:AssumeRole with the static credentials.
func (a *AWS) AssumeRole(roleARN, session string) (Creds, string, error) {
	form := url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {roleARN},
		"RoleSessionName": {session}, "DurationSeconds": {"900"}}
	var out struct {
		Creds stsCredentials `xml:"AssumeRoleResult>Credentials"`
		Arn   string         `xml:"AssumeRoleResult>AssumedRoleUser>Arn"`
	}
	if err := a.query("sts", form, &a.Static, &out); err != nil {
		return Creds{}, "", err
	}
	return Creds(out.Creds), out.Arn, nil
}

// AssumeRoleWithWebIdentity exchanges an OIDC JWT for temporary credentials.
// The call is unsigned – the web identity token is the credential.
func (a *AWS) AssumeRoleWithWebIdentity(roleARN, session, token string) (Creds, string, error) {
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {roleARN},
		"RoleSessionName": {session}, "WebIdentityToken": {token}, "DurationSeconds": {"900"}}
	var out struct {
		Creds stsCredentials `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
		Arn   string         `xml:"AssumeRoleWithWebIdentityResult>AssumedRoleUser>Arn"`
	}
	if err := a.query("sts", form, nil, &out); err != nil {
		return Creds{}, "", err
	}
	return Creds(out.Creds), out.Arn, nil
}

// PresignGetCallerIdentity returns a presigned sts:GetCallerIdentity URL. Handing
// it to an issuer proves who we are without revealing our secret key (the same
// pattern Vault's AWS auth method and SPIRE-like attestors use).
func (a *AWS) PresignGetCallerIdentity(c Creds) (string, error) {
	return Presign("GET", a.Endpoint+"/?Action=GetCallerIdentity&Version=2011-06-15", c, a.Region, "sts",
		time.Now(), time.Minute, false)
}

// CallerIdentityARN executes a presigned GetCallerIdentity URL and returns the ARN.
func CallerIdentityARN(client *http.Client, presigned string) (string, error) {
	resp, err := client.Get(presigned)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GetCallerIdentity %d: %s", resp.StatusCode, snippet(body))
	}
	var out struct {
		Arn string `xml:"GetCallerIdentityResult>Arn"`
	}
	if err := xml.Unmarshal(body, &out); err != nil || out.Arn == "" {
		// Some emulators answer JSON.
		var j struct {
			Arn string `json:"Arn"`
		}
		if json.Unmarshal(body, &j) == nil && j.Arn != "" {
			return j.Arn, nil
		}
		return "", fmt.Errorf("no Arn in GetCallerIdentity response: %s", snippet(body))
	}
	return out.Arn, nil
}

// RoleNameFromARN extracts the role name from an assumed-role or role ARN.
func RoleNameFromARN(arn string) (string, bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return "", false
	}
	res := strings.Split(parts[5], "/")
	switch {
	case res[0] == "assumed-role" && len(res) >= 2:
		return res[1], true
	case res[0] == "role" && len(res) >= 2:
		return res[len(res)-1], true
	}
	return "", false
}

// CreateRole creates an IAM role (idempotent: "already exists" is ignored).
func (a *AWS) CreateRole(name, trustPolicy string) error {
	form := url.Values{"Action": {"CreateRole"}, "Version": {"2010-05-08"}, "RoleName": {name},
		"AssumeRolePolicyDocument": {trustPolicy}}
	return ignoreExists(a.query("iam", form, &a.Static, nil))
}

// CreateOIDCProvider registers an issuer as an IAM OIDC identity provider.
func (a *AWS) CreateOIDCProvider(issuerURL, clientID string) error {
	form := url.Values{"Action": {"CreateOpenIDConnectProvider"}, "Version": {"2010-05-08"}, "Url": {issuerURL},
		"ClientIDList.member.1": {clientID}, "ThumbprintList.member.1": {strings.Repeat("0", 40)}}
	return ignoreExists(a.query("iam", form, &a.Static, nil))
}

// DynamoCreateTable creates a table with a string hash key (idempotent).
func (a *AWS) DynamoCreateTable(table, hashKey string) error {
	return ignoreExists(a.dynamo("CreateTable", map[string]any{
		"TableName":            table,
		"AttributeDefinitions": []map[string]string{{"AttributeName": hashKey, "AttributeType": "S"}},
		"KeySchema":            []map[string]string{{"AttributeName": hashKey, "KeyType": "HASH"}},
		"BillingMode":          "PAY_PER_REQUEST",
	}, a.Static, nil))
}

// DynamoPutItem writes string attributes with the given (temporary) credentials.
func (a *AWS) DynamoPutItem(c Creds, table string, item map[string]string) error {
	attrs := map[string]map[string]string{}
	for k, v := range item {
		attrs[k] = map[string]string{"S": v}
	}
	return a.dynamo("PutItem", map[string]any{"TableName": table, "Item": attrs}, c, nil)
}

func (a *AWS) dynamo(op string, in map[string]any, c Creds, out any) error {
	body, _ := json.Marshal(in)
	req, _ := http.NewRequest("POST", a.Endpoint+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810."+op)
	SignRequest(req, body, c, a.Region, "dynamodb", time.Now())
	return a.do(req, func(b []byte) error {
		if out == nil {
			return nil
		}
		return json.Unmarshal(b, out)
	})
}

func (a *AWS) query(service string, form url.Values, c *Creds, out any) error {
	body := []byte(form.Encode())
	req, _ := http.NewRequest("POST", a.Endpoint+"/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if c != nil {
		SignRequest(req, body, *c, a.Region, service, time.Now())
	}
	return a.do(req, func(b []byte) error {
		if out == nil {
			return nil
		}
		return xml.Unmarshal(b, out)
	})
}

func (a *AWS) do(req *http.Request, decode func([]byte) error) error {
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %d: %s", req.Header.Get("X-Amz-Target")+req.URL.Path, resp.StatusCode, snippet(b))
	}
	if err := decode(b); err != nil {
		return fmt.Errorf("decode response: %w (%s)", err, snippet(b))
	}
	return nil
}

func ignoreExists(err error) error {
	if err != nil && (strings.Contains(err.Error(), "EntityAlreadyExists") ||
		strings.Contains(err.Error(), "ResourceInUseException") || strings.Contains(err.Error(), "already exists")) {
		return nil
	}
	return err
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
