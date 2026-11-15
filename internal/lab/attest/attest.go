// Package attest decides which registered workload is asking an issuer for a
// WIT. The IdP in internal/idp issues a WIT for any requested subject (PoC
// mode); the lab issuer instead requires platform evidence, the way SPIRE
// node/workload attestors or Vault auth methods do.
//
// Attestors are combined with a plan string: "," separates alternatives and
// "+" requires all members of a group, e.g.
//
//	ATTESTORS=aws-sts,docker            # AWS STS proof, or else Docker labels
//	ATTESTORS=docker+gcp-iam,join-token # Docker labels AND GCP SA registered, or a join token
package attest

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab/cloud"
)

// Registration is the issuer-side record of a workload (like a SPIRE entry).
type Registration struct {
	Workload          string `json:"workload"`                      // name the workload claims
	ID                string `json:"id"`                            // workload identifier to put in WIT sub
	AWSRole           string `json:"aws_role,omitempty"`            // aws-sts selector
	DockerLabel       string `json:"docker_label,omitempty"`        // docker selector (label wimse.workload)
	GCPServiceAccount string `json:"gcp_service_account,omitempty"` // gcp-iam selector (account id)
	JoinToken         string `json:"join_token,omitempty"`          // join-token selector (dev only)
	EntryPoint        bool   `json:"entry_point,omitempty"`         // may request Txn-Tokens
}

// LoadRegistrations reads a JSON array of registrations.
func LoadRegistrations(path string) ([]Registration, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var regs []Registration
	if err := json.Unmarshal(b, &regs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return regs, nil
}

// Request is what an attestor can look at.
type Request struct {
	RemoteIP string
	Evidence []lab.Evidence
}

func (r Request) evidence(typ string) (lab.Evidence, bool) {
	for _, e := range r.Evidence {
		if e.Type == typ {
			return e, true
		}
	}
	return lab.Evidence{}, false
}

// Attestor verifies one kind of evidence against a registration.
type Attestor interface {
	Name() string
	Attest(ctx context.Context, req Request, reg Registration) (detail string, err error)
}

// Plan is an OR of AND-groups of attestors.
type Plan [][]Attestor

// ParsePlan builds a plan from a spec like "aws-sts,docker" using the given attestors.
func ParsePlan(spec string, available map[string]Attestor) (Plan, error) {
	var plan Plan
	for _, group := range strings.Split(spec, ",") {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		var g []Attestor
		for _, name := range strings.Split(group, "+") {
			a, ok := available[strings.TrimSpace(name)]
			if !ok {
				return nil, fmt.Errorf("unknown attestor %q", name)
			}
			g = append(g, a)
		}
		plan = append(plan, g)
	}
	if len(plan) == 0 {
		return nil, errors.New("no attestors configured")
	}
	return plan, nil
}

// Run tries each group in order; the first group whose attestors all pass wins.
func (p Plan) Run(ctx context.Context, req Request, reg Registration) (string, []lab.Check, bool) {
	var checks []lab.Check
	for _, group := range p {
		names := make([]string, len(group))
		passed := true
		for i, a := range group {
			names[i] = a.Name()
			detail, err := a.Attest(ctx, req, reg)
			if err != nil {
				checks = append(checks, lab.Check{Name: "attestor " + a.Name(), OK: false, Detail: err.Error()})
				passed = false
				break
			}
			checks = append(checks, lab.Check{Name: "attestor " + a.Name(), OK: true, Detail: detail})
		}
		if passed {
			return strings.Join(names, "+"), checks, true
		}
	}
	return "", checks, false
}

// ---- join-token (dev / no-Docker mode) ---------------------------------------------

// JoinToken compares a pre-shared token. Weak: use only for local process runs.
type JoinToken struct{}

func (JoinToken) Name() string { return "join-token" }

func (JoinToken) Attest(_ context.Context, req Request, reg Registration) (string, error) {
	ev, ok := req.evidence("join-token")
	if !ok {
		return "", errors.New("no join-token evidence presented")
	}
	if reg.JoinToken == "" || subtle.ConstantTimeCompare([]byte(ev.Data["token"]), []byte(reg.JoinToken)) != 1 {
		return "", errors.New("join token does not match the registration")
	}
	return "pre-shared join token matched (dev-only attestation)", nil
}

// ---- aws-sts ----------------------------------------------------------------------

// AWSSTS verifies a presigned sts:GetCallerIdentity URL by executing it
// against the (pinned) STS endpoint and matching the returned role.
type AWSSTS struct {
	AllowedHost string // only presigned URLs for this host:port are executed (SSRF guard)
	HTTP        *http.Client
}

func (a AWSSTS) Name() string { return "aws-sts" }

func (a AWSSTS) Attest(_ context.Context, req Request, reg Registration) (string, error) {
	if reg.AWSRole == "" {
		return "", errors.New("registration has no aws_role selector")
	}
	ev, ok := req.evidence("aws-sts")
	if !ok || ev.Data["url"] == "" {
		return "", errors.New("no presigned GetCallerIdentity URL presented")
	}
	u, err := url.Parse(ev.Data["url"])
	if err != nil {
		return "", err
	}
	q := u.Query()
	switch {
	case u.Host != a.AllowedHost:
		return "", fmt.Errorf("presigned URL host %q is not the pinned STS endpoint %q", u.Host, a.AllowedHost)
	case q.Get("Action") != "GetCallerIdentity":
		return "", fmt.Errorf("presigned URL action %q is not GetCallerIdentity", q.Get("Action"))
	case q.Get("X-Amz-Signature") == "":
		return "", errors.New("URL is not SigV4-presigned")
	}
	arn, err := cloud.CallerIdentityARN(a.HTTP, u.String())
	if err != nil {
		return "", err
	}
	role, ok := cloud.RoleNameFromARN(arn)
	if !ok || role != reg.AWSRole {
		return "", fmt.Errorf("STS says caller is %s, registration expects role %s", arn, reg.AWSRole)
	}
	return "STS GetCallerIdentity → " + arn, nil
}

// ---- docker -----------------------------------------------------------------------

// Docker identifies the calling container by its source IP through the Docker
// Engine API and matches its `wimse.workload` label – the same idea as
// SPIRE's docker workload attestor. Requires the Docker socket (lab only).
type Docker struct {
	Socket string // e.g. /var/run/docker.sock
}

func (d Docker) Name() string { return "docker" }

func (d Docker) Attest(ctx context.Context, req Request, reg Registration) (string, error) {
	if reg.DockerLabel == "" {
		return "", errors.New("registration has no docker_label selector")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", d.Socket)
		}}}
	hreq, _ := http.NewRequestWithContext(ctx, "GET", "http://docker/containers/json", nil)
	resp, err := client.Do(hreq)
	if err != nil {
		return "", fmt.Errorf("docker API: %w", err)
	}
	defer resp.Body.Close()
	var containers []struct {
		Names           []string          `json:"Names"`
		Image           string            `json:"Image"`
		Labels          map[string]string `json:"Labels"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return "", fmt.Errorf("docker API: %w", err)
	}
	for _, c := range containers {
		for netName, n := range c.NetworkSettings.Networks {
			if n.IPAddress != req.RemoteIP {
				continue
			}
			label := c.Labels["wimse.workload"]
			if label != reg.DockerLabel {
				return "", fmt.Errorf("caller %s is container %v with label wimse.workload=%q, registration expects %q",
					req.RemoteIP, c.Names, label, reg.DockerLabel)
			}
			return fmt.Sprintf("container %s (%s) on %s, label wimse.workload=%s", strings.Join(c.Names, ","),
				c.Image, netName, label), nil
		}
	}
	return "", fmt.Errorf("no container has source IP %s", req.RemoteIP)
}

// ---- gcp-iam ----------------------------------------------------------------------

// GCPIAM checks the registration's service account exists in the (emulated)
// GCP project. It is a registration consistency check, not cryptographic
// proof – pair it with docker ("docker+gcp-iam").
type GCPIAM struct {
	GCP *cloud.GCP
}

func (g GCPIAM) Name() string { return "gcp-iam" }

func (g GCPIAM) Attest(_ context.Context, _ Request, reg Registration) (string, error) {
	if reg.GCPServiceAccount == "" {
		return "", errors.New("registration has no gcp_service_account selector")
	}
	email := g.GCP.ServiceAccountEmail(reg.GCPServiceAccount)
	id, err := g.GCP.GetServiceAccount(email)
	if err != nil {
		return "", fmt.Errorf("service account %s not found in GCP: %w", email, err)
	}
	return fmt.Sprintf("GCP IAM service account %s exists (uniqueId=%s)", email, id), nil
}
