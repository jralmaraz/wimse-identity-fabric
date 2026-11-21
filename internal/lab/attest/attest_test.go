package attest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
)

var reg = Registration{Workload: "orders", ID: "spiffe://aws.wimse.local/ns/shop/sa/orders", AWSRole: "orders-task", JoinToken: "s3cret"}

func join(tok string) Request {
	return Request{Evidence: []lab.Evidence{{Type: "join-token", Data: map[string]string{"token": tok}}}}
}

type fixed struct {
	name string
	err  error
}

func (f fixed) Name() string { return f.name }
func (f fixed) Attest(context.Context, Request, Registration) (string, error) {
	return "ok", f.err
}

func TestPlanOrOfAnds(t *testing.T) {
	avail := map[string]Attestor{"pass": fixed{"pass", nil}, "fail": fixed{"fail", context.Canceled}, "join-token": JoinToken{}}
	cases := map[string]bool{"pass": true, "fail": false, "fail,pass": true, "pass+fail": false, "pass+fail,join-token": true}
	for spec, want := range cases {
		plan, err := ParsePlan(spec, avail)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := plan.Run(context.Background(), join("s3cret"), reg); ok != want {
			t.Errorf("%s: got %v want %v", spec, ok, want)
		}
	}
	if _, err := ParsePlan("nope", avail); err == nil {
		t.Error("unknown attestor accepted")
	}
}

func TestJoinToken(t *testing.T) {
	if _, err := (JoinToken{}).Attest(context.Background(), join("wrong"), reg); err == nil {
		t.Error("wrong token accepted")
	}
	if _, err := (JoinToken{}).Attest(context.Background(), join(""), Registration{}); err == nil {
		t.Error("empty registration token accepted")
	}
}

func TestAWSSTS(t *testing.T) {
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arn := "arn:aws:sts::000000000000:assumed-role/orders-task/orders"
		if strings.Contains(r.URL.RawQuery, "Credential=OTHER") {
			arn = "arn:aws:sts::000000000000:assumed-role/admin/x"
		}
		w.Write([]byte("<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>" + arn + "</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"))
	}))
	defer sts.Close()
	host := strings.TrimPrefix(sts.URL, "http://")
	a := AWSSTS{AllowedHost: host, HTTP: sts.Client()}
	ev := func(u string) Request {
		return Request{Evidence: []lab.Evidence{{Type: "aws-sts", Data: map[string]string{"url": u}}}}
	}
	ok := sts.URL + "/?Action=GetCallerIdentity&X-Amz-Credential=AK/x&X-Amz-Signature=abc"
	if _, err := a.Attest(context.Background(), ev(ok), reg); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	bad := map[string]string{
		"other role":   sts.URL + "/?Action=GetCallerIdentity&X-Amz-Credential=OTHER/x&X-Amz-Signature=abc",
		"ssrf host":    "http://169.254.169.254/?Action=GetCallerIdentity&X-Amz-Signature=abc",
		"other action": sts.URL + "/?Action=AssumeRole&X-Amz-Signature=abc",
		"unsigned":     sts.URL + "/?Action=GetCallerIdentity",
	}
	for name, u := range bad {
		if _, err := a.Attest(context.Background(), ev(u), reg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
