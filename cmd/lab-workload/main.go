// lab-workload runs one of the three demo microservices of the local
// multi-cloud lab. Each one gets its identity from its own cloud's issuer and
// talks to the others with WIT + WPT (+ Txn-Token):
//
//	end user ─► orders (AWS) ──WIMSE──► payments (GCP) ──WIMSE──► ledger (AWS)
//	                │                       │                         │
//	           Txn-Token from          RFC 8693 → GCP STS        RFC 8693 → AWS STS
//	           issuer-aws              → Cloud KMS encrypt       → DynamoDB PutItem
//
// Configuration (env): ROLE (orders|payments|ledger), NAME, PORT, SELF_URL,
// ISSUER_URL, TRUST_DOMAINS, POLICY ("/path=id1,id2;/other=id3"), TXN_ISSUER,
// TXN_AUDIENCE, EVIDENCE (aws-sts,docker,join-token), JOIN_TOKEN, CLOUD
// (floci|off), PAYMENTS_URL, LEDGER_URL, AWS_ROLE_ARN, LEDGER_ROLE_ARN,
// LEDGER_TABLE, EXPECT_ORIGIN, GCP_WIF_AUDIENCE, GCP_KMS_RING, GCP_KMS_KEY.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/internal/lab"
	"github.com/jralmaraz/wimse-identity-fabric/internal/lab/cloud"
)

type service struct {
	role, name string
	agent      *lab.Agent
	cloudOn    bool
	aws        *cloud.AWS
	gcp        *cloud.GCP
}

func main() {
	role := mustEnv("ROLE")
	name := envOr("NAME", role)
	s := &service{role: role, name: name, cloudOn: os.Getenv("CLOUD") == "floci",
		aws: cloud.AWSFromEnv(), gcp: cloud.GCPFromEnv()}

	agent, err := lab.NewAgent(name, mustEnv("ISSUER_URL"), s.evidence)
	if err != nil {
		log.Fatal(err)
	}
	s.agent = agent
	go func() {
		if err := agent.AttestWithRetry(3 * time.Minute); err != nil {
			log.Printf("initial attestation failed (will retry on demand): %v", err)
			return
		}
		log.Printf("%s attested as %s", name, agent.ID())
	}()

	bundle, err := lab.TrustBundleFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	policy, err := parsePolicy(os.Getenv("POLICY"))
	if err != nil {
		log.Fatal(err)
	}
	v := lab.NewVerifier(name, mustEnv("SELF_URL"), bundle, policy)
	v.TxnIssuer = os.Getenv("TXN_ISSUER")
	v.TxnAudience = os.Getenv("TXN_AUDIENCE")
	v.RequireTxn = v.TxnIssuer != ""

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		lab.WriteJSON(w, 200, map[string]string{"status": "ok", "role": role, "workload_id": agent.ID()})
	})
	switch role {
	case "orders":
		mux.HandleFunc("POST /checkout", s.checkout)
		mux.HandleFunc("POST /debug/direct-ledger", s.directLedger)
	case "payments":
		mux.HandleFunc("POST /charge", v.Handler(s.charge))
	case "ledger":
		mux.HandleFunc("POST /entries", v.Handler(s.entries))
	default:
		log.Fatalf("unknown ROLE %q", role)
	}
	addr := ":" + envOr("PORT", "8080")
	log.Printf("lab-workload %s (role=%s) on %s, trusts %v, cloud=%v", name, role, addr, bundle.Domains(), s.cloudOn)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// evidence gathers attestation evidence for the issuer.
func (s *service) evidence() ([]lab.Evidence, error) {
	var out []lab.Evidence
	for _, typ := range strings.Split(envOr("EVIDENCE", "join-token"), ",") {
		switch strings.TrimSpace(typ) {
		case "join-token":
			out = append(out, lab.Evidence{Type: "join-token", Data: map[string]string{"token": os.Getenv("JOIN_TOKEN")}})
		case "docker":
			out = append(out, lab.Evidence{Type: "docker"})
		case "aws-sts":
			// Our "instance role": assume it, then presign GetCallerIdentity. The
			// issuer executes the URL; it never sees our secret key.
			creds, arn, err := s.aws.AssumeRole(os.Getenv("AWS_ROLE_ARN"), s.name)
			if err != nil {
				lab.Emit(lab.Event{Kind: "cloud", Src: s.name, Dst: "floci-aws", OK: false, TraceID: "startup",
					Summary: "sts:AssumeRole for attestation failed: " + err.Error()})
				continue
			}
			u, err := s.aws.PresignGetCallerIdentity(creds)
			if err != nil {
				continue
			}
			lab.Emit(lab.Event{Kind: "cloud", Src: s.name, Dst: "floci-aws", OK: true, TraceID: "startup",
				Summary: "sts:AssumeRole → " + arn + "; presigned GetCallerIdentity for the issuer"})
			out = append(out, lab.Evidence{Type: "aws-sts", Data: map[string]string{"url": u}})
		}
	}
	return out, nil
}

// ---- orders (AWS, entry point) -------------------------------------------------------

type checkoutReq struct {
	User   string `json:"user"`
	Item   string `json:"item"`
	Amount string `json:"amount"`
}

func (s *service) checkout(w http.ResponseWriter, r *http.Request) {
	in := checkoutReq{User: "alice@example.com", Item: "wimse-handbook", Amount: "42.00"}
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in)
	tp := lab.NewTraceparent()
	lab.Emit(lab.Event{TraceID: lab.TraceID(tp), Kind: "info", Src: "client", Dst: s.name, Method: "POST", Path: "/checkout",
		OK: true, Summary: fmt.Sprintf("end user %s buys %s for %s (edge request, user auth out of scope)", in.User, in.Item, in.Amount)})

	txn, err := s.agent.TxnToken(tp, in.User, "purchase", map[string]string{"item": in.Item, "amount": in.Amount})
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": "txn-token: " + err.Error(), "trace_id": lab.TraceID(tp)})
		return
	}
	var out map[string]any
	status, err := s.agent.PostJSON(mustEnv("PAYMENTS_URL")+"/charge", tp, in, txn, &out)
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": err.Error(), "trace_id": lab.TraceID(tp)})
		return
	}
	lab.WriteJSON(w, status, map[string]any{"trace_id": lab.TraceID(tp), "orders": s.agent.ID(), "payments": out})
}

// directLedger tries to skip payments and write to the ledger directly. The
// ledger authenticates orders fine – and then its policy says no (403).
func (s *service) directLedger(w http.ResponseWriter, _ *http.Request) {
	tp := lab.NewTraceparent()
	txn, err := s.agent.TxnToken(tp, "mallory@example.com", "purchase", map[string]string{"item": "free-stuff", "amount": "0"})
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	var out map[string]any
	status, err := s.agent.PostJSON(mustEnv("LEDGER_URL")+"/entries", tp, map[string]string{"amount": "1000000"}, txn, &out)
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	lab.WriteJSON(w, 200, map[string]any{"trace_id": lab.TraceID(tp), "ledger_status": status, "ledger_response": out})
}

// ---- payments (GCP) ------------------------------------------------------------------

func (s *service) charge(w http.ResponseWriter, r *http.Request, caller *lab.Caller) {
	var in checkoutReq
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in)
	tp := caller.Traceprnt
	result := map[string]any{"charged": true, "caller": caller.ID, "txn": caller.Txn.Txn, "payments": s.agent.ID()}

	if s.cloudOn {
		aud := envOr("GCP_WIF_AUDIENCE", "//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/wimse-lab/providers/issuer-gcp")
		ring, key := envOr("GCP_KMS_RING", "wimse-lab"), envOr("GCP_KMS_KEY", "card-data")
		ct, err := s.cloudChain(tp, "floci-gcp", []step{
			{"RFC 8693 exchange at issuer-gcp (aud=GCP WIF)", func(_ string) (string, error) { return s.agent.Exchange(tp, aud) }},
			{"GCP STS /v1/token: exchanged JWT → federated access token", func(jwt string) (string, error) { return s.gcp.STSExchange(jwt, aud) }},
			{"Cloud KMS encrypt card reference with federated token", func(at string) (string, error) {
				return s.gcp.Encrypt(at, ring, key, []byte("card-ref:"+caller.Txn.Txn))
			}},
		})
		result["gcp_kms"] = cloudResult(ct, err)
	}

	var ledger map[string]any
	status, err := s.agent.PostJSON(mustEnv("LEDGER_URL")+"/entries", tp,
		map[string]string{"user": caller.Txn.Subject, "item": in.Item, "amount": in.Amount}, caller.TxnRaw, &ledger)
	if err != nil {
		lab.WriteJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	result["ledger"] = ledger
	lab.WriteJSON(w, status, result)
}

// ---- ledger (AWS) --------------------------------------------------------------------

func (s *service) entries(w http.ResponseWriter, r *http.Request, caller *lab.Caller) {
	var in map[string]string
	_ = json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in)
	tp := caller.Traceprnt

	// Chain integrity: the transaction must have been started by the expected
	// entry point, whatever hop delivers it.
	origin := ""
	if caller.Txn.ReqCtx != nil {
		origin = caller.Txn.ReqCtx.ReqWL
	}
	if want := os.Getenv("EXPECT_ORIGIN"); want != "" && origin != want {
		lab.WriteProblem(w, &lab.Rejection{Status: 403, Code: "unexpected-origin",
			Detail: fmt.Sprintf("transaction started by %s, expected %s", origin, want)})
		return
	}
	entry := map[string]string{"txn": caller.Txn.Txn, "user": caller.Txn.Subject, "amount": in["amount"],
		"item": in["item"], "origin": origin, "recorded_via": caller.ID, "at": time.Now().UTC().Format(time.RFC3339)}
	result := map[string]any{"recorded": true, "entry": entry, "ledger": s.agent.ID()}

	if s.cloudOn {
		roleARN := envOr("LEDGER_ROLE_ARN", "arn:aws:iam::000000000000:role/ledger-data")
		table := envOr("LEDGER_TABLE", "wimse-ledger")
		var creds cloud.Creds
		out, err := s.cloudChain(tp, "floci-aws", []step{
			{"RFC 8693 exchange at issuer-aws (aud=sts.amazonaws.com)", func(_ string) (string, error) {
				return s.agent.Exchange(tp, "sts.amazonaws.com")
			}},
			{"sts:AssumeRoleWithWebIdentity with exchanged JWT", func(jwt string) (string, error) {
				c, arn, err := s.aws.AssumeRoleWithWebIdentity(roleARN, "ledger-"+caller.Txn.Txn[:8], jwt)
				creds = c
				return arn, err
			}},
			{"dynamodb:PutItem with temporary credentials", func(_ string) (string, error) {
				return table + "/" + caller.Txn.Txn, s.aws.DynamoPutItem(creds, table, entry)
			}},
		})
		result["dynamodb"] = cloudResult(out, err)
	}
	lab.WriteJSON(w, 200, result)
}

// ---- cloud helpers ---------------------------------------------------------------------

type step struct {
	desc string
	fn   func(prev string) (string, error)
}

// cloudChain runs dependent cloud steps, emitting one observer event per step.
// Cloud steps are best effort: the WIMSE flow is the point of the demo, and
// emulator coverage varies – failures are shown, not fatal.
func (s *service) cloudChain(tp, dst string, steps []step) (string, error) {
	prev := ""
	for i, st := range steps {
		out, err := st.fn(prev)
		target := dst
		if i == 0 { // first step is always the RFC 8693 exchange at our own issuer
			target = "issuer-" + strings.TrimPrefix(dst, "floci-")
		}
		ev := lab.Event{TraceID: lab.TraceID(tp), Kind: "cloud", Src: s.name, Dst: target, OK: err == nil, Summary: st.desc}
		if err != nil {
			ev.Summary += " FAILED: " + err.Error()
			lab.Emit(ev)
			return "", fmt.Errorf("%s: %w", st.desc, err)
		}
		if i > 0 { // the issuer already reports the exchange itself
			ev.Summary += " → " + trunc(out, 60)
			lab.Emit(ev)
		}
		prev = out
	}
	return prev, nil
}

func cloudResult(out string, err error) map[string]any {
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true, "result": trunc(out, 80)}
}

func parsePolicy(raw string) (map[string][]string, error) {
	p := map[string][]string{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		path, ids, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("bad POLICY entry %q (want /path=id1,id2)", entry)
		}
		for _, id := range strings.Split(ids, ",") {
			if id = strings.TrimSpace(id); id != "" {
				p[strings.TrimSpace(path)] = append(p[strings.TrimSpace(path)], id)
			}
		}
	}
	return p, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
