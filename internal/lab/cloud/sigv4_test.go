package cloud

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

var exampleCreds = Creds{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}

// Example from the AWS General Reference "Signature Version 4 signing process"
// (IAM ListUsers, 2015-08-30T12:36:00Z).
func TestSignRequestAWSExample(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	ts, _ := time.Parse(amzDateFormat, "20150830T123600Z")
	SignRequest(req, nil, exampleCreds, "us-east-1", "iam", ts)

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, want)
	}
}

// Example from the Amazon S3 docs "Authenticating Requests: Using Query Parameters".
func TestPresignS3Example(t *testing.T) {
	creds := Creds{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	ts, _ := time.Parse(amzDateFormat, "20130524T000000Z")
	u, err := Presign("GET", "https://examplebucket.s3.amazonaws.com/test.txt", creds, "us-east-1", "s3", ts,
		86400*time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	const want = "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	if !strings.HasSuffix(u, want) {
		t.Fatalf("presigned URL signature mismatch: %s", u)
	}
}

func TestPresignIncludesSessionToken(t *testing.T) {
	c := exampleCreds
	c.SessionToken = "tok/en+="
	u, err := Presign("GET", "http://floci:4566/?Action=GetCallerIdentity&Version=2011-06-15", c, "us-east-1",
		"sts", time.Now(), time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "X-Amz-Security-Token=tok%2Fen%2B%3D") || !strings.Contains(u, "Action=GetCallerIdentity") {
		t.Fatalf("unexpected URL %s", u)
	}
}
