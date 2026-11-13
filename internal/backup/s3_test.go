package backup

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// TestS3Signature checks the signer against the worked example in the
// AWS Signature V4 documentation (GET Object with a Range header).
func TestS3Signature(t *testing.T) {
	c := &S3{T: store.S3Target{Region: "us-east-1", Bucket: "examplebucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		Now: func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }}
	req, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	c.sign(req, nil)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization\n got %s\nwant %s", got, want)
	}
}

// fakeS3 is a path-style bucket that checks each request is signed.
type fakeS3 struct {
	mu   sync.Mutex
	objs map[string][]byte
	fail string // answer every request with this error code
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") {
		http.Error(w, "<Error><Code>AccessDenied</Code></Error>", 403)
		return
	}
	if f.fail != "" {
		w.WriteHeader(403)
		io.WriteString(w, "<Error><Code>"+f.fail+"</Code><Message>nope</Message></Error>")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/bkt/")
	switch r.Method {
	case "PUT":
		b, _ := io.ReadAll(r.Body)
		f.objs[key] = b
	case "DELETE":
		delete(f.objs, key)
		w.WriteHeader(204)
	case "GET":
		if r.URL.Query().Get("list-type") == "2" {
			p := r.URL.Query().Get("prefix")
			io.WriteString(w, "<ListBucketResult>")
			for k, v := range f.objs {
				if strings.HasPrefix(k, p) && !strings.Contains(k[len(p):], "/") {
					io.WriteString(w, "<Contents><Key>"+k+"</Key><Size>"+strconv.Itoa(len(v))+"</Size><LastModified>2026-11-13T00:00:00.000Z</LastModified></Contents>")
				}
			}
			io.WriteString(w, "<IsTruncated>false</IsTruncated></ListBucketResult>")
			return
		}
		b, ok := f.objs[key]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
			return
		}
		w.Write(b)
	}
}

func TestS3RoundTrip(t *testing.T) {
	f := &fakeS3{objs: map[string][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := &S3{T: store.S3Target{Endpoint: srv.URL, Bucket: "bkt", Prefix: "dns home", AccessKey: "AK", SecretKey: "SK", PathStyle: true}}
	ctx := context.Background()
	if err := c.Test(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.objs) != 0 {
		t.Fatalf("test file left behind: %v", f.objs)
	}
	if err := c.Put(ctx, "a.dnsbak", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.objs["dns home/a.dnsbak"]; !ok {
		t.Fatalf("stored under %v", f.objs)
	}
	l, err := c.List(ctx)
	if err != nil || len(l) != 1 || l[0].Key != "a.dnsbak" {
		t.Fatalf("list = %v, %v", l, err)
	}
	f.fail = "SignatureDoesNotMatch"
	if err := c.Put(ctx, "b.dnsbak", nil); err == nil || !strings.Contains(err.Error(), "secret key") {
		t.Fatalf("want a hint about keys, got %v", err)
	}
}
