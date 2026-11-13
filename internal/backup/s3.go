package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/prezmc/dnserv/internal/store"
)

// S3 is a small client for an S3 or S3-compatible bucket: just what
// backups need (put, list, get, delete), signed with AWS Signature V4.
// It avoids pulling the whole AWS SDK into the image.
type S3 struct {
	T      store.S3Target
	Client *http.Client
	Now    func() time.Time
}

// S3Object is one object in a listing.
type S3Object struct {
	Key      string
	Size     int64
	Modified time.Time
}

func (c *S3) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (c *S3) region() string {
	if c.T.Region != "" {
		return c.T.Region
	}
	// Most S3-compatible services accept any region; this is the usual
	// default (MinIO, R2 "auto" also works when set by hand).
	return "us-east-1"
}

// base returns the scheme and host, and the path prefix for the bucket.
func (c *S3) base() (scheme, host, path string) {
	ep := c.T.Endpoint
	scheme = "https"
	if i := strings.Index(ep, "://"); i >= 0 {
		scheme, ep = ep[:i], ep[i+3:]
	}
	if ep == "" {
		ep = "s3." + c.region() + ".amazonaws.com"
	}
	// Bucket names with dots break the TLS name check in virtual-host
	// style, so those go in the path too.
	if c.T.PathStyle || strings.Contains(c.T.Bucket, ".") {
		return scheme, ep, "/" + c.T.Bucket
	}
	return scheme, c.T.Bucket + "." + ep, ""
}

// Key returns the object key for a file name, inside the folder.
func (c *S3) Key(name string) string {
	if c.T.Prefix == "" {
		return name
	}
	return c.T.Prefix + "/" + name
}

// do sends one signed request and returns the body of a 2xx answer.
func (c *S3) do(ctx context.Context, method, key string, query url.Values, body []byte) ([]byte, error) {
	scheme, host, path := c.base()
	p := path + "/" + key
	// RawPath makes the request carry exactly the escaping that is signed.
	u := &url.URL{Scheme: scheme, Host: host, Path: p, RawPath: uriEncode(p, false), RawQuery: canonicalQuery(query)}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body == nil {
		req.Body = nil
	}
	req.ContentLength = int64(len(body))
	c.sign(req, body)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxObject))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, s3Error(resp.StatusCode, b)
	}
	return b, nil
}

// maxObject caps what is read back from the bucket.
const maxObject = 128 << 20

// s3Error turns an S3 error answer into a message a person can act on.
func s3Error(status int, body []byte) error {
	var e struct {
		Code    string
		Message string
	}
	_ = xml.Unmarshal(body, &e)
	hint := ""
	switch e.Code {
	case "NoSuchBucket":
		hint = " (check the bucket name)"
	case "InvalidAccessKeyId", "SignatureDoesNotMatch":
		hint = " (check the access key and secret key)"
	case "AccessDenied":
		hint = " (the key needs permission to list, read, write and delete in that bucket)"
	case "AuthorizationHeaderMalformed", "PermanentRedirect", "IllegalLocationConstraintException":
		hint = " (check the region)"
	}
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Errorf("S3 said %s: %s%s", e.Code, e.Message, hint)
	case e.Code != "":
		return fmt.Errorf("S3 said %s%s", e.Code, hint)
	}
	return fmt.Errorf("S3 answered %d %s", status, http.StatusText(status))
}

// Put uploads one object.
func (c *S3) Put(ctx context.Context, name string, b []byte) error {
	_, err := c.do(ctx, http.MethodPut, c.Key(name), nil, b)
	return err
}

// Get downloads one object.
func (c *S3) Get(ctx context.Context, name string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, c.Key(name), nil, nil)
}

// Delete removes one object.
func (c *S3) Delete(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, c.Key(name), nil, nil)
	return err
}

// List returns the objects directly in the folder, by file name.
func (c *S3) List(ctx context.Context) ([]S3Object, error) {
	prefix := ""
	if c.T.Prefix != "" {
		prefix = c.T.Prefix + "/"
	}
	var out []S3Object
	token := ""
	for range 50 { // at most 50,000 objects
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "delimiter": {"/"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		b, err := c.do(ctx, http.MethodGet, "", q, nil)
		if err != nil {
			return nil, err
		}
		var r struct {
			Contents []struct {
				Key          string
				Size         int64
				LastModified time.Time
			}
			IsTruncated           bool
			NextContinuationToken string
		}
		if err := xml.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("couldn't read the bucket listing: %w", err)
		}
		for _, o := range r.Contents {
			out = append(out, S3Object{Key: strings.TrimPrefix(o.Key, prefix), Size: o.Size, Modified: o.LastModified})
		}
		if !r.IsTruncated || r.NextContinuationToken == "" {
			return out, nil
		}
		token = r.NextContinuationToken
	}
	return out, nil
}

// uriEncode escapes like S3 expects: everything but unreserved
// characters, and "/" too unless slash is set.
func uriEncode(s string, slash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case 'A' <= ch && ch <= 'Z', 'a' <= ch && ch <= 'z', '0' <= ch && ch <= '9', ch == '-', ch == '_', ch == '.', ch == '~':
			b.WriteByte(ch)
		case ch == '/' && !slash:
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := slices.Clone(q[k])
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// sign adds AWS Signature V4 headers to req.
func (c *S3) sign(req *http.Request, body []byte) {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	now = now.UTC()
	stamp, day := now.Format("20060102T150405Z"), now.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payload)

	// Sign host and every x-amz-* header (and range, if set).
	names := []string{"host"}
	vals := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "range" || lk == "content-type" {
			names = append(names, lk)
			vals[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	sort.Strings(names)
	var hdrs strings.Builder
	for _, n := range names {
		hdrs.WriteString(n + ":" + vals[n] + "\n")
	}
	signed := strings.Join(names, ";")
	canon := strings.Join([]string{req.Method, uriEncode(req.URL.Path, false), req.URL.RawQuery, hdrs.String(), signed, payload}, "\n")
	scope := day + "/" + c.region() + "/s3/aws4_request"
	cs := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(cs[:])
	k := hmacSHA([]byte("AWS4"+c.T.SecretKey), day)
	k = hmacSHA(k, c.region())
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.T.AccessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

// Test checks that DNServ can write, list, read and delete in the
// bucket, using a small file it removes again.
func (c *S3) Test(ctx context.Context) error {
	name := ".dnserv-test-" + time.Now().UTC().Format("20060102-150405")
	data := []byte("DNServ checks it can write backups here. Safe to delete.\n")
	if err := c.Put(ctx, name, data); err != nil {
		return fmt.Errorf("writing a test file: %w", err)
	}
	if _, err := c.List(ctx); err != nil {
		_ = c.Delete(ctx, name)
		return fmt.Errorf("listing the folder: %w", err)
	}
	got, err := c.Get(ctx, name)
	if err != nil {
		_ = c.Delete(ctx, name)
		return fmt.Errorf("reading the test file back: %w", err)
	}
	if !bytes.Equal(got, data) {
		_ = c.Delete(ctx, name)
		return errors.New("the test file came back different")
	}
	if err := c.Delete(ctx, name); err != nil {
		return fmt.Errorf("deleting the test file (old backups couldn't be removed): %w", err)
	}
	return nil
}
