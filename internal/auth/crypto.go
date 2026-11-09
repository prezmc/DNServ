// Package auth implements passwords, TOTP, recovery codes, sessions, API
// tokens and login throttling.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: OWASP's recommended minimum (19 MiB, 2 passes),
// light enough for a Raspberry Pi.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

// MinPasswordLen is the minimum password length.
const MinPasswordLen = 12

// CheckPasswordStrength rejects short or trivially weak passwords.
func CheckPasswordStrength(pw, username string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if utf8.RuneCountInString(pw) > 256 {
		return errors.New("password must be at most 256 characters")
	}
	if username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(username)) {
		return errors.New("password must not contain the username")
	}
	distinct := map[rune]bool{}
	for _, r := range pw {
		distinct[r] = true
	}
	if len(distinct) < 5 {
		return errors.New("password is too repetitive")
	}
	return nil
}

// HashPassword returns an encoded Argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when a username doesn't exist, so a
// failed login takes the same time either way.
var dummyHash, _ = HashPassword("dnserve-timing-equalizer")

// VerifyDummy spends the same time as a real verification.
func VerifyDummy(pw string) { VerifyPassword(dummyHash, pw) }

// RandomID returns a URL-safe random identifier with n bytes of entropy.
func RandomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken hashes a high-entropy secret (session or API token, recovery
// code). These are random, so a fast hash is safe.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- TOTP (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits) ---

const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew accepts codes one step either side, for clock drift.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret, base32 encoded.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// TOTPURL is the otpauth:// URL authenticator apps read from a QR code.
func TOTPURL(secret, account, issuer string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(totpDigits))
	v.Set("period", strconv.Itoa(totpPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000), nil
}

// TOTPCode returns the code for time t (for tests and enrollment checks).
func TOTPCode(secret string, t time.Time) (string, error) {
	return totpAt(secret, t.Unix()/totpPeriod)
}

// VerifyTOTP checks code at time now and returns the matching step. The
// caller must reject steps at or before the last one used (replay).
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want, err := totpAt(secret, cur+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return cur + d, true
		}
	}
	return 0, false
}

// --- recovery codes ---

// NewRecoveryCodes returns n one-time codes like "k7m2-9xq4-pt3h" and their
// hashes.
func NewRecoveryCodes(n int) (codes, hashes []string) {
	const alphabet = "23456789abcdefghjkmnpqrstuvwxyz" // no 0/o, 1/l/i
	for i := 0; i < n; i++ {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		var sb strings.Builder
		for j, c := range b {
			if j > 0 && j%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(c)%len(alphabet)])
		}
		code := sb.String()
		codes = append(codes, code)
		hashes = append(hashes, HashToken(NormalizeRecovery(code)))
	}
	return codes, hashes
}

// NewSetupCode returns a first-run code like "K7M2-9XQ4" (about 40 bits,
// and setup attempts are throttled).
func NewSetupCode() string {
	const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i, c := range b {
		b[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}

// NormalizeSetupCode ignores case, spaces and dashes.
func NormalizeSetupCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

// NormalizeRecovery strips separators and case so "K7M2 9XQ4 PT3H" works.
func NormalizeRecovery(code string) string {
	r := strings.NewReplacer("-", "", " ", "")
	return strings.ToLower(r.Replace(strings.TrimSpace(code)))
}
