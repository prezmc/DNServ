// Package backup writes and reads encrypted DNServe backups, and runs the
// backup schedule.
//
// A backup is encrypted to a public key derived from the owner's
// passphrase. Nodes keep only the public key, so they can make backups on
// a schedule but can't read them; the passphrase is needed to restore and
// is never stored. The format is a short text header, so the file says
// what it is, followed by the sealed data:
//
//	DNSERVE-BACKUP 1
//	{"created":...,"salt":...,"epk":...,"nonce":...}
//	<XChaCha20-Poly1305 ciphertext of gzipped JSON>
//
// The key: X25519 private key = scrypt(passphrase, salt); per file, an
// ephemeral X25519 key agrees a secret with it, and HKDF-SHA256 turns that
// into the data key. The header is authenticated as associated data.
package backup

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/prezmc/dnserve/internal/store"
)

const magic = "DNSERVE-BACKUP 1\n"

// Scrypt cost: about 100 ms and 32 MB, once per passphrase use.
const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

// MinPassphrase is the shortest passphrase accepted.
const MinPassphrase = 12

// Header describes a backup. It is readable without the passphrase.
type Header struct {
	Created   time.Time `json:"created"`
	Node      string    `json:"node"`
	ClusterID string    `json:"cluster_id,omitempty"`
	Version   string    `json:"version,omitempty"` // DNServe version that made it
	Salt      string    `json:"salt"`
	N         int       `json:"n"`
	R         int       `json:"r"`
	P         int       `json:"p"`
	EPK       string    `json:"epk"`
	Nonce     string    `json:"nonce"`
}

var b64 = base64.StdEncoding

func privateKey(passphrase string, salt []byte, n, r, p int) (*ecdh.PrivateKey, error) {
	seed, err := scrypt.Key([]byte(passphrase), salt, n, r, p, 32)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(seed)
}

// NewKey derives the backup key from a passphrase. It returns the public
// key and salt (base64) to store; the passphrase itself is not kept.
func NewKey(passphrase string) (publicKey, salt string, err error) {
	if len([]rune(passphrase)) < MinPassphrase {
		return "", "", fmt.Errorf("use a passphrase of at least %d characters (a few random words works well)", MinPassphrase)
	}
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		return "", "", err
	}
	k, err := privateKey(passphrase, s, scryptN, scryptR, scryptP)
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(k.PublicKey().Bytes()), b64.EncodeToString(s), nil
}

func dataKey(shared, epk, pub []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, append(append([]byte{}, epk...), pub...), "dnserve-backup-v1", chacha20poly1305.KeySize)
}

// Seal encrypts data for cfg's key.
func Seal(data store.BackupData, cfg store.BackupConfig, h Header) ([]byte, error) {
	if !cfg.Configured() {
		return nil, errors.New("backups aren't set up: choose a backup passphrase first")
	}
	pubBytes, err := b64.DecodeString(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := dataKey(shared, eph.PublicKey().Bytes(), pubBytes)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h.Salt, h.N, h.R, h.P = cfg.Salt, scryptN, scryptR, scryptP
	h.EPK, h.Nonce = b64.EncodeToString(eph.PublicKey().Bytes()), b64.EncodeToString(nonce)
	if h.Created.IsZero() {
		h.Created = time.Now().UTC()
	}
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}

	var plain bytes.Buffer
	zw := gzip.NewWriter(&plain)
	if err := json.NewEncoder(zw).Encode(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(magic)
	out.Write(hdr)
	out.WriteByte('\n')
	out.Write(aead.Seal(nil, nonce, plain.Bytes(), hdr))
	return out.Bytes(), nil
}

// ErrBadPassphrase means the passphrase is wrong or the file was changed.
var ErrBadPassphrase = errors.New("that passphrase doesn't open this backup (or the file is damaged)")

// ReadHeader returns a backup's header without decrypting it.
func ReadHeader(file []byte) (Header, []byte, []byte, error) {
	var h Header
	if !bytes.HasPrefix(file, []byte(magic)) {
		return h, nil, nil, errors.New("that isn't a DNServe backup file")
	}
	rest := file[len(magic):]
	i := bytes.IndexByte(rest, '\n')
	if i < 0 {
		return h, nil, nil, errors.New("the backup file is damaged")
	}
	hdr := rest[:i]
	if err := json.Unmarshal(hdr, &h); err != nil {
		return h, nil, nil, errors.New("the backup file is damaged")
	}
	return h, hdr, rest[i+1:], nil
}

// Open decrypts a backup with the passphrase.
func Open(file []byte, passphrase string) (Header, store.BackupData, error) {
	var data store.BackupData
	h, hdr, sealed, err := ReadHeader(file)
	if err != nil {
		return h, data, err
	}
	salt, err1 := b64.DecodeString(h.Salt)
	epk, err2 := b64.DecodeString(h.EPK)
	nonce, err3 := b64.DecodeString(h.Nonce)
	if err := errors.Join(err1, err2, err3); err != nil || h.N < 2 || h.N > 1<<20 || h.R < 1 || h.R > 32 || h.P < 1 || h.P > 16 {
		return h, data, errors.New("the backup file is damaged")
	}
	priv, err := privateKey(passphrase, salt, h.N, h.R, h.P)
	if err != nil {
		return h, data, err
	}
	ep, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return h, data, errors.New("the backup file is damaged")
	}
	shared, err := priv.ECDH(ep)
	if err != nil {
		return h, data, ErrBadPassphrase
	}
	key, err := dataKey(shared, epk, priv.PublicKey().Bytes())
	if err != nil {
		return h, data, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return h, data, err
	}
	if len(nonce) != aead.NonceSize() {
		return h, data, errors.New("the backup file is damaged")
	}
	plain, err := aead.Open(nil, nonce, sealed, hdr)
	if err != nil {
		return h, data, ErrBadPassphrase
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return h, data, err
	}
	dec := json.NewDecoder(bufio.NewReader(io.LimitReader(zr, 256<<20)))
	if err := dec.Decode(&data); err != nil {
		return h, data, fmt.Errorf("the backup's contents are damaged: %w", err)
	}
	return h, data, nil
}
