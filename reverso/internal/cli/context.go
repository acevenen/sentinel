package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/acevenen/sentinel/reverso/internal/evidence"
	"github.com/acevenen/sentinel/reverso/internal/scope"
)

// Project workspace layout under <dir>/.reverso.
const (
	workDir       = ".reverso"
	manifestName  = "scope.yaml"
	configName    = "config.json"
	dbName        = "evidence.db"
	blobsName     = "blobs"
	auditName     = "audit.log"
	keysDir       = "keys"
	ownerKeyName  = "owner.key"
	ownerPubName  = "owner.pub"
	auditKeyName  = "audit.key"
	auditPubName  = "audit.pub"
	saltName      = "blob.salt"
	passphraseEnv = "REVERSO_PASSPHRASE"
)

// workConfig persists project-level settings.
type workConfig struct {
	ProjectID string `json:"project_id"`
	Encrypted bool   `json:"encrypted"`
}

// Context bundles everything a command needs after the project is initialized.
type Context struct {
	Dir      string
	Store    *evidence.Store
	Blobs    *evidence.BlobStore
	Audit    *evidence.AuditLog
	AuditPub ed25519.PublicKey
	OwnerPub ed25519.PublicKey
	Manifest *scope.Manifest
	Policy   scope.Policy
	Actor    string
}

// Close releases the store.
func (c *Context) Close() {
	if c != nil && c.Store != nil {
		_ = c.Store.Close()
	}
}

func work(dir string) string         { return filepath.Join(dir, workDir) }
func manifestPath(dir string) string { return filepath.Join(work(dir), manifestName) }
func configPath(dir string) string   { return filepath.Join(work(dir), configName) }
func keyPath(dir, name string) string {
	return filepath.Join(work(dir), keysDir, name)
}

// initialized reports whether a project workspace exists at dir.
func initialized(dir string) bool {
	_, err := os.Stat(configPath(dir))
	return err == nil
}

func writeConfig(dir string, cfg workConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(dir), data, 0o600)
}

func readConfig(dir string) (workConfig, error) {
	var cfg workConfig
	data, err := os.ReadFile(configPath(dir))
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

func writeKey(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Join(work(dir), keysDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(keyPath(dir, name), data, mode)
}

func readKeyFile(dir, name string) ([]byte, error) {
	return os.ReadFile(keyPath(dir, name))
}

// deriveKey turns a passphrase and salt into a 32-byte AES key.
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, evidence.KeySize)
}

// blobStore builds the blob store honoring the project's encryption setting.
func blobStore(dir string, encrypted bool) (*evidence.BlobStore, error) {
	root := filepath.Join(work(dir), blobsName)
	if !encrypted {
		return evidence.NewBlobStore(root), nil
	}
	pass := os.Getenv(passphraseEnv)
	if pass == "" {
		return nil, fmt.Errorf("evidence store is encrypted; set %s to unlock it", passphraseEnv)
	}
	salt, err := os.ReadFile(filepath.Join(work(dir), saltName))
	if err != nil {
		return nil, fmt.Errorf("reading blob salt: %w", err)
	}
	key, err := deriveKey(pass, salt)
	if err != nil {
		return nil, fmt.Errorf("deriving encryption key: %w", err)
	}
	return evidence.NewEncryptedBlobStore(root, key)
}

// ErrNotInitialized means a command ran outside an initialized project.
var ErrNotInitialized = errors.New("no REVerso project here; run `reverso scope init` first")

// loadContext opens the project workspace, loads and verifies the manifest,
// and builds a fail-closed policy. The manifest signature must verify against
// the project owner key (the trust anchor) or loading fails.
func loadContext(dir, actor string) (*Context, error) {
	if !initialized(dir) {
		return nil, ErrNotInitialized
	}
	cfg, err := readConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("reading project config: %w", err)
	}

	store, err := evidence.Open(filepath.Join(work(dir), dbName))
	if err != nil {
		return nil, err
	}

	blobs, err := blobStore(dir, cfg.Encrypted)
	if err != nil {
		_ = store.Close()
		return nil, err
	}

	auditPrivRaw, err := readKeyFile(dir, auditKeyName)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("reading audit key: %w", err)
	}
	auditPriv, err := scope.DecodePrivateKey(string(auditPrivRaw))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("decoding audit key: %w", err)
	}
	auditPubRaw, err := readKeyFile(dir, auditPubName)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("reading audit public key: %w", err)
	}
	auditPub, err := scope.DecodePublicKey(string(auditPubRaw))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("decoding audit public key: %w", err)
	}

	ownerPubRaw, err := readKeyFile(dir, ownerPubName)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("reading owner public key: %w", err)
	}
	ownerPub, err := scope.DecodePublicKey(string(ownerPubRaw))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("decoding owner public key: %w", err)
	}

	manifest, err := scope.Load(manifestPath(dir))
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := manifest.Validate(); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("manifest is invalid: %w", err)
	}
	if err := manifest.VerifySignature([]ed25519.PublicKey{ownerPub}); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("manifest signature: %w", err)
	}

	return &Context{
		Dir:      dir,
		Store:    store,
		Blobs:    blobs,
		Audit:    evidence.NewAuditLog(filepath.Join(work(dir), auditName), auditPriv),
		AuditPub: auditPub,
		OwnerPub: ownerPub,
		Manifest: manifest,
		Policy:   scope.New(manifest),
		Actor:    actor,
	}, nil
}

// newAuditKeypair generates a fresh audit signing keypair.
func newAuditKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
