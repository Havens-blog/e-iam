package cryptox

import (
	"strings"
	"testing"
)

func TestAESCryptoV1_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		plainText string
	}{
		{"short key", "mysecret", "hello world"},
		{"exact 16 key", "0123456789abcdef", "sensitive-data"},
		{"long key truncated", "this-is-a-very-long-key-truncated-to-16", "MFA secret value"},
		{"empty plaintext", "key", ""},
		{"unicode", "key", "密码secret🔐"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crypto := MustNewAESCrypto(tc.key)
			enc, err := crypto.Encrypt(tc.plainText)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			if enc == tc.plainText && tc.plainText != "" {
				t.Fatalf("ciphertext identical to plaintext — not encrypted")
			}
			dec, err := crypto.Decrypt(enc)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if dec != tc.plainText {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, tc.plainText)
			}
		})
	}
}

func TestAESCryptoV2_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		plainText string
	}{
		{"short key", "mysecret", "hello world"},
		{"long key", "a-much-longer-key-than-16-bytes", "OIDC client secret"},
		{"empty plaintext", "key", ""},
		{"unicode", "key", "密码secret🔐"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crypto := MustNewAESCryptoV2(tc.key)
			enc, err := crypto.Encrypt(tc.plainText)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			if enc == tc.plainText && tc.plainText != "" {
				t.Fatalf("ciphertext identical to plaintext — not encrypted")
			}
			dec, err := crypto.Decrypt(enc)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if dec != tc.plainText {
				t.Fatalf("round-trip mismatch: got %q, want %q", dec, tc.plainText)
			}
		})
	}
}

func TestCryptoManager_EncryptProducesPrefix(t *testing.T) {
	mgr := NewCryptoManager("v1").
		Register("v1", MustNewAESCryptoV2("test-key"))

	enc, err := mgr.Encrypt("my secret")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(enc, "ENC:v1:") {
		t.Fatalf("missing ENC: prefix: got %q", enc)
	}
}

func TestCryptoManager_RoundTrip(t *testing.T) {
	mgr := NewCryptoManager("v2").
		Register("v2", MustNewAESCryptoV2("manager-key"))

	plain := "LDAP bind password"
	enc, err := mgr.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if !strings.HasPrefix(enc, "ENC:v2:") {
		t.Fatalf("expected ENC:v2: prefix, got %q", enc)
	}

	dec, err := mgr.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if dec != plain {
		t.Fatalf("round-trip mismatch: got %q, want %q", dec, plain)
	}
}

func TestCryptoManager_LegacyFallback(t *testing.T) {
	// V1 algo used for legacy data (no ENC: prefix)
	v1 := MustNewAESCrypto("legacy-key")
	legacyEnc, err := v1.Encrypt("old password")
	if err != nil {
		t.Fatalf("legacy Encrypt failed: %v", err)
	}
	if strings.HasPrefix(legacyEnc, EncryptedPrefix) {
		t.Fatalf("legacy ciphertext should NOT have ENC: prefix")
	}

	// Manager: default V2, legacy V1 — decrypts unprefixed V1 ciphertext
	mgr := NewCryptoManager("v2").
		Register("v2", MustNewAESCryptoV2("new-key")).
		Register("legacy", v1).
		WithLegacyAlgo("legacy")

	dec, err := mgr.Decrypt(legacyEnc)
	if err != nil {
		t.Fatalf("legacy Decrypt failed: %v", err)
	}
	if dec != "old password" {
		t.Fatalf("legacy round-trip mismatch: got %q, want %q", dec, "old password")
	}
}

func TestCryptoManager_LegacyMigrationHandler(t *testing.T) {
	v1 := MustNewAESCrypto("legacy-key")
	legacyEnc, _ := v1.Encrypt("migrate me")

	var migratedOld, migratedNew string
	mgr := NewCryptoManager("v2").
		Register("v2", MustNewAESCryptoV2("new-key")).
		Register("legacy", v1).
		WithLegacyAlgo("legacy").
		WithMigrationHandler(func(oldEnc, newEnc string) {
			migratedOld = oldEnc
			migratedNew = newEnc
		})

	_, _ = mgr.Decrypt(legacyEnc)
	if migratedOld != legacyEnc {
		t.Fatalf("migration handler oldEnc mismatch: got %q, want %q", migratedOld, legacyEnc)
	}
	if !strings.HasPrefix(migratedNew, "ENC:v2:") {
		t.Fatalf("migration handler newEnc should have ENC:v2: prefix, got %q", migratedNew)
	}
}

func TestCryptoManager_PlaintextFallback(t *testing.T) {
	// No legacy algo registered — unprefixed value returned as plaintext
	mgr := NewCryptoManager("v1").
		Register("v1", MustNewAESCryptoV2("key"))

	dec, err := mgr.Decrypt("just-plaintext-no-prefix")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec != "just-plaintext-no-prefix" {
		t.Fatalf("plaintext fallback mismatch: got %q", dec)
	}
}

func TestCryptoManager_UnsupportedVersion(t *testing.T) {
	mgr := NewCryptoManager("v1").
		Register("v1", MustNewAESCryptoV2("key"))

	_, err := mgr.Decrypt("ENC:v99:somehex")
	if err == nil {
		t.Fatalf("expected error for unsupported version, got nil")
	}
}

func TestCryptoManager_NoDefaultAlgorithm(t *testing.T) {
	mgr := NewCryptoManager("v1")
	_, err := mgr.Encrypt("test")
	if err == nil {
		t.Fatalf("expected error when no default algorithm registered, got nil")
	}
}

func TestCryptoManager_InvalidEncryptedFormat(t *testing.T) {
	mgr := NewCryptoManager("v1").
		Register("v1", MustNewAESCryptoV2("key"))

	_, err := mgr.Decrypt("ENC:no-colon-hex")
	if err == nil {
		t.Fatalf("expected error for invalid format, got nil")
	}
}

func TestPadKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantLen int
	}{
		{"short padded to 16", "abc", 16},
		{"exact 16 unchanged", "0123456789abcdef", 16},
		{"long truncated to 16", "0123456789abcdefghijklmn", 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			padded, err := padKey(tc.key)
			if err != nil {
				t.Fatalf("padKey error: %v", err)
			}
			if len(padded) != tc.wantLen {
				t.Fatalf("padKey length: got %d, want %d", len(padded), tc.wantLen)
			}
		})
	}
}
