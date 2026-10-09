package cryptox

// compat_test.go proves BYTE-LEVEL COMPATIBILITY of the local port
// (eiam/internal/cryptox) against ciphertexts produced by the ORIGINAL
// library github.com/Duke1616/ecmdb@v1.11.0/pkg/cryptox.
//
// The KAT vectors below were generated ONCE by a throwaway program that
// imported the ORIGINAL ecmdb cryptox with FIXED keys + FIXED plaintext,
// then encrypted. They are frozen string literals — do NOT regenerate them.
// AES-GCM uses a random nonce, so encryption output is non-deterministic;
// compatibility is proven ONLY by "original-lib encrypt -> local-lib decrypt"
// (never by comparing two encryption outputs).
//
// Generation material (must stay in sync with these literals):
//
//	katV1Key = "kat-v1-fixed-key"
//	katV2Key = "kat-v2-fixed-key"
//	katPlain = "KAT fixed plaintext 1234"
//
// Vector provenance:
//
//	V1_LEGACY_ENC  = CryptoAES(V1Key).Encrypt(plain)   // no prefix, JSON-serialized
//	V2_ENC         = CryptoAESV2(V2Key).Encrypt(plain) // no prefix, raw bytes
//	MGR_ENC_V1     = Manager(default=v1, algo=V2).Encrypt(plain) // ENC:v1: prefix
import "testing"

// Fixed KAT material — mirrors the throwaway generator.
const (
	katV1Key       = "kat-v1-fixed-key"
	katV2Key       = "kat-v2-fixed-key"
	katPlain       = "KAT fixed plaintext 1234"
	katV1LegacyEnc = "432a7cd9cb1fc5475f89ff29245ef8949423581de91a1b21b37b6ffe4cf81724f2950ef0d629fea693183ce066e542176f31927ebd6c"
	katV2Enc       = "e3454cdb658ce1274c7f2d49fb66ea3f3ad50d8644375dde892cd41213ec90623bc373260659860147265bc243135c419d7b6410"
	katMgrEncV1    = "ENC:v1:652f473bfb29cfba98d06fc85008b765c0c26732a37050ab034cf43d4c04dd9e19ffb57605f429cc739a31949d0394cf81afdeb2"
)

// TestKAT_DecryptOriginalV1Legacy proves the LOCAL CryptoAES (V1, legacy,
// non-prefixed, JSON-serialized plaintext) can decrypt a ciphertext that the
// ORIGINAL ecmdb CryptoAES produced. This is the "存量 V1 legacy 密文" path.
func TestKAT_DecryptOriginalV1Legacy(t *testing.T) {
	dec, err := MustNewAESCrypto(katV1Key).Decrypt(katV1LegacyEnc)
	if err != nil {
		t.Fatalf("local V1 Decrypt of original-lib ciphertext failed: %v", err)
	}
	if dec != katPlain {
		t.Fatalf("V1 KAT mismatch: got %q, want %q", dec, katPlain)
	}
}

// TestKAT_DecryptOriginalV2 proves the LOCAL CryptoAESV2 (raw plaintext
// bytes, SHA256-derived key) can decrypt a ciphertext that the ORIGINAL
// ecmdb CryptoAESV2 produced. This is the "V2 直连" path.
func TestKAT_DecryptOriginalV2(t *testing.T) {
	dec, err := MustNewAESCryptoV2(katV2Key).Decrypt(katV2Enc)
	if err != nil {
		t.Fatalf("local V2 Decrypt of original-lib ciphertext failed: %v", err)
	}
	if dec != katPlain {
		t.Fatalf("V2 KAT mismatch: got %q, want %q", dec, katPlain)
	}
}

// TestKAT_DecryptOriginalManagerPrefix proves the LOCAL CryptoManager can
// decrypt an "ENC:v1:<hex>" ciphertext that the ORIGINAL ecmdb CryptoManager
// produced (default v1 backed by a V2 algo). This is the "Manager 前缀路由"
// path that real persisted secrets use.
func TestKAT_DecryptOriginalManagerPrefix(t *testing.T) {
	mgr := NewCryptoManager("v1").
		Register("v1", MustNewAESCryptoV2(katV2Key))

	dec, err := mgr.Decrypt(katMgrEncV1)
	if err != nil {
		t.Fatalf("local Manager Decrypt of original-lib ciphertext failed: %v", err)
	}
	if dec != katPlain {
		t.Fatalf("Manager KAT mismatch: got %q, want %q", dec, katPlain)
	}
}

// TestKAT_LegacyViaManagerFallback proves a non-prefixed V1 ciphertext from
// the ORIGINAL library is recovered through the Manager's legacy-fallback
// path (no ENC: prefix -> tryLegacyDecrypt). This mirrors real-world mixed
// stores where old rows lack the prefix.
func TestKAT_LegacyViaManagerFallback(t *testing.T) {
	mgr := NewCryptoManager("v2").
		Register("v2", MustNewAESCryptoV2(katV2Key)).
		Register("legacy", MustNewAESCrypto(katV1Key)).
		WithLegacyAlgo("legacy")

	dec, err := mgr.Decrypt(katV1LegacyEnc)
	if err != nil {
		t.Fatalf("Manager legacy fallback Decrypt failed: %v", err)
	}
	if dec != katPlain {
		t.Fatalf("Manager legacy KAT mismatch: got %q, want %q", dec, katPlain)
	}
}
