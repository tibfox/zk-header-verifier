package main

import (
	"encoding/hex"
	"testing"

	ce "zk-header-verifier/contract/contracterrors"
)

// Real SP1-Helios v6.1.0 ABI-encoded ProofOutputs for Sepolia block 10764834.
// Sourced from go-vsc-node modules/wasm/sdk/sp1_verifier_test.go.
//
// This is a legacy (pre-chainId) encoding: 13 ABI slots (416 bytes) whose
// final field is an EMPTY storageSlots[] dynamic array — slot 11 (byte 352)
// holds its offset pointer (0x160) and slot 12 (byte 384) holds its length
// (0). It predates W4 Cluster B Site 5's chainId extension and carries no
// chainId commitment.
//
// Watch the collision: the empty-array length slot lands exactly at
// PvFieldChainId (byte 384), and the corpus is exactly PvMinLenWithChainId
// (416) bytes. So parseProvenFields cannot reject this on length — it
// succeeds and reads chainId == 0 (the array length). Length alone cannot
// distinguish a legacy proof from a new one; only the SP1 verifying key
// can. A legacy proof is still rejected, downstream: submitProof compares
// the (zero) provenChainId against the verifier's bound chainId — forced
// non-zero at init — and aborts with ErrTransaction. When a rebuilt prover
// emits a real chainId, commit a new fixture and add a test asserting the
// expected non-zero value.
const v6_1_0_PublicValuesHex = "00000000000000000000000000000000000000000000000000000000000000201024268bf088fa5770d276017f20a3fa4e0cc13c5f854b3a8b1f791cc1b85c3a00000000000000000000000000000000000000000000000000000000009af1e04577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d00000000000000000000000000000000000000000000000000000000009af220999525d0726b588e6cc9bd6841eb5393bc0b5137d980b30f8ed136efdd8a348e6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf0000000000000000000000000000000000000000000000000000000000a442224577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d4293e591071f6fb96e4a99a578693578bf4a9125c17b20abb845d3861c248ee000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000"

const (
	expectedStateRoot   = "6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e"
	expectedBlockHash   = "7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf"
	expectedBlockNumber = uint64(10764834) // 0xa44222
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// Golden decode of parseProvenFields against a REAL alloy-abi-encoded
// ProofOutputs blob — the only parser test that does. The other parser
// tests plant bytes at the same offset constant they read back
// (e.g. pv[PvFieldBlockNumber+31] then read via PvFieldBlockNumber), so a
// wrong offset shifts write and read together and goes undetected. The
// known-good stateRoot/blockHash/blockNumber below are the sole non-circular
// anchor for those security-critical offsets.
//
// chainId is intentionally not asserted: this corpus predates the chainId
// extension, so PvFieldChainId reads the empty storageSlots[] length (0),
// not a committed chainId. There is no meaningful invariant to pin there —
// see the const block above. A real chainId needs a fixture from a rebuilt
// prover.
func TestParseProvenFields_DecodesRealV6_1_0Corpus(t *testing.T) {
	pv := mustDecodeHex(t, v6_1_0_PublicValuesHex)
	stateRoot, blockHash, blockNumber, _, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error parsing real corpus: %v", err)
	}
	if stateRoot != expectedStateRoot {
		t.Errorf("stateRoot = %q, want %q", stateRoot, expectedStateRoot)
	}
	if blockHash != expectedBlockHash {
		t.Errorf("blockHash = %q, want %q", blockHash, expectedBlockHash)
	}
	if blockNumber != expectedBlockNumber {
		t.Errorf("blockNumber = %d, want %d", blockNumber, expectedBlockNumber)
	}
}

func TestParseProvenFields_TooShort(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one byte short of legacy minimum", PvMinLen - 1},
		{"only the offset prefix", 32},
		{"legacy boundary exact", PvMinLen}, // post-extension, this now triggers PvMinLenWithChainId rejection
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv := make([]byte, tt.size)
			if tt.size >= 32 {
				pv[31] = byte(PvAbiOffset) // valid offset so length is the only failure mode
			}
			_, _, _, _, err := parseProvenFields(pv)
			if err == nil {
				t.Fatal("expected error for short input, got none")
			}
			if err.Symbol != ce.ErrInput {
				t.Errorf("symbol = %q, want ErrInput", err.Symbol)
			}
		})
	}
}

func TestParseProvenFields_WrongAbiOffset(t *testing.T) {
	pv := make([]byte, PvMinLenWithChainId)
	// Build a fully-sized buffer but with a wrong offset prefix.
	pv[31] = 0x40

	_, _, _, _, err := parseProvenFields(pv)
	if err == nil {
		t.Fatal("expected error for non-32 ABI offset, got none")
	}
	if err.Symbol != ce.ErrInput {
		t.Errorf("symbol = %q, want ErrInput", err.Symbol)
	}
}

// W4 Cluster B Site 6: boundary check at exactly PvMinLenWithChainId
// with a plausibly-shaped offset+blockNumber+chainId.
func TestParseProvenFields_BoundaryWithChainId(t *testing.T) {
	pv := make([]byte, PvMinLenWithChainId)
	pv[31] = byte(PvAbiOffset) // offset = 32
	// Plant a recognizable block number at the right offset.
	pv[PvFieldBlockNumber+31] = 0x42
	// Plant a chainId at slot 11 — last 8 bytes of [384:416].
	pv[PvFieldChainId+31] = 0x01 // chainId = 1 (mainnet)

	_, _, blockNumber, chainId, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error at PvMinLenWithChainId boundary: %v", err)
	}
	if blockNumber != 0x42 {
		t.Errorf("blockNumber = %d, want 0x42", blockNumber)
	}
	if chainId != 1 {
		t.Errorf("chainId = %d, want 1", chainId)
	}
}

// W4 Cluster B HIGH #22: sanity test on the looksLikeBlockHash shape
// check used by initContract to reject obviously-malformed anchors.
func TestLooksLikeBlockHash(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"0x0000000000000000000000000000000000000000000000000000000000000000", true},
		{"0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},
		{"0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", true},
		{"", false},
		{"0x", false},
		{"0xabcd", false},   // too short
		{"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false}, // no 0x prefix
		{"0xZZZ_def0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false}, // non-hex char
	}
	for _, tt := range tests {
		if got := looksLikeBlockHash(tt.s); got != tt.want {
			t.Errorf("looksLikeBlockHash(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
