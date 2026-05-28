package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	ce "zk-header-verifier/contract/contracterrors"
	"zk-header-verifier/sdk"
)

func main() {}

const (
	KeyLastHeight   = "h"
	KeyBlockPrefix  = "b-"
	KeyGroth16Vk    = "vk"
	KeyVkRoot       = "vr"
	KeySp1VkeyHash  = "sp1vk"
	KeyMaxRetention = "mr"

	// W4 Cluster B CRIT #25 — cross-batch parent anchor.
	// On every successful submitProof, KeyLastBlockHash is updated to the
	// last (highest-numbered) block hash in the batch. The next batch must
	// satisfy `parsed[0].ParentHash == lastBlockHash` at the top of
	// submitProof, preventing a forged "first proof" from injecting an
	// arbitrary state. Seeded by `initContract` via the new
	// `initial_block_hash` parameter (atomic backfill at deploy time).
	KeyLastBlockHash = "lbh"

	// W4 Cluster B HIGH #22 — ELF hash pinning.
	// SHA-256 of the SP1 ELF binary the prover is expected to use. The
	// prover startup check reads this and fatal-exits on mismatch. Set
	// via `setExpectedElfHash` admin handler (Fund-affecting class,
	// 400K-block timelock — owned by Cluster B per v18 §AI).
	KeyExpectedElfHash = "elfhash"

	// W4 Cluster B CRIT #6 Site 6 enforcement: the chainId this verifier
	// instance is bound to. Set at init from InitContractParams.ExpectedChainId.
	// submitProof rejects any proof whose committed chainId (slot 11 of
	// ProofOutputs) does not equal this value — otherwise a valid SP1 proof
	// for the WRONG chain (e.g. a Sepolia proof against a mainnet verifier)
	// would be accepted and its headers stored as authoritative.
	KeyExpectedChainId = "cid"

	DefaultMaxRetention = uint64(10000)

	// Max headers per transaction. Limited by Magi's 16KB MAX_TX_SIZE.
	// Each header with RLP hex costs ~681 CBOR bytes. 12 × 681 + 1000 overhead = ~9172 bytes.
	MaxHeadersPerTx = 12

	// ProofOutputs ABI layout (alloy::abi_encode of the SP1 program's output struct).
	//
	// W4 Cluster B CRIT #6 Site 6 + W1-cluster-B-schema §1 LOCKED (v17.1 §G):
	// 12 head slots: 10 static fields (slots 0-9) + slot 10 (storageSlots
	// dynamic offset pointer) + slot 11 (chainId, NEW — appended last in the
	// sol! struct definition in sp1-helios-magi/primitives/src/types.rs).
	// This contract reads slots 5/6/7 (stateRoot/blockHash/blockNumber) for
	// legacy reads and slot 11 (chainId) for chain-binding verification.
	// PvMinLen=288 covers legacy slot 5/6/7 reads (kept for backward-compat
	// parsers that don't need chainId); PvMinLenWithChainId=416 covers the
	// full extended struct and MUST be checked before reading PvFieldChainId.
	//
	// Append-last position rationale: inserting chainId before storageSlots
	// would shift the slot-10 dynamic offset pointer and break every
	// positional decoder. Appending preserves slots 0-10 byte-for-byte.
	PvAbiOffset         = 32                  // alloy tuple head, asserted equal at runtime
	PvFieldStateRoot    = PvAbiOffset + 5*32  // 192
	PvFieldBlockHash    = PvAbiOffset + 6*32  // 224
	PvFieldBlockNumber  = PvAbiOffset + 7*32  // 256
	PvMinLen            = PvAbiOffset + 8*32  // 288 — legacy: 8 head slots fully present
	PvFieldChainId      = PvAbiOffset + 11*32 // 384 — slot 11 (chainId)
	PvMinLenWithChainId = PvAbiOffset + 12*32 // 416 — 12 head slots (covers chainId read)
)

// --- Admin actions ---

// InitContractParams — W1-cluster-B-schema §3 + v20 §BG LOCKED.
// Extended with:
//   - InitialBlockHash + InitialHeight (CRIT #25 atomic anchor backfill)
//   - IsTestnet (Cluster E clearTestnetState gate sentinel)
type InitContractParams struct {
	Groth16Vk        string `json:"groth16_vk"`
	VkRoot           string `json:"vk_root"`
	Sp1VkeyHash      string `json:"sp1_vkey_hash"`
	MaxRetention     uint64 `json:"max_retention"`
	InitialHeight    uint64 `json:"initial_height"`
	InitialBlockHash string `json:"initial_block_hash"`
	IsTestnet        bool   `json:"is_testnet"`
	// W4 Cluster B CRIT #6 Site 6: the L1 chainId this verifier is bound to
	// (e.g. 1 mainnet, 11155111 Sepolia). submitProof enforces that every
	// proof's committed chainId equals this. Required (non-zero) at init.
	ExpectedChainId uint64 `json:"expected_chain_id"`
}

//go:wasmexport init
func initContract(input *string) *string {
	checkOwner()

	// W4 Cluster B v19 §AT + v20 §BF + S-B-v18-3: one-shot re-entry guard.
	// First call (deploy-time) bypasses any timelock — submitProof cannot
	// function until init has set the vkey state, so a 14-day timelock on
	// first init would brick the bridge for 14 days. Re-entry (after any
	// vkey state already installed) is blocked entirely; subsequent vkey
	// rotations must go through updateVkey (which IS wrapped in the 400K
	// propose/execute pattern per Cluster B v18 §AF). Re-entry guard also
	// covers the case where updateVkey has run (it also writes KeyGroth16Vk)
	// — intentional, per S-B-v19-NOTABLE-3.
	if existing := sdk.StateGetObject(KeyGroth16Vk); existing != nil && *existing != "" {
		ce.Abort(ce.ErrState, "already initialized — use updateVkey (with propose/execute timelock) to rotate", "init")
	}

	var params InitContractParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "init")
	}
	if params.Groth16Vk == "" || params.VkRoot == "" || params.Sp1VkeyHash == "" {
		ce.Abort(ce.ErrInput, "groth16_vk, vk_root, and sp1_vkey_hash required", "init")
	}

	// W4 Cluster B CRIT #25 + B-B-4: require initial anchor params.
	// Without these, submitProof would either reject all proofs ("anchor
	// not set") or accept a forged batch whose ParentHash matches the
	// uninitialized zero hash. The guard closes the N2 bypass window.
	if params.InitialBlockHash == "" || params.InitialHeight == 0 {
		ce.Abort(ce.ErrInput, "initial_block_hash and initial_height required for anchor", "init")
	}
	// Sanity-check the anchor hash shape (0x-prefixed 64-hex == 32 bytes).
	if !looksLikeBlockHash(params.InitialBlockHash) {
		ce.Abort(ce.ErrInput, "initial_block_hash must be 0x-prefixed 32-byte hex", "init")
	}

	// W4 Cluster B CRIT #6 Site 6: require the bound chainId. Without it,
	// submitProof has nothing to compare provenChainId against and the
	// chain-binding fix is inert (the bug the audit found).
	if params.ExpectedChainId == 0 {
		ce.Abort(ce.ErrInput, "expected_chain_id required (non-zero) for chain-binding enforcement", "init")
	}

	sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)

	retention := params.MaxRetention
	if retention == 0 {
		retention = DefaultMaxRetention
	}
	sdk.StateSetObject(KeyMaxRetention, strconv.FormatUint(retention, 10))

	// CRIT #25 atomic anchor: seed KeyLastBlockHash and last-height so the
	// first submitProof batch must produce a header whose ParentHash equals
	// this anchor. Seeded values come from the W0 operator runbook P5 step
	// (operator selects a recent finalized L1 block, queries its hash via
	// any trusted source, includes here at deploy time).
	sdk.StateSetObject(KeyLastBlockHash, params.InitialBlockHash)
	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(params.InitialHeight, 10))

	// W4 Cluster B CRIT #6 Site 6: persist the bound chainId for submitProof
	// enforcement. Immutable after init (no setter handler — chain binding
	// must not be admin-mutable, same rationale as account-mapping dropping
	// setChainId per CRIT #6 Site 12).
	sdk.StateSetObject(KeyExpectedChainId, strconv.FormatUint(params.ExpectedChainId, 10))

	// v20 §BG: testnet sentinel for Cluster E's clearTestnetState. ABSENCE
	// of this key == mainnet; presence == testnet. Mainnet deploys MUST
	// pass IsTestnet=false; clearTestnetState reads this sentinel.
	if params.IsTestnet {
		sdk.StateSetObject("is_testnet", "true")
	}

	return nil
}

// looksLikeBlockHash — minimal shape check for InitialBlockHash. Full
// 32-byte/hex validation happens implicitly at the first submitProof
// (the comparison vs parsed[0].ParentHash will fail loudly on any
// malformed value).
func looksLikeBlockHash(s string) bool {
	if len(s) != 66 {
		return false
	}
	if s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// setExpectedElfHash — W4 Cluster B HIGH #22 Site 12 (v18 §AI + §AF):
// admin handler to pin the SHA-256 hash of the SP1 ELF binary the prover
// is allowed to use. Prover startup reads this and fatal-exits on
// mismatch. Fund-affecting class (wrong hash = bridge halt; malicious
// setExpectedElfHash + compromised prover = attacker controls all
// ZK-verified Ethereum state). Owner-gated here; the 400K-block
// propose/execute timelock wrap lives in the ZK verifier admin gates
// section (Cluster B owns this end-to-end per v18 §AF; Cluster C
// explicitly out-of-scope for ZK verifier handlers).
//
// Until the first successful setExpectedElfHash, the prover startup
// check logs a WARNING and continues — this allows a clean deploy-then-
// pin sequence during the W0 P5 ramp-up window (operator computes the
// hash from the deployed prover, then proposes/executes via the timelock).
//go:wasmexport setExpectedElfHash
func setExpectedElfHash(input *string) *string {
	checkOwner()
	var params struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "setExpectedElfHash")
	}
	// SHA-256 hex form: 64 hex chars, optionally 0x-prefixed.
	h := params.Hash
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		ce.Abort(ce.ErrInput, "hash must be 32-byte hex (64 chars, optional 0x prefix)", "setExpectedElfHash")
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			ce.Abort(ce.ErrInput, "hash contains non-hex character", "setExpectedElfHash")
		}
	}
	sdk.StateSetObject(KeyExpectedElfHash, h)
	return nil
}

//go:wasmexport updateVkey
func updateVkey(input *string) *string {
	checkOwner()
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "updateVkey")
	}
	if params.Groth16Vk != "" {
		sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	}
	if params.VkRoot != "" {
		sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	}
	if params.Sp1VkeyHash != "" {
		sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)
	}
	return nil
}

// --- Permissionless proof submission ---

type SubmitProofParams struct {
	Proof        string            `json:"proof"`
	PublicValues string            `json:"public_values"`
	Headers      []SubmittedHeader `json:"headers"`
}

// SubmittedHeader carries only the canonical RLP. All header fields are
// extracted from the RLP itself; JSON copies are not trusted.
type SubmittedHeader struct {
	RlpHex string `json:"rlp_hex"`
}

//go:wasmexport submitProof
func submitProof(input *string) *string {
	var params SubmitProofParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON: "+err.Error(), "submitProof")
	}
	if params.Proof == "" || params.PublicValues == "" || len(params.Headers) == 0 {
		ce.Abort(ce.ErrInput, "proof, public_values, and headers required", "submitProof")
	}
	if len(params.Headers) > MaxHeadersPerTx {
		ce.Abort(ce.ErrInput, "too many headers (max "+strconv.Itoa(MaxHeadersPerTx)+")", "submitProof")
	}

	// Load verification parameters
	groth16Vk := sdk.StateGetObject(KeyGroth16Vk)
	if groth16Vk == nil || *groth16Vk == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no groth16_vk", "submitProof")
	}
	vkRoot := sdk.StateGetObject(KeyVkRoot)
	if vkRoot == nil || *vkRoot == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no vk_root", "submitProof")
	}
	sp1VkeyHash := sdk.StateGetObject(KeySp1VkeyHash)
	if sp1VkeyHash == nil || *sp1VkeyHash == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no sp1_vkey_hash", "submitProof")
	}

	// 1. Verify the ZK proof
	result := sdk.Sp1VerifyGroth16(params.Proof, params.PublicValues, *sp1VkeyHash, *groth16Vk, *vkRoot)
	if result != "true" {
		ce.Abort(ce.ErrTransaction, "proof verification failed", "submitProof")
	}

	// 2. Decode publicValues to get proven block hash, number, and chainId.
	pvBytes, err := hex.DecodeString(params.PublicValues)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid public_values hex", "submitProof")
	}
	// W4 Cluster B CRIT #6 Site 6: chainId is now returned from
	// parseProvenFields (slot 11 of ProofOutputs).
	provenStateRoot, provenBlockHash, provenBlockNumber, provenChainId, perr := parseProvenFields(pvBytes)
	if perr != nil {
		ce.CustomAbort(ce.Prepend(perr, "submitProof"))
	}

	// W4 Cluster B CRIT #6 Site 6 ENFORCEMENT: reject any proof whose
	// committed chainId does not match the chainId this verifier was bound
	// to at init. Prior to this check the verifier parsed + stored
	// provenChainId but never compared it, so a valid SP1 proof generated
	// against the WRONG chain would have been accepted and its headers
	// written as authoritative — defeating the entire chain-binding fix.
	expectedChainPtr := sdk.StateGetObject(KeyExpectedChainId)
	if expectedChainPtr == nil || *expectedChainPtr == "" {
		ce.Abort(ce.ErrInitialization, "expected_chain_id not set; verifier must be initialized with expected_chain_id", "submitProof")
	}
	expectedChainId, ecErr := strconv.ParseUint(*expectedChainPtr, 10, 64)
	if ecErr != nil {
		ce.Abort(ce.ErrState, "stored expected_chain_id is not a valid uint64", "submitProof")
	}
	if provenChainId != expectedChainId {
		ce.Abort(ce.ErrTransaction, "proof chainId ("+strconv.FormatUint(provenChainId, 10)+") does not match verifier's bound chainId ("+strconv.FormatUint(expectedChainId, 10)+")", "submitProof")
	}

	// W4 Cluster B CRIT #25 — anchor check.
	// Read the cross-batch anchor BEFORE parsing headers. Without an
	// anchor (empty or zero hash), every prior submission state is
	// untrusted and a forged "first batch" could inject arbitrary state.
	// initContract MUST have set this; the InitContractParams.
	// InitialBlockHash guard at init time prevents zero-anchor deploys.
	anchorPtr := sdk.StateGetObject(KeyLastBlockHash)
	if anchorPtr == nil || *anchorPtr == "" || *anchorPtr == "0x0000000000000000000000000000000000000000000000000000000000000000" {
		ce.Abort(ce.ErrInitialization, "lastBlockHash anchor not set; call initContract with initial_block_hash", "submitProof")
	}
	anchorHex := *anchorPtr
	// Strip 0x prefix to compare against the keccak hex (which is bare hex).
	if len(anchorHex) >= 2 && (anchorHex[0:2] == "0x" || anchorHex[0:2] == "0X") {
		anchorHex = anchorHex[2:]
	}

	// 3. Parse every header from its RLP and compute keccak hashes.
	// Trust flows: proof -> provenBlockHash -> last RLP keccak -> earlier RLPs
	// via parentHash chain -> all extracted fields from each RLP.
	lastIdx := len(params.Headers) - 1
	parsed := make([]parsedHeader, len(params.Headers))
	hashes := make([]string, len(params.Headers))
	for i, h := range params.Headers {
		parsed[i] = parseHeader(h.RlpHex)
		hashes[i] = sdk.Keccak256(h.RlpHex)
	}

	// W4 Cluster B CRIT #25 — cross-batch parent check.
	// The first header in this batch MUST extend the previously-stored
	// chain at exactly `parsed[0].ParentHash == lastBlockHash`. This
	// closes the "unbound prevHeader" gap that let any well-formed proof
	// for ANY hash chain land regardless of the contract's prior history.
	if hex.EncodeToString(parsed[0].ParentHash[:]) != anchorHex {
		ce.Abort(ce.ErrTransaction, "parent hash of first header does not match stored anchor (lastBlockHash)", "submitProof")
	}

	// 4. Bind the last header's RLP and extracted fields to the proof's public inputs.
	if hashes[lastIdx] != provenBlockHash {
		ce.Abort(ce.ErrTransaction, "keccak256(last header RLP) != proven block hash", "submitProof")
	}
	if parsed[lastIdx].BlockNumber != provenBlockNumber {
		ce.Abort(ce.ErrTransaction, "last header block number ("+
			strconv.FormatUint(parsed[lastIdx].BlockNumber, 10)+
			") != proven block number ("+
			strconv.FormatUint(provenBlockNumber, 10)+")", "submitProof")
	}
	if hex.EncodeToString(parsed[lastIdx].StateRoot[:]) != provenStateRoot {
		ce.Abort(ce.ErrTransaction, "last header state_root != proven state root", "submitProof")
	}

	// 5. Walk the keccak chain backward. parentHash comes from the parsed RLP,
	// so if this passes, every earlier header's RLP is bound to a real ancestor.
	for i := lastIdx - 1; i >= 0; i-- {
		expectedParent := hex.EncodeToString(parsed[i+1].ParentHash[:])
		if expectedParent != hashes[i] {
			ce.Abort(ce.ErrTransaction, "hash chain broken at block "+
				strconv.FormatUint(parsed[i].BlockNumber, 10), "submitProof")
		}
	}

	// 6. Sequential block-number check + store the RLP-extracted fields.
	// W4 Cluster B Site 6 + §AW: every stored header gains a ChainId
	// field populated from the proven slot-11 value. This is the
	// authoritative ChainId for the EthBlockHeader the account-mapping
	// contract reads downstream (CRIT #6 Site 2 ERC-20 path).
	lastHeight := getLastHeight()
	maxRetention := getMaxRetention()
	for i := range parsed {
		p := parsed[i]
		if lastHeight > 0 && p.BlockNumber != lastHeight+1 {
			ce.Abort(ce.ErrInput, "block heights must be sequential", "submitProof")
		}
		if i > 0 && p.BlockNumber != parsed[i-1].BlockNumber+1 {
			ce.Abort(ce.ErrInput, "headers not sequential within batch", "submitProof")
		}

		storeHeader(p.BlockNumber, p.StateRoot, p.TxRoot, p.RcptRoot, p.BaseFeePerGas, p.GasLimit, p.Timestamp, provenChainId)
		lastHeight = p.BlockNumber

		if p.BlockNumber > maxRetention {
			sdk.StateDeleteObject(KeyBlockPrefix + strconv.FormatUint(p.BlockNumber-maxRetention, 10))
		}
	}

	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(lastHeight, 10))

	// W4 Cluster B CRIT #25 — update anchor for the next batch. Use the
	// hex of the last header's keccak so the next call's parsed[0].
	// ParentHash check has a canonical form to match against. Prepend 0x
	// for consistency with the InitialBlockHash format (initContract
	// validates 0x-prefixed input; stored value retains the prefix so
	// off-chain tooling reads back identical to what was supplied).
	sdk.StateSetObject(KeyLastBlockHash, "0x"+hashes[lastIdx])
	return nil
}

// --- RLP decoder ---
//
// Header field order (post-merge Ethereum, per yellow paper / EIP-1559):
//   0  parentHash         9  gasLimit
//   1  ommersHash         10 gasUsed
//   2  coinbase           11 timestamp
//   3  stateRoot          12 extraData
//   4  transactionsRoot   13 mixHash
//   5  receiptsRoot       14 nonce
//   6  logsBloom          15 baseFeePerGas
//   7  difficulty         (16+ withdrawalsRoot/blob fields ignored)
//   8  number

// parsedHeader — W4 Cluster B Site 4 + §AW disambiguation.
// ChainId field added but NOT populated by parseHeader (Ethereum RLP
// block headers have no chainId field — adding RLP extraction would be
// wrong). ChainId here is populated from parseProvenFields' return
// value (slot 11 of ProofOutputs) in submitProof, then forwarded into
// storeHeader. This struct's ChainId is informational only; the
// authoritative chainId is the function-local provenChainId that the
// submitProof loop passes into storeHeader.
type parsedHeader struct {
	BlockNumber   uint64
	ParentHash    [32]byte
	StateRoot     [32]byte
	TxRoot        [32]byte
	RcptRoot      [32]byte
	GasLimit      uint64
	Timestamp     uint64
	BaseFeePerGas uint64
	ChainId       uint64 // populated post-parseProvenFields, NOT from RLP
}

func parseHeader(rlpHex string) parsedHeader {
	rlpBytes, err := hex.DecodeString(rlpHex)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid rlp_hex", "submitProof")
	}
	payloadStart, _, _, isList := readRLPItem(rlpBytes, 0)
	if !isList {
		ce.Abort(ce.ErrInput, "rlp not a list", "submitProof")
	}
	p := payloadStart
	var h parsedHeader

	p = readBytes32(rlpBytes, p, &h.ParentHash)
	p = skipItem(rlpBytes, p) // ommersHash
	p = skipItem(rlpBytes, p) // coinbase
	p = readBytes32(rlpBytes, p, &h.StateRoot)
	p = readBytes32(rlpBytes, p, &h.TxRoot)
	p = readBytes32(rlpBytes, p, &h.RcptRoot)
	p = skipItem(rlpBytes, p) // logsBloom
	p = skipItem(rlpBytes, p) // difficulty
	p, h.BlockNumber = readUintField(rlpBytes, p)
	p, h.GasLimit = readUintField(rlpBytes, p)
	p = skipItem(rlpBytes, p) // gasUsed
	p, h.Timestamp = readUintField(rlpBytes, p)
	p = skipItem(rlpBytes, p) // extraData
	p = skipItem(rlpBytes, p) // mixHash
	p = skipItem(rlpBytes, p) // nonce
	_, h.BaseFeePerGas = readUintField(rlpBytes, p)

	return h
}

// readRLPItem returns (valueStart, valueLen, nextOffset, isList) for the RLP
// item beginning at buf[offset]. Reverts on truncated/malformed input.
func readRLPItem(buf []byte, offset int) (int, int, int, bool) {
	if offset >= len(buf) {
		ce.Abort(ce.ErrInput, "rlp truncated", "submitProof")
	}
	b := buf[offset]
	switch {
	case b < 0x80:
		// single byte 0x00..0x7f is its own encoding
		return offset, 1, offset + 1, false
	case b < 0xb8:
		l := int(b - 0x80)
		if offset+1+l > len(buf) {
			ce.Abort(ce.ErrInput, "rlp string truncated", "submitProof")
		}
		return offset + 1, l, offset + 1 + l, false
	case b < 0xc0:
		ll := int(b - 0xb7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string len truncated", "submitProof")
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string truncated", "submitProof")
		}
		return offset + 1 + ll, l, end, false
	case b < 0xf8:
		l := int(b - 0xc0)
		if offset+1+l > len(buf) {
			ce.Abort(ce.ErrInput, "rlp short-list truncated", "submitProof")
		}
		return offset + 1, l, offset + 1 + l, true
	default:
		ll := int(b - 0xf7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list len truncated", "submitProof")
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list truncated", "submitProof")
		}
		return offset + 1 + ll, l, end, true
	}
}

func readRLPLen(buf []byte) int {
	if len(buf) > 8 {
		ce.Abort(ce.ErrInput, "rlp len overflow", "submitProof")
	}
	var v int
	for _, b := range buf {
		v = (v << 8) | int(b)
	}
	return v
}

func readBytes32(buf []byte, offset int, out *[32]byte) int {
	s, l, next, isList := readRLPItem(buf, offset)
	if isList {
		ce.Abort(ce.ErrInput, "rlp expected string, got list", "submitProof")
	}
	if l != 32 {
		ce.Abort(ce.ErrInput, "rlp expected 32-byte field", "submitProof")
	}
	copy(out[:], buf[s:s+32])
	return next
}

func skipItem(buf []byte, offset int) int {
	_, _, next, _ := readRLPItem(buf, offset)
	return next
}

func readUintField(buf []byte, offset int) (int, uint64) {
	s, l, next, isList := readRLPItem(buf, offset)
	if isList {
		ce.Abort(ce.ErrInput, "rlp expected uint, got list", "submitProof")
	}
	if l > 8 {
		ce.Abort(ce.ErrInput, "rlp uint > 8 bytes", "submitProof")
	}
	var v uint64
	for i := 0; i < l; i++ {
		v = (v << 8) | uint64(buf[s+i])
	}
	return next, v
}

// --- Storage helpers ---

// HeaderVersionV1 + storeHeader — W4 Cluster B Site 4/6 unified layout.
// The serialized form MUST match the account-mapping EthBlockHeader
// serialization byte-for-byte (137 bytes total, version+128+chainId).
// account-mapping reads from this contract's KeyBlockPrefix via the
// VerifierContractIdKey indirection — any layout drift would silently
// misread chainId or baseFee.
//
// Layout (LOCKED, mirrors account-mapping/contract/blocklist/blocks.go):
//   [version:1][blockNumber:8][stateRoot:32][txRoot:32][rcptRoot:32]
//   [baseFee:8][gasLimit:8][timestamp:8][chainId:8] = 137 bytes.
const HeaderVersionV1 byte = 0x01
const HeaderSerializedSize = 137

func storeHeader(blockNumber uint64, stateRoot, txRoot, rcptRoot [32]byte, baseFee, gasLimit, timestamp, chainId uint64) {
	buf := make([]byte, 0, HeaderSerializedSize)
	buf = append(buf, HeaderVersionV1)
	buf = appendUint64(buf, blockNumber)
	buf = append(buf, stateRoot[:]...)
	buf = append(buf, txRoot[:]...)
	buf = append(buf, rcptRoot[:]...)
	buf = appendUint64(buf, baseFee)
	buf = appendUint64(buf, gasLimit)
	buf = appendUint64(buf, timestamp)
	// W4 Cluster B Site 6: appended chainId; populated from the proven
	// slot-11 value of ProofOutputs. account-mapping/blocklist/blocks.go
	// DeserializeHeader reads this at byte offset 129-136.
	buf = appendUint64(buf, chainId)
	sdk.StateSetObject(KeyBlockPrefix+strconv.FormatUint(blockNumber, 10), string(buf))
}

func getLastHeight() uint64 {
	data := sdk.StateGetObject(KeyLastHeight)
	if data == nil || *data == "" {
		return 0
	}
	h, _ := strconv.ParseUint(*data, 10, 64)
	return h
}

func getMaxRetention() uint64 {
	data := sdk.StateGetObject(KeyMaxRetention)
	if data == nil || *data == "" {
		return DefaultMaxRetention
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

func checkOwner() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.Abort(ce.ErrNoPermission, "owner required", "auth")
	}
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint64BE(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// parseProvenFields extracts (executionStateRoot, executionBlockHash,
// executionBlockNumber, chainId) from the SP1 program's ABI-encoded
// ProofOutputs bytes. Returns a non-nil *ContractError on any structural
// problem. No SDK calls — pure function, safe to test under standard
// go test (contracterrors transitively imports sdk but its construction
// path doesn't exercise any wasmimport).
//
// W4 Cluster B CRIT #6 Site 6 + S-B-v17-4 comment fix:
//   - Extended return signature adds `chainId uint64` (slot 11).
//   - Length check is split: legacy parsers see PvMinLen=288, chainId-aware
//     callers MUST pass a buffer >= PvMinLenWithChainId=416.
//   - chainId is read as uint64 big-endian from the LAST 8 bytes of the
//     32-byte ABI slot at offset PvFieldChainId (same pattern as
//     blockNumber). See sp1-helios-magi/primitives/src/types.rs for the
//     authoritative sol struct.
func parseProvenFields(pvBytes []byte) (stateRoot, blockHash string, blockNumber, chainId uint64, err *ce.ContractError) {
	if len(pvBytes) < PvMinLen {
		return "", "", 0, 0, ce.NewContractError(ce.ErrInput, "public_values too short for ABI fields")
	}
	if readUint64BE(pvBytes[24:32]) != PvAbiOffset {
		return "", "", 0, 0, ce.NewContractError(ce.ErrInput, "unexpected ABI tuple offset (expected 32)")
	}
	stateRoot = hex.EncodeToString(pvBytes[PvFieldStateRoot : PvFieldStateRoot+32])
	blockHash = hex.EncodeToString(pvBytes[PvFieldBlockHash : PvFieldBlockHash+32])
	blockNumber = readUint64BE(pvBytes[PvFieldBlockNumber+24 : PvFieldBlockNumber+32])
	// W4 Cluster B Site 6: chainId is in slot 11 (PvFieldChainId=384).
	// Require the full extended length before reading; legacy callers that
	// only need stateRoot/blockHash/blockNumber are at line above and have
	// already been served by the PvMinLen=288 check.
	if len(pvBytes) < PvMinLenWithChainId {
		return "", "", 0, 0, ce.NewContractError(ce.ErrInput, "public_values too short for chainId field")
	}
	chainId = readUint64BE(pvBytes[PvFieldChainId+24 : PvFieldChainId+32])
	return
}
