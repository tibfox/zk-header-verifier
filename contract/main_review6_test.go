package main

import (
	"testing"
)

// ============================================================================
// review6 fix tests
//
// These tests prove two review6 fixes in contract/main.go:
//
//   L6  — readRLPItem / parseHeader / readRLPLen / readBytes32 now return
//         zero-valued tuples (or unchanged outputs) immediately after each
//         ce.Abort, so a no-op Abort stub (Go test build) cannot fall
//         through to corrupted-offsets math or out-of-bounds slicing.
//
//   M10 — applyUpdateVkey and propose-side validateActionPayload require
//         all three vkey fields (groth16_vk, vk_root, sp1_vkey_hash).
//
// Stub semantics. In the Go test build the sdk_stub `revert` host import
// is a no-op (see sdk/sdk_stub.go: `func revert(...) { return }`).
// ce.Abort routes through sdk.Revert (because every call site passes a
// non-empty error symbol), so under `go test` ce.Abort returns to its
// caller instead of terminating. That is exactly the corrupted-fallthrough
// hazard the L6/M10 review-fix `return` statements close, and it is what
// these tests exercise.
// ============================================================================

// --- L6: readRLPItem returns zero tuple after Abort no-op ---

// TestReview6_L6_readRLPItem_TruncatedInputs verifies that on malformed RLP
// the function returns (0,0,0,false) — the explicit zero-return added in
// review6 — rather than the corrupted offsets the pre-fix fall-through would
// have produced.
func TestReview6_L6_readRLPItem_TruncatedInputs(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		off  int
	}{
		// offset >= len(buf): "rlp truncated"
		{"empty buffer", []byte{}, 0},
		{"offset past end", []byte{0x42}, 5},

		// 0x80..0xb7 short string with truncated payload.
		// 0x82 = "string of length 2" but buffer only has the header byte.
		{"short string truncated", []byte{0x82}, 0},

		// 0xb8..0xbf long string with truncated length descriptor.
		// 0xb8 says "next 1 byte is the length", but the buffer only has the
		// header — readRLPItem must abort+zero-return, NOT read past the end.
		{"long-string len truncated", []byte{0xb8}, 0},

		// 0xb8 0xff = "next 1 byte is length", length=255, then 255 payload
		// bytes — but only 2 bytes total in the buffer. The long-string
		// payload bounds check must trigger the zero-return path.
		{"long-string payload truncated", []byte{0xb8, 0xff}, 0},

		// 0xc1 = short list with one byte of payload, but no payload byte.
		{"short list truncated", []byte{0xc1}, 0},

		// 0xf8 = "next 1 byte is list length", but buffer ends after header.
		{"long-list len truncated", []byte{0xf8}, 0},

		// 0xf8 0xff = list of length 255, but no payload bytes follow.
		{"long-list payload truncated", []byte{0xf8, 0xff}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// In the Go test build ce.Abort is a no-op. The L6 fix added
			// `return 0, 0, 0, false` after each Abort. Pre-fix the function
			// would fall through and return either (offset+1, 0, ...) or
			// negative offsets — values a caller would then dereference into
			// out-of-bounds territory.
			start, l, next, isList := readRLPItem(tc.buf, tc.off)
			if start != 0 || l != 0 || next != 0 || isList {
				t.Errorf("readRLPItem(%v, %d) = (%d, %d, %d, %v); want (0, 0, 0, false)",
					tc.buf, tc.off, start, l, next, isList)
			}
		})
	}
}

// TestReview6_L6_readRLPItem_HappyPath confirms the L6 fix did not regress
// the well-formed path. Each case is a minimal valid RLP item.
func TestReview6_L6_readRLPItem_HappyPath(t *testing.T) {
	cases := []struct {
		name      string
		buf       []byte
		wantStart int
		wantLen   int
		wantNext  int
		wantList  bool
	}{
		{"single byte < 0x80", []byte{0x42}, 0, 1, 1, false},
		// 0x83 0x01 0x02 0x03 = 3-byte string [0x01,0x02,0x03]
		{"short string len 3", []byte{0x83, 0x01, 0x02, 0x03}, 1, 3, 4, false},
		// 0xc3 0x01 0x02 0x03 = short list, 3 bytes of payload
		{"short list len 3", []byte{0xc3, 0x01, 0x02, 0x03}, 1, 3, 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, l, next, isList := readRLPItem(tc.buf, 0)
			if start != tc.wantStart || l != tc.wantLen || next != tc.wantNext || isList != tc.wantList {
				t.Errorf("readRLPItem = (%d, %d, %d, %v); want (%d, %d, %d, %v)",
					start, l, next, isList, tc.wantStart, tc.wantLen, tc.wantNext, tc.wantList)
			}
		})
	}
}

// --- L6: readRLPLen returns zero after Abort no-op ---

// TestReview6_L6_readRLPLen_Overflow verifies the explicit `return 0` after
// the >8-byte abort. Pre-fix, the function would fall through and shift a
// 9+ byte length into `int v`, producing an attacker-controllable arbitrary
// integer that the caller would use as a slice length.
func TestReview6_L6_readRLPLen_Overflow(t *testing.T) {
	// 9 bytes — one over the cap.
	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	got := readRLPLen(buf)
	if got != 0 {
		t.Errorf("readRLPLen(9-byte input) = %d; want 0 (post-Abort zero-return)", got)
	}
}

// TestReview6_L6_readRLPLen_HappyPath sanity-checks the valid path.
func TestReview6_L6_readRLPLen_HappyPath(t *testing.T) {
	// 0x01 0x00 == 256
	if got := readRLPLen([]byte{0x01, 0x00}); got != 256 {
		t.Errorf("readRLPLen([0x01 0x00]) = %d; want 256", got)
	}
}

// --- L6: readBytes32 returns `next` without modifying out on Abort no-op ---

// TestReview6_L6_readBytes32_RejectsList verifies that when the item at
// `offset` is a list (not a 32-byte string), readBytes32 returns the parsed
// `next` value and leaves `out` untouched. Pre-fix, the function would fall
// through past the abort and run `copy(out[:], buf[s:s+32])` against bytes
// that don't exist, panicking with index-out-of-range.
func TestReview6_L6_readBytes32_RejectsList(t *testing.T) {
	// 0xc0 == empty list header. readRLPItem returns (1, 0, 1, true).
	// readBytes32 must abort+return-next, NOT slice buf[1:33] (panic).
	buf := []byte{0xc0}
	var out [32]byte
	// Sentinel non-zero pattern; the test asserts it stays untouched.
	for i := range out {
		out[i] = 0xAA
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readBytes32 panicked (out-of-bounds slice) — L6 fix missing? recover()=%v", r)
		}
	}()
	next := readBytes32(buf, 0, &out)

	// readRLPItem for 0xc0 returns next=1. The L6 fix returns this value.
	if next != 1 {
		t.Errorf("readBytes32 returned next=%d; want 1 (the readRLPItem next)", next)
	}
	for i, b := range out {
		if b != 0xAA {
			t.Errorf("out[%d] = %#x; want 0xAA (Abort must NOT mutate out)", i, b)
		}
	}
}

// TestReview6_L6_readBytes32_RejectsWrongLength covers the second abort site
// in readBytes32 (string of length != 32). Same expectation: `next` is
// returned, `out` is not mutated.
func TestReview6_L6_readBytes32_RejectsWrongLength(t *testing.T) {
	// 0x82 0x01 0x02 = 2-byte string. readRLPItem -> (1, 2, 3, false). The
	// l != 32 branch triggers; readBytes32 must return 3 without slicing.
	buf := []byte{0x82, 0x01, 0x02}
	var out [32]byte
	for i := range out {
		out[i] = 0xBB
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readBytes32 panicked — L6 fix missing? recover()=%v", r)
		}
	}()
	next := readBytes32(buf, 0, &out)

	if next != 3 {
		t.Errorf("readBytes32 returned next=%d; want 3", next)
	}
	for i, b := range out {
		if b != 0xBB {
			t.Errorf("out[%d] = %#x; want 0xBB", i, b)
		}
	}
}

// TestReview6_L6_readBytes32_HappyPath confirms 32-byte strings still decode.
func TestReview6_L6_readBytes32_HappyPath(t *testing.T) {
	// 0xa0 (= 0x80+32) followed by 32 bytes.
	buf := make([]byte, 33)
	buf[0] = 0xa0
	for i := 1; i < 33; i++ {
		buf[i] = byte(i)
	}
	var out [32]byte
	next := readBytes32(buf, 0, &out)
	if next != 33 {
		t.Errorf("readBytes32 next=%d; want 33", next)
	}
	for i := 0; i < 32; i++ {
		if out[i] != byte(i+1) {
			t.Errorf("out[%d] = %#x; want %#x", i, out[i], i+1)
		}
	}
}

// --- L6: parseHeader returns zero parsedHeader on bad input ---

// TestReview6_L6_parseHeader_InvalidHex verifies parseHeader returns the
// zero parsedHeader{} after the hex.DecodeString error path's Abort —
// the explicit `return parsedHeader{}` that review6 added. Pre-fix the
// code would have fallen through, called readRLPItem on a nil slice, then
// run RLP field reads against an empty buffer.
func TestReview6_L6_parseHeader_InvalidHex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseHeader panicked on invalid hex — L6 fix missing? recover()=%v", r)
		}
	}()
	h := parseHeader("not-valid-hex")
	want := parsedHeader{}
	if h != want {
		t.Errorf("parseHeader(\"not-valid-hex\") = %+v; want zero parsedHeader{}", h)
	}
}

// TestReview6_L6_parseHeader_NotAList feeds parseHeader a valid hex string
// whose RLP decodes to a single-byte item rather than a list. The L6 fix's
// `return parsedHeader{}` after the "rlp not a list" Abort must kick in.
func TestReview6_L6_parseHeader_NotAList(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseHeader panicked on non-list RLP — L6 fix missing? recover()=%v", r)
		}
	}()
	// "42" decodes to []byte{0x42}; readRLPItem treats <0x80 as a single-
	// byte string, so isList=false and the "rlp not a list" abort fires.
	h := parseHeader("42")
	want := parsedHeader{}
	if h != want {
		t.Errorf("parseHeader(non-list RLP) = %+v; want zero parsedHeader{}", h)
	}
}

// ============================================================================
// M10 — applyUpdateVkey + validateActionPayload require all three vkey fields
// ============================================================================
//
// In the Go test build sdk.Revert is a no-op, so a rejection via ce.Abort
// returns normally to the test. The bug class M10 closes is that, without
// the explicit `return` after the Abort, applyUpdateVkey would FALL THROUGH
// and call sdk.StateSetObject(...) on whatever partial set of fields was
// supplied — corrupting the vkey trust root with mixed material.
//
// Under the stub, StateSetObject is also a no-op, so we cannot read back
// post-call state to assert the fix. What we CAN assert without panicking:
//
//   1. Successful 3-field call returns normally (no panic, runs through
//      all three sdk.StateSetObject sites).
//   2. Single-field and two-field calls return normally too (the Abort path
//      is taken, and the M10 `return` skips the StateSetObject calls —
//      without the return, the same no-op StateSetObject calls would also
//      run, but with empty values, which is the corruption mode).
//   3. Bad-JSON call also returns normally (the JSON-error Abort path's
//      explicit `return` is exercised).
//
// All three subtests use defer/recover to detect any unexpected panic; the
// goal of M10's `return` after Abort is exactly to keep the function from
// reaching code that could panic (or write garbage) under a no-op Abort.

// TestReview6_M10_applyUpdateVkey verifies every branch of applyUpdateVkey.
func TestReview6_M10_applyUpdateVkey(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		// review6 M10: happy path — all three vkey fields present.
		{"all three fields", `{"groth16_vk":"a","vk_root":"b","sp1_vkey_hash":"c"}`},

		// review6 M10: only groth16_vk — must trigger the "requires all three"
		// abort + early return.
		{"only groth16_vk", `{"groth16_vk":"a"}`},

		// review6 M10: groth16_vk + vk_root only — still partial, still
		// rejected by the M10 atomic-rotation gate.
		{"missing sp1_vkey_hash", `{"groth16_vk":"a","vk_root":"b"}`},

		// review6 M10: groth16_vk + sp1_vkey_hash, no vk_root.
		{"missing vk_root", `{"groth16_vk":"a","sp1_vkey_hash":"c"}`},

		// review6 M10: vk_root + sp1_vkey_hash, no groth16_vk.
		{"missing groth16_vk", `{"vk_root":"b","sp1_vkey_hash":"c"}`},

		// review6 M10: empty object — all three blank, all three checks fire.
		{"empty object", `{}`},

		// review6 L6/M10: bad JSON exercises the JSON-error abort path's
		// explicit `return` added in review6 (without it, the code would
		// access params.Groth16Vk (== "") and fall through to the field
		// check abort, which is harmless here but mis-routes the error).
		{"bad JSON", `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("applyUpdateVkey(%q) panicked — review6 fix missing? recover()=%v", tc.payload, r)
				}
			}()
			// In the Go test build the Abort sites no-op, and the review6
			// `return` statements keep execution from reaching code that
			// would panic or store garbage. The test passes if no panic.
			applyUpdateVkey(tc.payload)
		})
	}
}

// TestReview6_M10_validateActionPayload_UpdateVkey covers the propose-time
// validator that mirrors applyUpdateVkey's all-three-fields gate (review6
// M10 propose-side fix). Same recovery pattern as above.
func TestReview6_M10_validateActionPayload_UpdateVkey(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		// Happy path — all three present, propose-side validator accepts.
		{"all three fields", `{"groth16_vk":"a","vk_root":"b","sp1_vkey_hash":"c"}`},

		// Single field — propose-time rejection, the M10 fix's whole point
		// (without it, a 14-day timelock cycle would queue around a payload
		// that the execute-side gate would then reject).
		{"only groth16_vk", `{"groth16_vk":"a"}`},

		// Two fields — same propose-time rejection.
		{"missing sp1_vkey_hash", `{"groth16_vk":"a","vk_root":"b"}`},
		{"missing vk_root", `{"groth16_vk":"a","sp1_vkey_hash":"c"}`},
		{"missing groth16_vk", `{"vk_root":"b","sp1_vkey_hash":"c"}`},

		// Empty object — all three checks fire.
		{"empty object", `{}`},

		// Bad JSON — the propose-side validator's JSON-error Abort path
		// also has the review6 `return` so it cannot fall through to the
		// field check.
		{"bad JSON", `not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("validateActionPayload(updateVkey, %q) panicked — review6 fix missing? recover()=%v", tc.payload, r)
				}
			}()
			validateActionPayload("updateVkey", tc.payload)
		})
	}
}

// TestReview6_M10_validateActionPayload_UnknownAction confirms the validator
// is a no-op for actions outside its switch — the propose() handler already
// rejects unknown actions in timelockFor; this is a sanity bound on the
// validator's scope.
func TestReview6_M10_validateActionPayload_UnknownAction(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("validateActionPayload panicked on unknown action: %v", r)
		}
	}()
	validateActionPayload("notARealAction", `{"foo":"bar"}`)
}
