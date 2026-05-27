package contracterrors

import (
	"errors"
	"strings"
	"zk-header-verifier/sdk"
)

type ErrorSymbol string

// Errors
const (
	ErrJson           = ErrorSymbol("json_error")
	ErrStateAccess    = ErrorSymbol("state_access_error")
	ErrAuth           = ErrorSymbol("authentication_error")
	ErrNoPermission   = ErrorSymbol("no_permission")
	ErrInput          = ErrorSymbol("bad_input")
	ErrInvalidHex     = ErrorSymbol("invalid_hex")
	ErrInitialization = ErrorSymbol("contract_not_initialized")
	ErrState          = ErrorSymbol("invalid_state_transition")
	ErrIntent         = ErrorSymbol("intent_error")
	ErrBalance        = ErrorSymbol("insufficient_balance")
	ErrArithmetic     = ErrorSymbol("overflow_underflow")
	ErrTransaction    = ErrorSymbol("transaction_error")
)

const (
	MsgNoPublicKey = "no registered public key"
	MsgBadInput    = "error unmarshalling input"
)

const (
	errMsgActiveAuth = "active auth required to move funds"
)

type ContractError struct {
	Symbol ErrorSymbol
	Msg    string
}

func (es ErrorSymbol) String() string {
	return string(es)
}

func (e *ContractError) Error() string {
	return e.Symbol.String() + ": " + e.Msg
}

// Is enables errors.Is(err, sentinel) for ContractError sentinels by comparing
// Symbol + Msg instead of pointer identity. Without this, errors.Is degrades
// to pointer equality — fine for direct sentinel returns, but silently wrong
// for any future case where the value has been copied or rebuilt.
func (e *ContractError) Is(target error) bool {
	t, ok := target.(*ContractError)
	if !ok {
		return false
	}
	return e.Symbol == t.Symbol && e.Msg == t.Msg
}

func buildString(prepends []string, msg string) string {
	if len(prepends) == 0 {
		return msg
	}

	var b strings.Builder

	totalLen := len(msg) + (len(prepends) * 2)
	for _, s := range prepends {
		totalLen += len(s)
	}
	b.Grow(totalLen)

	for _, s := range prepends {
		b.WriteString(s)
		b.WriteString(": ")
	}
	b.WriteString(msg)
	return b.String()
}

func NewContractError(symbol ErrorSymbol, msg string, prepends ...string) *ContractError {
	newMsg := buildString(prepends, msg)
	return &ContractError{
		Symbol: symbol,
		Msg:    newMsg,
	}
}

func WrapContractError(symbol ErrorSymbol, err error, prepends ...string) *ContractError {
	var newMsg string
	if err != nil {
		newMsg = buildString(prepends, err.Error())
	}
	return &ContractError{
		Symbol: symbol,
		Msg:    newMsg,
	}
}

func Prepend(err error, prepends ...string) error {
	if len(prepends) == 0 {
		return err
	}

	var origMsg string
	cErr, isCErr := err.(*ContractError)
	if isCErr {
		origMsg = cErr.Msg
	} else {
		origMsg = err.Error()
	}

	newMsg := buildString(prepends, origMsg)
	if isCErr {
		cErr.Msg = newMsg
		return cErr
	} else {
		return errors.New(newMsg)
	}
}

func CustomAbort(err error) {
	if cErr, ok := err.(*ContractError); ok {
		if cErr.Symbol != "" {
			sdk.Revert(cErr.Msg, cErr.Symbol.String())
		} else {
			sdk.Abort(cErr.Msg)
		}
	} else {
		sdk.Abort(err.Error())
	}
}

// Abort is a one-call convenience for sites that previously called sdk.Revert("msg", "ctx").
// Builds a ContractError with the given symbol and aborts. Prepends are joined into the
// message exactly like NewContractError, so passing the action name (e.g. "submitProof")
// reproduces the old context prefix while moving the symbol into Revert's symbol slot.
func Abort(symbol ErrorSymbol, msg string, prepends ...string) {
	CustomAbort(NewContractError(symbol, msg, prepends...))
}

/*
NOTES:

ce.Prepend(err, ...) mutates cErr.Msg in place. If a package-level sentinel like
ErrInvalidProof is passed to Prepend, the singleton gets corrupted globally and all
subsequent errors.Is(_, ErrInvalidProof) checks break with no warning.

Unwrap for WrapContractError. Right now WrapContractError(symbol, inner, ...) flattens
inner to a string and discards the original error pointer. errors.Is(wrapped, innerSentinel)
therefore returns false. errors.Is could walk the wrap chain, WrapContractError
would need to keep the inner error as a field and add an Unwrap() method. Not done because
it would create extra pointers in a allocate-only memory environment.
*/
