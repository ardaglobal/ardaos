package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// LoanStateKeyPrefix is the prefix to retrieve all LoanState
	LoanStateKeyPrefix = "LoanState/value/"
)

// LoanStateKey returns the store key to retrieve a LoanState from the index fields
func LoanStateKey(
	index string,
) []byte {
	var key []byte

	indexBytes := []byte(index)
	key = append(key, indexBytes...)
	key = append(key, []byte("/")...)

	return key
}
