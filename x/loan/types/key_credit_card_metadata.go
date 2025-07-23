package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// CreditCardMetadataKeyPrefix is the prefix to retrieve all CreditCardMetadata
	CreditCardMetadataKeyPrefix = "CreditCardMetadata/value/"
)

// CreditCardMetadataKey returns the store key to retrieve a CreditCardMetadata from the index fields
func CreditCardMetadataKey(
	index string,
) []byte {
	var key []byte

	indexBytes := []byte(index)
	key = append(key, indexBytes...)
	key = append(key, []byte("/")...)

	return key
}
