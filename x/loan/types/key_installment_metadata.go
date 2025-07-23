package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// InstallmentMetadataKeyPrefix is the prefix to retrieve all InstallmentMetadata
	InstallmentMetadataKeyPrefix = "InstallmentMetadata/value/"
)

// InstallmentMetadataKey returns the store key to retrieve a InstallmentMetadata from the index fields
func InstallmentMetadataKey(
	index string,
) []byte {
	var key []byte

	indexBytes := []byte(index)
	key = append(key, indexBytes...)
	key = append(key, []byte("/")...)

	return key
}
