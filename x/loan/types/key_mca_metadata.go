package types

import "encoding/binary"

var _ binary.ByteOrder

const (
	// McaMetadataKeyPrefix is the prefix to retrieve all McaMetadata
	McaMetadataKeyPrefix = "McaMetadata/value/"
)

// McaMetadataKey returns the store key to retrieve a McaMetadata from the index fields
func McaMetadataKey(
	index string,
) []byte {
	var key []byte

	indexBytes := []byte(index)
	key = append(key, indexBytes...)
	key = append(key, []byte("/")...)

	return key
}
