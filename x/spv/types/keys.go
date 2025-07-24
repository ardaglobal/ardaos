package types

const (
	// ModuleName defines the module name
	ModuleName = "spv"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_spv"
)

var (
	ParamsKey = []byte("p_spv")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
