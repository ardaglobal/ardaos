package types

const (
	// ModuleName defines the module name
	ModuleName = "ardaus"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_ardaus"
)

var (
	ParamsKey = []byte("p_ardaus")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
