package types

const (
	// ModuleName defines the module name
	ModuleName = "vault"

	// StoreKey defines the primary module store key
	StoreKey = ModuleName

	// MemStoreKey defines the in-memory store key
	MemStoreKey = "mem_vault"
)

var (
	ParamsKey = []byte("p_vault")
)

func KeyPrefix(p string) []byte {
	return []byte(p)
}
