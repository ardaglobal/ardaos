package keeper

import (
	"context"

	"arda-os/x/loan/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetMcaMetadata set a specific mcaMetadata in the store from its index
func (k Keeper) SetMcaMetadata(ctx context.Context, mcaMetadata types.McaMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.McaMetadataKeyPrefix))
	b := k.cdc.MustMarshal(&mcaMetadata)
	store.Set(types.McaMetadataKey(
		mcaMetadata.Index,
	), b)
}

// GetMcaMetadata returns a mcaMetadata from its index
func (k Keeper) GetMcaMetadata(
	ctx context.Context,
	index string,

) (val types.McaMetadata, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.McaMetadataKeyPrefix))

	b := store.Get(types.McaMetadataKey(
		index,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveMcaMetadata removes a mcaMetadata from the store
func (k Keeper) RemoveMcaMetadata(
	ctx context.Context,
	index string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.McaMetadataKeyPrefix))
	store.Delete(types.McaMetadataKey(
		index,
	))
}

// GetAllMcaMetadata returns all mcaMetadata
func (k Keeper) GetAllMcaMetadata(ctx context.Context) (list []types.McaMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.McaMetadataKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.McaMetadata
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
