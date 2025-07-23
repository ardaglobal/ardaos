package keeper

import (
	"context"

	"arda-os/x/loan/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetInstallmentMetadata set a specific installmentMetadata in the store from its index
func (k Keeper) SetInstallmentMetadata(ctx context.Context, installmentMetadata types.InstallmentMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.InstallmentMetadataKeyPrefix))
	b := k.cdc.MustMarshal(&installmentMetadata)
	store.Set(types.InstallmentMetadataKey(
		installmentMetadata.Index,
	), b)
}

// GetInstallmentMetadata returns a installmentMetadata from its index
func (k Keeper) GetInstallmentMetadata(
	ctx context.Context,
	index string,

) (val types.InstallmentMetadata, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.InstallmentMetadataKeyPrefix))

	b := store.Get(types.InstallmentMetadataKey(
		index,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveInstallmentMetadata removes a installmentMetadata from the store
func (k Keeper) RemoveInstallmentMetadata(
	ctx context.Context,
	index string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.InstallmentMetadataKeyPrefix))
	store.Delete(types.InstallmentMetadataKey(
		index,
	))
}

// GetAllInstallmentMetadata returns all installmentMetadata
func (k Keeper) GetAllInstallmentMetadata(ctx context.Context) (list []types.InstallmentMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.InstallmentMetadataKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.InstallmentMetadata
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
