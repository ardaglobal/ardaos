package keeper

import (
	"context"

	"arda-os/x/loan/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetCreditCardMetadata set a specific creditCardMetadata in the store from its index
func (k Keeper) SetCreditCardMetadata(ctx context.Context, creditCardMetadata types.CreditCardMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CreditCardMetadataKeyPrefix))
	b := k.cdc.MustMarshal(&creditCardMetadata)
	store.Set(types.CreditCardMetadataKey(
		creditCardMetadata.Index,
	), b)
}

// GetCreditCardMetadata returns a creditCardMetadata from its index
func (k Keeper) GetCreditCardMetadata(
	ctx context.Context,
	index string,

) (val types.CreditCardMetadata, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CreditCardMetadataKeyPrefix))

	b := store.Get(types.CreditCardMetadataKey(
		index,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveCreditCardMetadata removes a creditCardMetadata from the store
func (k Keeper) RemoveCreditCardMetadata(
	ctx context.Context,
	index string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CreditCardMetadataKeyPrefix))
	store.Delete(types.CreditCardMetadataKey(
		index,
	))
}

// GetAllCreditCardMetadata returns all creditCardMetadata
func (k Keeper) GetAllCreditCardMetadata(ctx context.Context) (list []types.CreditCardMetadata) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.CreditCardMetadataKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.CreditCardMetadata
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
