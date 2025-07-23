package keeper

import (
	"context"

	"arda-os/x/loan/types"

	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/runtime"
)

// SetLoanState set a specific loanState in the store from its index
func (k Keeper) SetLoanState(ctx context.Context, loanState types.LoanState) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.LoanStateKeyPrefix))
	b := k.cdc.MustMarshal(&loanState)
	store.Set(types.LoanStateKey(
		loanState.Index,
	), b)
}

// GetLoanState returns a loanState from its index
func (k Keeper) GetLoanState(
	ctx context.Context,
	index string,

) (val types.LoanState, found bool) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.LoanStateKeyPrefix))

	b := store.Get(types.LoanStateKey(
		index,
	))
	if b == nil {
		return val, false
	}

	k.cdc.MustUnmarshal(b, &val)
	return val, true
}

// RemoveLoanState removes a loanState from the store
func (k Keeper) RemoveLoanState(
	ctx context.Context,
	index string,

) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.LoanStateKeyPrefix))
	store.Delete(types.LoanStateKey(
		index,
	))
}

// GetAllLoanState returns all loanState
func (k Keeper) GetAllLoanState(ctx context.Context) (list []types.LoanState) {
	storeAdapter := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	store := prefix.NewStore(storeAdapter, types.KeyPrefix(types.LoanStateKeyPrefix))
	iterator := storetypes.KVStorePrefixIterator(store, []byte{})

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var val types.LoanState
		k.cdc.MustUnmarshal(iterator.Value(), &val)
		list = append(list, val)
	}

	return
}
