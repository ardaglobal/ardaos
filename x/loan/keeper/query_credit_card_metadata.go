package keeper

import (
	"context"

	"arda-os/x/loan/types"

	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) CreditCardMetadataAll(ctx context.Context, req *types.QueryAllCreditCardMetadataRequest) (*types.QueryAllCreditCardMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var creditCardMetadatas []types.CreditCardMetadata

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	creditCardMetadataStore := prefix.NewStore(store, types.KeyPrefix(types.CreditCardMetadataKeyPrefix))

	pageRes, err := query.Paginate(creditCardMetadataStore, req.Pagination, func(key []byte, value []byte) error {
		var creditCardMetadata types.CreditCardMetadata
		if err := k.cdc.Unmarshal(value, &creditCardMetadata); err != nil {
			return err
		}

		creditCardMetadatas = append(creditCardMetadatas, creditCardMetadata)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllCreditCardMetadataResponse{CreditCardMetadata: creditCardMetadatas, Pagination: pageRes}, nil
}

func (k Keeper) CreditCardMetadata(ctx context.Context, req *types.QueryGetCreditCardMetadataRequest) (*types.QueryGetCreditCardMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetCreditCardMetadata(
		ctx,
		req.Index,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetCreditCardMetadataResponse{CreditCardMetadata: val}, nil
}
