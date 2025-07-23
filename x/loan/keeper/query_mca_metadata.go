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

func (k Keeper) McaMetadataAll(ctx context.Context, req *types.QueryAllMcaMetadataRequest) (*types.QueryAllMcaMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var mcaMetadatas []types.McaMetadata

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	mcaMetadataStore := prefix.NewStore(store, types.KeyPrefix(types.McaMetadataKeyPrefix))

	pageRes, err := query.Paginate(mcaMetadataStore, req.Pagination, func(key []byte, value []byte) error {
		var mcaMetadata types.McaMetadata
		if err := k.cdc.Unmarshal(value, &mcaMetadata); err != nil {
			return err
		}

		mcaMetadatas = append(mcaMetadatas, mcaMetadata)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllMcaMetadataResponse{McaMetadata: mcaMetadatas, Pagination: pageRes}, nil
}

func (k Keeper) McaMetadata(ctx context.Context, req *types.QueryGetMcaMetadataRequest) (*types.QueryGetMcaMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetMcaMetadata(
		ctx,
		req.Index,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetMcaMetadataResponse{McaMetadata: val}, nil
}
