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

func (k Keeper) InstallmentMetadataAll(ctx context.Context, req *types.QueryAllInstallmentMetadataRequest) (*types.QueryAllInstallmentMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var installmentMetadatas []types.InstallmentMetadata

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	installmentMetadataStore := prefix.NewStore(store, types.KeyPrefix(types.InstallmentMetadataKeyPrefix))

	pageRes, err := query.Paginate(installmentMetadataStore, req.Pagination, func(key []byte, value []byte) error {
		var installmentMetadata types.InstallmentMetadata
		if err := k.cdc.Unmarshal(value, &installmentMetadata); err != nil {
			return err
		}

		installmentMetadatas = append(installmentMetadatas, installmentMetadata)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllInstallmentMetadataResponse{InstallmentMetadata: installmentMetadatas, Pagination: pageRes}, nil
}

func (k Keeper) InstallmentMetadata(ctx context.Context, req *types.QueryGetInstallmentMetadataRequest) (*types.QueryGetInstallmentMetadataResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetInstallmentMetadata(
		ctx,
		req.Index,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetInstallmentMetadataResponse{InstallmentMetadata: val}, nil
}
