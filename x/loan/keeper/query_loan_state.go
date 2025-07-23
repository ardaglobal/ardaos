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

func (k Keeper) LoanStateAll(ctx context.Context, req *types.QueryAllLoanStateRequest) (*types.QueryAllLoanStateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var loanStates []types.LoanState

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	loanStateStore := prefix.NewStore(store, types.KeyPrefix(types.LoanStateKeyPrefix))

	pageRes, err := query.Paginate(loanStateStore, req.Pagination, func(key []byte, value []byte) error {
		var loanState types.LoanState
		if err := k.cdc.Unmarshal(value, &loanState); err != nil {
			return err
		}

		loanStates = append(loanStates, loanState)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllLoanStateResponse{LoanState: loanStates, Pagination: pageRes}, nil
}

func (k Keeper) LoanState(ctx context.Context, req *types.QueryGetLoanStateRequest) (*types.QueryGetLoanStateResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetLoanState(
		ctx,
		req.Index,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetLoanStateResponse{LoanState: val}, nil
}
