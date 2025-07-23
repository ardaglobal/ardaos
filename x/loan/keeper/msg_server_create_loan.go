package keeper

import (
	"context"

	"arda-os/x/loan/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) CreateLoan(goCtx context.Context, msg *types.MsgCreateLoan) (*types.MsgCreateLoanResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// TODO: Handling the message
	_ = ctx

	return &types.MsgCreateLoanResponse{}, nil
}
