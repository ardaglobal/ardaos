package keeper

import (
	"context"

	"arda-os/x/loan/types"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateLoanState(goCtx context.Context, msg *types.MsgCreateLoanState) (*types.MsgCreateLoanStateResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value already exists
	_, isFound := k.GetLoanState(
		ctx,
		msg.Index,
	)
	if isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "index already set")
	}

	var loanState = types.LoanState{
		Creator:         msg.Creator,
		Index:           msg.Index,
		LoanId:          msg.LoanId,
		Status:          msg.Status,
		CurrentBalance:  msg.CurrentBalance,
		PaymentsMade:    msg.PaymentsMade,
		LastPaymentDate: msg.LastPaymentDate,
		NextPaymentDate: msg.NextPaymentDate,
		DelinquencyDays: msg.DelinquencyDays,
	}

	k.SetLoanState(
		ctx,
		loanState,
	)
	return &types.MsgCreateLoanStateResponse{}, nil
}

func (k msgServer) UpdateLoanState(goCtx context.Context, msg *types.MsgUpdateLoanState) (*types.MsgUpdateLoanStateResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetLoanState(
		ctx,
		msg.Index,
	)
	if !isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, "index not set")
	}

	// Checks if the msg creator is the same as the current owner
	if msg.Creator != valFound.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "incorrect owner")
	}

	var loanState = types.LoanState{
		Creator:         msg.Creator,
		Index:           msg.Index,
		LoanId:          msg.LoanId,
		Status:          msg.Status,
		CurrentBalance:  msg.CurrentBalance,
		PaymentsMade:    msg.PaymentsMade,
		LastPaymentDate: msg.LastPaymentDate,
		NextPaymentDate: msg.NextPaymentDate,
		DelinquencyDays: msg.DelinquencyDays,
	}

	k.SetLoanState(ctx, loanState)

	return &types.MsgUpdateLoanStateResponse{}, nil
}

func (k msgServer) DeleteLoanState(goCtx context.Context, msg *types.MsgDeleteLoanState) (*types.MsgDeleteLoanStateResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetLoanState(
		ctx,
		msg.Index,
	)
	if !isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, "index not set")
	}

	// Checks if the msg creator is the same as the current owner
	if msg.Creator != valFound.Creator {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "incorrect owner")
	}

	k.RemoveLoanState(
		ctx,
		msg.Index,
	)

	return &types.MsgDeleteLoanStateResponse{}, nil
}
