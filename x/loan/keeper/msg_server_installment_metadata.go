package keeper

import (
	"context"

	"arda-os/x/loan/types"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateInstallmentMetadata(goCtx context.Context, msg *types.MsgCreateInstallmentMetadata) (*types.MsgCreateInstallmentMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value already exists
	_, isFound := k.GetInstallmentMetadata(
		ctx,
		msg.Index,
	)
	if isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "index already set")
	}

	var installmentMetadata = types.InstallmentMetadata{
		Creator:           msg.Creator,
		Index:             msg.Index,
		LoanId:            msg.LoanId,
		PaymentAmount:     msg.PaymentAmount,
		PaymentFrequency:  msg.PaymentFrequency,
		RemainingPayments: msg.RemainingPayments,
		AmortizationType:  msg.AmortizationType,
		PrepaymentAllowed: msg.PrepaymentAllowed,
	}

	k.SetInstallmentMetadata(
		ctx,
		installmentMetadata,
	)
	return &types.MsgCreateInstallmentMetadataResponse{}, nil
}

func (k msgServer) UpdateInstallmentMetadata(goCtx context.Context, msg *types.MsgUpdateInstallmentMetadata) (*types.MsgUpdateInstallmentMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetInstallmentMetadata(
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

	var installmentMetadata = types.InstallmentMetadata{
		Creator:           msg.Creator,
		Index:             msg.Index,
		LoanId:            msg.LoanId,
		PaymentAmount:     msg.PaymentAmount,
		PaymentFrequency:  msg.PaymentFrequency,
		RemainingPayments: msg.RemainingPayments,
		AmortizationType:  msg.AmortizationType,
		PrepaymentAllowed: msg.PrepaymentAllowed,
	}

	k.SetInstallmentMetadata(ctx, installmentMetadata)

	return &types.MsgUpdateInstallmentMetadataResponse{}, nil
}

func (k msgServer) DeleteInstallmentMetadata(goCtx context.Context, msg *types.MsgDeleteInstallmentMetadata) (*types.MsgDeleteInstallmentMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetInstallmentMetadata(
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

	k.RemoveInstallmentMetadata(
		ctx,
		msg.Index,
	)

	return &types.MsgDeleteInstallmentMetadataResponse{}, nil
}
