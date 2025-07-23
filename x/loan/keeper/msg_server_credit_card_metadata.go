package keeper

import (
	"context"

	"arda-os/x/loan/types"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateCreditCardMetadata(goCtx context.Context, msg *types.MsgCreateCreditCardMetadata) (*types.MsgCreateCreditCardMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value already exists
	_, isFound := k.GetCreditCardMetadata(
		ctx,
		msg.Index,
	)
	if isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "index already set")
	}

	var creditCardMetadata = types.CreditCardMetadata{
		Creator:         msg.Creator,
		Index:           msg.Index,
		LoanId:          msg.LoanId,
		CreditLimit:     msg.CreditLimit,
		AvailableCredit: msg.AvailableCredit,
		MinimumPayment:  msg.MinimumPayment,
		DailyRate:       msg.DailyRate,
		GracePeriodDays: msg.GracePeriodDays,
		OverlimitFee:    msg.OverlimitFee,
		LateFee:         msg.LateFee,
	}

	k.SetCreditCardMetadata(
		ctx,
		creditCardMetadata,
	)
	return &types.MsgCreateCreditCardMetadataResponse{}, nil
}

func (k msgServer) UpdateCreditCardMetadata(goCtx context.Context, msg *types.MsgUpdateCreditCardMetadata) (*types.MsgUpdateCreditCardMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetCreditCardMetadata(
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

	var creditCardMetadata = types.CreditCardMetadata{
		Creator:         msg.Creator,
		Index:           msg.Index,
		LoanId:          msg.LoanId,
		CreditLimit:     msg.CreditLimit,
		AvailableCredit: msg.AvailableCredit,
		MinimumPayment:  msg.MinimumPayment,
		DailyRate:       msg.DailyRate,
		GracePeriodDays: msg.GracePeriodDays,
		OverlimitFee:    msg.OverlimitFee,
		LateFee:         msg.LateFee,
	}

	k.SetCreditCardMetadata(ctx, creditCardMetadata)

	return &types.MsgUpdateCreditCardMetadataResponse{}, nil
}

func (k msgServer) DeleteCreditCardMetadata(goCtx context.Context, msg *types.MsgDeleteCreditCardMetadata) (*types.MsgDeleteCreditCardMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetCreditCardMetadata(
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

	k.RemoveCreditCardMetadata(
		ctx,
		msg.Index,
	)

	return &types.MsgDeleteCreditCardMetadataResponse{}, nil
}
