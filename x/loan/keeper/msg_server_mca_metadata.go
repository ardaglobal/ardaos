package keeper

import (
	"context"

	"arda-os/x/loan/types"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

func (k msgServer) CreateMcaMetadata(goCtx context.Context, msg *types.MsgCreateMcaMetadata) (*types.MsgCreateMcaMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value already exists
	_, isFound := k.GetMcaMetadata(
		ctx,
		msg.Index,
	)
	if isFound {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "index already set")
	}

	var mcaMetadata = types.McaMetadata{
		Creator:                   msg.Creator,
		Index:                     msg.Index,
		LoanId:                    msg.LoanId,
		DailyCollectionPercentage: msg.DailyCollectionPercentage,
		MerchantId:                msg.MerchantId,
		ProcessorName:             msg.ProcessorName,
		EstimatedTermDays:         msg.EstimatedTermDays,
		TotalPaybackAmount:        msg.TotalPaybackAmount,
		DailySalesAverage:         msg.DailySalesAverage,
	}

	k.SetMcaMetadata(
		ctx,
		mcaMetadata,
	)
	return &types.MsgCreateMcaMetadataResponse{}, nil
}

func (k msgServer) UpdateMcaMetadata(goCtx context.Context, msg *types.MsgUpdateMcaMetadata) (*types.MsgUpdateMcaMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetMcaMetadata(
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

	var mcaMetadata = types.McaMetadata{
		Creator:                   msg.Creator,
		Index:                     msg.Index,
		LoanId:                    msg.LoanId,
		DailyCollectionPercentage: msg.DailyCollectionPercentage,
		MerchantId:                msg.MerchantId,
		ProcessorName:             msg.ProcessorName,
		EstimatedTermDays:         msg.EstimatedTermDays,
		TotalPaybackAmount:        msg.TotalPaybackAmount,
		DailySalesAverage:         msg.DailySalesAverage,
	}

	k.SetMcaMetadata(ctx, mcaMetadata)

	return &types.MsgUpdateMcaMetadataResponse{}, nil
}

func (k msgServer) DeleteMcaMetadata(goCtx context.Context, msg *types.MsgDeleteMcaMetadata) (*types.MsgDeleteMcaMetadataResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Check if the value exists
	valFound, isFound := k.GetMcaMetadata(
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

	k.RemoveMcaMetadata(
		ctx,
		msg.Index,
	)

	return &types.MsgDeleteMcaMetadataResponse{}, nil
}
