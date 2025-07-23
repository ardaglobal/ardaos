package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateMcaMetadata{}

func NewMsgCreateMcaMetadata(
	creator string,
	index string,
	loanId string,
	dailyCollectionPercentage string,
	merchantId string,
	processorName string,
	estimatedTermDays string,
	totalPaybackAmount string,
	dailySalesAverage string,

) *MsgCreateMcaMetadata {
	return &MsgCreateMcaMetadata{
		Creator:                   creator,
		Index:                     index,
		LoanId:                    loanId,
		DailyCollectionPercentage: dailyCollectionPercentage,
		MerchantId:                merchantId,
		ProcessorName:             processorName,
		EstimatedTermDays:         estimatedTermDays,
		TotalPaybackAmount:        totalPaybackAmount,
		DailySalesAverage:         dailySalesAverage,
	}
}

func (msg *MsgCreateMcaMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgUpdateMcaMetadata{}

func NewMsgUpdateMcaMetadata(
	creator string,
	index string,
	loanId string,
	dailyCollectionPercentage string,
	merchantId string,
	processorName string,
	estimatedTermDays string,
	totalPaybackAmount string,
	dailySalesAverage string,

) *MsgUpdateMcaMetadata {
	return &MsgUpdateMcaMetadata{
		Creator:                   creator,
		Index:                     index,
		LoanId:                    loanId,
		DailyCollectionPercentage: dailyCollectionPercentage,
		MerchantId:                merchantId,
		ProcessorName:             processorName,
		EstimatedTermDays:         estimatedTermDays,
		TotalPaybackAmount:        totalPaybackAmount,
		DailySalesAverage:         dailySalesAverage,
	}
}

func (msg *MsgUpdateMcaMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgDeleteMcaMetadata{}

func NewMsgDeleteMcaMetadata(
	creator string,
	index string,

) *MsgDeleteMcaMetadata {
	return &MsgDeleteMcaMetadata{
		Creator: creator,
		Index:   index,
	}
}

func (msg *MsgDeleteMcaMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
