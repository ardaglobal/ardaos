package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateCreditCardMetadata{}

func NewMsgCreateCreditCardMetadata(
	creator string,
	index string,
	loanId string,
	creditLimit string,
	availableCredit string,
	minimumPayment string,
	dailyRate string,
	gracePeriodDays string,
	overlimitFee string,
	lateFee string,

) *MsgCreateCreditCardMetadata {
	return &MsgCreateCreditCardMetadata{
		Creator:         creator,
		Index:           index,
		LoanId:          loanId,
		CreditLimit:     creditLimit,
		AvailableCredit: availableCredit,
		MinimumPayment:  minimumPayment,
		DailyRate:       dailyRate,
		GracePeriodDays: gracePeriodDays,
		OverlimitFee:    overlimitFee,
		LateFee:         lateFee,
	}
}

func (msg *MsgCreateCreditCardMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgUpdateCreditCardMetadata{}

func NewMsgUpdateCreditCardMetadata(
	creator string,
	index string,
	loanId string,
	creditLimit string,
	availableCredit string,
	minimumPayment string,
	dailyRate string,
	gracePeriodDays string,
	overlimitFee string,
	lateFee string,

) *MsgUpdateCreditCardMetadata {
	return &MsgUpdateCreditCardMetadata{
		Creator:         creator,
		Index:           index,
		LoanId:          loanId,
		CreditLimit:     creditLimit,
		AvailableCredit: availableCredit,
		MinimumPayment:  minimumPayment,
		DailyRate:       dailyRate,
		GracePeriodDays: gracePeriodDays,
		OverlimitFee:    overlimitFee,
		LateFee:         lateFee,
	}
}

func (msg *MsgUpdateCreditCardMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgDeleteCreditCardMetadata{}

func NewMsgDeleteCreditCardMetadata(
	creator string,
	index string,

) *MsgDeleteCreditCardMetadata {
	return &MsgDeleteCreditCardMetadata{
		Creator: creator,
		Index:   index,
	}
}

func (msg *MsgDeleteCreditCardMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
