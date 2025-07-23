package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateInstallmentMetadata{}

func NewMsgCreateInstallmentMetadata(
	creator string,
	index string,
	loanId string,
	paymentAmount string,
	paymentFrequency string,
	remainingPayments string,
	amortizationType string,
	prepaymentAllowed string,

) *MsgCreateInstallmentMetadata {
	return &MsgCreateInstallmentMetadata{
		Creator:           creator,
		Index:             index,
		LoanId:            loanId,
		PaymentAmount:     paymentAmount,
		PaymentFrequency:  paymentFrequency,
		RemainingPayments: remainingPayments,
		AmortizationType:  amortizationType,
		PrepaymentAllowed: prepaymentAllowed,
	}
}

func (msg *MsgCreateInstallmentMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgUpdateInstallmentMetadata{}

func NewMsgUpdateInstallmentMetadata(
	creator string,
	index string,
	loanId string,
	paymentAmount string,
	paymentFrequency string,
	remainingPayments string,
	amortizationType string,
	prepaymentAllowed string,

) *MsgUpdateInstallmentMetadata {
	return &MsgUpdateInstallmentMetadata{
		Creator:           creator,
		Index:             index,
		LoanId:            loanId,
		PaymentAmount:     paymentAmount,
		PaymentFrequency:  paymentFrequency,
		RemainingPayments: remainingPayments,
		AmortizationType:  amortizationType,
		PrepaymentAllowed: prepaymentAllowed,
	}
}

func (msg *MsgUpdateInstallmentMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgDeleteInstallmentMetadata{}

func NewMsgDeleteInstallmentMetadata(
	creator string,
	index string,

) *MsgDeleteInstallmentMetadata {
	return &MsgDeleteInstallmentMetadata{
		Creator: creator,
		Index:   index,
	}
}

func (msg *MsgDeleteInstallmentMetadata) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
