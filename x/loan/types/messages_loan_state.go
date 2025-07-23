package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateLoanState{}

func NewMsgCreateLoanState(
	creator string,
	index string,
	loanId string,
	status string,
	currentBalance string,
	paymentsMade string,
	lastPaymentDate string,
	nextPaymentDate string,
	delinquencyDays string,

) *MsgCreateLoanState {
	return &MsgCreateLoanState{
		Creator:         creator,
		Index:           index,
		LoanId:          loanId,
		Status:          status,
		CurrentBalance:  currentBalance,
		PaymentsMade:    paymentsMade,
		LastPaymentDate: lastPaymentDate,
		NextPaymentDate: nextPaymentDate,
		DelinquencyDays: delinquencyDays,
	}
}

func (msg *MsgCreateLoanState) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgUpdateLoanState{}

func NewMsgUpdateLoanState(
	creator string,
	index string,
	loanId string,
	status string,
	currentBalance string,
	paymentsMade string,
	lastPaymentDate string,
	nextPaymentDate string,
	delinquencyDays string,

) *MsgUpdateLoanState {
	return &MsgUpdateLoanState{
		Creator:         creator,
		Index:           index,
		LoanId:          loanId,
		Status:          status,
		CurrentBalance:  currentBalance,
		PaymentsMade:    paymentsMade,
		LastPaymentDate: lastPaymentDate,
		NextPaymentDate: nextPaymentDate,
		DelinquencyDays: delinquencyDays,
	}
}

func (msg *MsgUpdateLoanState) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}

var _ sdk.Msg = &MsgDeleteLoanState{}

func NewMsgDeleteLoanState(
	creator string,
	index string,

) *MsgDeleteLoanState {
	return &MsgDeleteLoanState{
		Creator: creator,
		Index:   index,
	}
}

func (msg *MsgDeleteLoanState) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
