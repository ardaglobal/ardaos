package types

import (
	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var _ sdk.Msg = &MsgCreateLoan{}

func NewMsgCreateLoan(creator string, borrower string, lender string, principalAmount string, currency string, interestRate string, termMonths string, loanType string, collateralDescription string, jurisdiction string) *MsgCreateLoan {
	return &MsgCreateLoan{
		Creator:               creator,
		Borrower:              borrower,
		Lender:                lender,
		PrincipalAmount:       principalAmount,
		Currency:              currency,
		InterestRate:          interestRate,
		TermMonths:            termMonths,
		LoanType:              loanType,
		CollateralDescription: collateralDescription,
		Jurisdiction:          jurisdiction,
	}
}

func (msg *MsgCreateLoan) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Creator)
	if err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid creator address (%s)", err)
	}
	return nil
}
