package types

import (
	"testing"

	"arda-os/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgCreateCreditCardMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgCreateCreditCardMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgCreateCreditCardMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgCreateCreditCardMetadata{
				Creator: sample.AccAddress(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestMsgUpdateCreditCardMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgUpdateCreditCardMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgUpdateCreditCardMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgUpdateCreditCardMetadata{
				Creator: sample.AccAddress(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestMsgDeleteCreditCardMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgDeleteCreditCardMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgDeleteCreditCardMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgDeleteCreditCardMetadata{
				Creator: sample.AccAddress(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.ValidateBasic()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
		})
	}
}
