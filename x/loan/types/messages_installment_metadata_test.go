package types

import (
	"testing"

	"arda-os/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgCreateInstallmentMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgCreateInstallmentMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgCreateInstallmentMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgCreateInstallmentMetadata{
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

func TestMsgUpdateInstallmentMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgUpdateInstallmentMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgUpdateInstallmentMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgUpdateInstallmentMetadata{
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

func TestMsgDeleteInstallmentMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgDeleteInstallmentMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgDeleteInstallmentMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgDeleteInstallmentMetadata{
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
