package types

import (
	"testing"

	"arda-os/testutil/sample"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestMsgCreateMcaMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgCreateMcaMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgCreateMcaMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgCreateMcaMetadata{
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

func TestMsgUpdateMcaMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgUpdateMcaMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgUpdateMcaMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgUpdateMcaMetadata{
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

func TestMsgDeleteMcaMetadata_ValidateBasic(t *testing.T) {
	tests := []struct {
		name string
		msg  MsgDeleteMcaMetadata
		err  error
	}{
		{
			name: "invalid address",
			msg: MsgDeleteMcaMetadata{
				Creator: "invalid_address",
			},
			err: sdkerrors.ErrInvalidAddress,
		}, {
			name: "valid address",
			msg: MsgDeleteMcaMetadata{
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
