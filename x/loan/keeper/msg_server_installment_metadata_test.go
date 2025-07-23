package keeper_test

import (
	"strconv"
	"testing"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"

	keepertest "arda-os/testutil/keeper"
	"arda-os/x/loan/keeper"
	"arda-os/x/loan/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestInstallmentMetadataMsgServerCreate(t *testing.T) {
	k, ctx := keepertest.LoanKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	creator := "A"
	for i := 0; i < 5; i++ {
		expected := &types.MsgCreateInstallmentMetadata{Creator: creator,
			Index: strconv.Itoa(i),
		}
		_, err := srv.CreateInstallmentMetadata(ctx, expected)
		require.NoError(t, err)
		rst, found := k.GetInstallmentMetadata(ctx,
			expected.Index,
		)
		require.True(t, found)
		require.Equal(t, expected.Creator, rst.Creator)
	}
}

func TestInstallmentMetadataMsgServerUpdate(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgUpdateInstallmentMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgUpdateInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgUpdateInstallmentMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgUpdateInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)
			expected := &types.MsgCreateInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			}
			_, err := srv.CreateInstallmentMetadata(ctx, expected)
			require.NoError(t, err)

			_, err = srv.UpdateInstallmentMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				rst, found := k.GetInstallmentMetadata(ctx,
					expected.Index,
				)
				require.True(t, found)
				require.Equal(t, expected.Creator, rst.Creator)
			}
		})
	}
}

func TestInstallmentMetadataMsgServerDelete(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgDeleteInstallmentMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgDeleteInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgDeleteInstallmentMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgDeleteInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)

			_, err := srv.CreateInstallmentMetadata(ctx, &types.MsgCreateInstallmentMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			})
			require.NoError(t, err)
			_, err = srv.DeleteInstallmentMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				_, found := k.GetInstallmentMetadata(ctx,
					tc.request.Index,
				)
				require.False(t, found)
			}
		})
	}
}
