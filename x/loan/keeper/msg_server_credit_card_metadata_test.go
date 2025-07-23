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

func TestCreditCardMetadataMsgServerCreate(t *testing.T) {
	k, ctx := keepertest.LoanKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	creator := "A"
	for i := 0; i < 5; i++ {
		expected := &types.MsgCreateCreditCardMetadata{Creator: creator,
			Index: strconv.Itoa(i),
		}
		_, err := srv.CreateCreditCardMetadata(ctx, expected)
		require.NoError(t, err)
		rst, found := k.GetCreditCardMetadata(ctx,
			expected.Index,
		)
		require.True(t, found)
		require.Equal(t, expected.Creator, rst.Creator)
	}
}

func TestCreditCardMetadataMsgServerUpdate(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgUpdateCreditCardMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgUpdateCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgUpdateCreditCardMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgUpdateCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)
			expected := &types.MsgCreateCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			}
			_, err := srv.CreateCreditCardMetadata(ctx, expected)
			require.NoError(t, err)

			_, err = srv.UpdateCreditCardMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				rst, found := k.GetCreditCardMetadata(ctx,
					expected.Index,
				)
				require.True(t, found)
				require.Equal(t, expected.Creator, rst.Creator)
			}
		})
	}
}

func TestCreditCardMetadataMsgServerDelete(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgDeleteCreditCardMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgDeleteCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgDeleteCreditCardMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgDeleteCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)

			_, err := srv.CreateCreditCardMetadata(ctx, &types.MsgCreateCreditCardMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			})
			require.NoError(t, err)
			_, err = srv.DeleteCreditCardMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				_, found := k.GetCreditCardMetadata(ctx,
					tc.request.Index,
				)
				require.False(t, found)
			}
		})
	}
}
