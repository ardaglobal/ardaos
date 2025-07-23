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

func TestLoanStateMsgServerCreate(t *testing.T) {
	k, ctx := keepertest.LoanKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	creator := "A"
	for i := 0; i < 5; i++ {
		expected := &types.MsgCreateLoanState{Creator: creator,
			Index: strconv.Itoa(i),
		}
		_, err := srv.CreateLoanState(ctx, expected)
		require.NoError(t, err)
		rst, found := k.GetLoanState(ctx,
			expected.Index,
		)
		require.True(t, found)
		require.Equal(t, expected.Creator, rst.Creator)
	}
}

func TestLoanStateMsgServerUpdate(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgUpdateLoanState
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgUpdateLoanState{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgUpdateLoanState{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgUpdateLoanState{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)
			expected := &types.MsgCreateLoanState{Creator: creator,
				Index: strconv.Itoa(0),
			}
			_, err := srv.CreateLoanState(ctx, expected)
			require.NoError(t, err)

			_, err = srv.UpdateLoanState(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				rst, found := k.GetLoanState(ctx,
					expected.Index,
				)
				require.True(t, found)
				require.Equal(t, expected.Creator, rst.Creator)
			}
		})
	}
}

func TestLoanStateMsgServerDelete(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgDeleteLoanState
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgDeleteLoanState{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgDeleteLoanState{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgDeleteLoanState{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)

			_, err := srv.CreateLoanState(ctx, &types.MsgCreateLoanState{Creator: creator,
				Index: strconv.Itoa(0),
			})
			require.NoError(t, err)
			_, err = srv.DeleteLoanState(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				_, found := k.GetLoanState(ctx,
					tc.request.Index,
				)
				require.False(t, found)
			}
		})
	}
}
