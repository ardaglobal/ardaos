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

func TestMcaMetadataMsgServerCreate(t *testing.T) {
	k, ctx := keepertest.LoanKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	creator := "A"
	for i := 0; i < 5; i++ {
		expected := &types.MsgCreateMcaMetadata{Creator: creator,
			Index: strconv.Itoa(i),
		}
		_, err := srv.CreateMcaMetadata(ctx, expected)
		require.NoError(t, err)
		rst, found := k.GetMcaMetadata(ctx,
			expected.Index,
		)
		require.True(t, found)
		require.Equal(t, expected.Creator, rst.Creator)
	}
}

func TestMcaMetadataMsgServerUpdate(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgUpdateMcaMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgUpdateMcaMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgUpdateMcaMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgUpdateMcaMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)
			expected := &types.MsgCreateMcaMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			}
			_, err := srv.CreateMcaMetadata(ctx, expected)
			require.NoError(t, err)

			_, err = srv.UpdateMcaMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				rst, found := k.GetMcaMetadata(ctx,
					expected.Index,
				)
				require.True(t, found)
				require.Equal(t, expected.Creator, rst.Creator)
			}
		})
	}
}

func TestMcaMetadataMsgServerDelete(t *testing.T) {
	creator := "A"

	tests := []struct {
		desc    string
		request *types.MsgDeleteMcaMetadata
		err     error
	}{
		{
			desc: "Completed",
			request: &types.MsgDeleteMcaMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			},
		},
		{
			desc: "Unauthorized",
			request: &types.MsgDeleteMcaMetadata{Creator: "B",
				Index: strconv.Itoa(0),
			},
			err: sdkerrors.ErrUnauthorized,
		},
		{
			desc: "KeyNotFound",
			request: &types.MsgDeleteMcaMetadata{Creator: creator,
				Index: strconv.Itoa(100000),
			},
			err: sdkerrors.ErrKeyNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			k, ctx := keepertest.LoanKeeper(t)
			srv := keeper.NewMsgServerImpl(k)

			_, err := srv.CreateMcaMetadata(ctx, &types.MsgCreateMcaMetadata{Creator: creator,
				Index: strconv.Itoa(0),
			})
			require.NoError(t, err)
			_, err = srv.DeleteMcaMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				_, found := k.GetMcaMetadata(ctx,
					tc.request.Index,
				)
				require.False(t, found)
			}
		})
	}
}
