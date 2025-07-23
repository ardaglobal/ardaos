package keeper_test

import (
	"strconv"
	"testing"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	keepertest "arda-os/testutil/keeper"
	"arda-os/testutil/nullify"
	"arda-os/x/loan/types"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func TestMcaMetadataQuerySingle(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	msgs := createNMcaMetadata(keeper, ctx, 2)
	tests := []struct {
		desc     string
		request  *types.QueryGetMcaMetadataRequest
		response *types.QueryGetMcaMetadataResponse
		err      error
	}{
		{
			desc: "First",
			request: &types.QueryGetMcaMetadataRequest{
				Index: msgs[0].Index,
			},
			response: &types.QueryGetMcaMetadataResponse{McaMetadata: msgs[0]},
		},
		{
			desc: "Second",
			request: &types.QueryGetMcaMetadataRequest{
				Index: msgs[1].Index,
			},
			response: &types.QueryGetMcaMetadataResponse{McaMetadata: msgs[1]},
		},
		{
			desc: "KeyNotFound",
			request: &types.QueryGetMcaMetadataRequest{
				Index: strconv.Itoa(100000),
			},
			err: status.Error(codes.NotFound, "not found"),
		},
		{
			desc: "InvalidRequest",
			err:  status.Error(codes.InvalidArgument, "invalid request"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			response, err := keeper.McaMetadata(ctx, tc.request)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Equal(t,
					nullify.Fill(tc.response),
					nullify.Fill(response),
				)
			}
		})
	}
}

func TestMcaMetadataQueryPaginated(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	msgs := createNMcaMetadata(keeper, ctx, 5)

	request := func(next []byte, offset, limit uint64, total bool) *types.QueryAllMcaMetadataRequest {
		return &types.QueryAllMcaMetadataRequest{
			Pagination: &query.PageRequest{
				Key:        next,
				Offset:     offset,
				Limit:      limit,
				CountTotal: total,
			},
		}
	}
	t.Run("ByOffset", func(t *testing.T) {
		step := 2
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.McaMetadataAll(ctx, request(nil, uint64(i), uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.McaMetadata), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.McaMetadata),
			)
		}
	})
	t.Run("ByKey", func(t *testing.T) {
		step := 2
		var next []byte
		for i := 0; i < len(msgs); i += step {
			resp, err := keeper.McaMetadataAll(ctx, request(next, 0, uint64(step), false))
			require.NoError(t, err)
			require.LessOrEqual(t, len(resp.McaMetadata), step)
			require.Subset(t,
				nullify.Fill(msgs),
				nullify.Fill(resp.McaMetadata),
			)
			next = resp.Pagination.NextKey
		}
	})
	t.Run("Total", func(t *testing.T) {
		resp, err := keeper.McaMetadataAll(ctx, request(nil, 0, 0, true))
		require.NoError(t, err)
		require.Equal(t, len(msgs), int(resp.Pagination.Total))
		require.ElementsMatch(t,
			nullify.Fill(msgs),
			nullify.Fill(resp.McaMetadata),
		)
	})
	t.Run("InvalidRequest", func(t *testing.T) {
		_, err := keeper.McaMetadataAll(ctx, nil)
		require.ErrorIs(t, err, status.Error(codes.InvalidArgument, "invalid request"))
	})
}
