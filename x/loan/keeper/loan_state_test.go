package keeper_test

import (
	"context"
	"strconv"
	"testing"

	keepertest "arda-os/testutil/keeper"
	"arda-os/testutil/nullify"
	"arda-os/x/loan/keeper"
	"arda-os/x/loan/types"

	"github.com/stretchr/testify/require"
)

// Prevent strconv unused error
var _ = strconv.IntSize

func createNLoanState(keeper keeper.Keeper, ctx context.Context, n int) []types.LoanState {
	items := make([]types.LoanState, n)
	for i := range items {
		items[i].Index = strconv.Itoa(i)

		keeper.SetLoanState(ctx, items[i])
	}
	return items
}

func TestLoanStateGet(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNLoanState(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetLoanState(ctx,
			item.Index,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestLoanStateRemove(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNLoanState(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveLoanState(ctx,
			item.Index,
		)
		_, found := keeper.GetLoanState(ctx,
			item.Index,
		)
		require.False(t, found)
	}
}

func TestLoanStateGetAll(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNLoanState(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllLoanState(ctx)),
	)
}
