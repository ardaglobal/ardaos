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

func createNInstallmentMetadata(keeper keeper.Keeper, ctx context.Context, n int) []types.InstallmentMetadata {
	items := make([]types.InstallmentMetadata, n)
	for i := range items {
		items[i].Index = strconv.Itoa(i)

		keeper.SetInstallmentMetadata(ctx, items[i])
	}
	return items
}

func TestInstallmentMetadataGet(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNInstallmentMetadata(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetInstallmentMetadata(ctx,
			item.Index,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestInstallmentMetadataRemove(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNInstallmentMetadata(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveInstallmentMetadata(ctx,
			item.Index,
		)
		_, found := keeper.GetInstallmentMetadata(ctx,
			item.Index,
		)
		require.False(t, found)
	}
}

func TestInstallmentMetadataGetAll(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNInstallmentMetadata(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllInstallmentMetadata(ctx)),
	)
}
