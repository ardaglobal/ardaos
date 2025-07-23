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

func createNCreditCardMetadata(keeper keeper.Keeper, ctx context.Context, n int) []types.CreditCardMetadata {
	items := make([]types.CreditCardMetadata, n)
	for i := range items {
		items[i].Index = strconv.Itoa(i)

		keeper.SetCreditCardMetadata(ctx, items[i])
	}
	return items
}

func TestCreditCardMetadataGet(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNCreditCardMetadata(keeper, ctx, 10)
	for _, item := range items {
		rst, found := keeper.GetCreditCardMetadata(ctx,
			item.Index,
		)
		require.True(t, found)
		require.Equal(t,
			nullify.Fill(&item),
			nullify.Fill(&rst),
		)
	}
}
func TestCreditCardMetadataRemove(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNCreditCardMetadata(keeper, ctx, 10)
	for _, item := range items {
		keeper.RemoveCreditCardMetadata(ctx,
			item.Index,
		)
		_, found := keeper.GetCreditCardMetadata(ctx,
			item.Index,
		)
		require.False(t, found)
	}
}

func TestCreditCardMetadataGetAll(t *testing.T) {
	keeper, ctx := keepertest.LoanKeeper(t)
	items := createNCreditCardMetadata(keeper, ctx, 10)
	require.ElementsMatch(t,
		nullify.Fill(items),
		nullify.Fill(keeper.GetAllCreditCardMetadata(ctx)),
	)
}
