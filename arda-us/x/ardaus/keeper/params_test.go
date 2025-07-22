package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "arda-us/testutil/keeper"
	"arda-us/x/ardaus/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.ArdausKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
