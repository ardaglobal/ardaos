package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "github.com/ardaglobal/ardaos/testutil/keeper"
	"github.com/ardaglobal/ardaos/x/compliance/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.ComplianceKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}
