package ardaus_test

import (
	"testing"

	keepertest "arda-us/testutil/keeper"
	"arda-us/testutil/nullify"
	ardaus "arda-us/x/ardaus/module"
	"arda-us/x/ardaus/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.ArdausKeeper(t)
	ardaus.InitGenesis(ctx, k, genesisState)
	got := ardaus.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	// this line is used by starport scaffolding # genesis/test/assert
}
