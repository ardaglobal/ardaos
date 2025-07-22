package ardaos_test

import (
	"testing"

	keepertest "arda-os/testutil/keeper"
	"arda-os/testutil/nullify"
	ardaos "arda-os/x/ardaos/module"
	"arda-os/x/ardaos/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.ArdaosKeeper(t)
	ardaos.InitGenesis(ctx, k, genesisState)
	got := ardaos.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	// this line is used by starport scaffolding # genesis/test/assert
}
