package vault_test

import (
	"testing"

	keepertest "github.com/ardaglobal/ardaos/testutil/keeper"
	"github.com/ardaglobal/ardaos/testutil/nullify"
	vault "github.com/ardaglobal/ardaos/x/vault/module"
	"github.com/ardaglobal/ardaos/x/vault/types"
	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.VaultKeeper(t)
	vault.InitGenesis(ctx, k, genesisState)
	got := vault.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	// this line is used by starport scaffolding # genesis/test/assert
}
