package loan_test

import (
	"testing"

	keepertest "arda-os/testutil/keeper"
	"arda-os/testutil/nullify"
	loan "arda-os/x/loan/module"
	"arda-os/x/loan/types"

	"github.com/stretchr/testify/require"
)

func TestGenesis(t *testing.T) {
	genesisState := types.GenesisState{
		Params: types.DefaultParams(),

		LoanStateList: []types.LoanState{
			{
				Index: "0",
			},
			{
				Index: "1",
			},
		},
		CreditCardMetadataList: []types.CreditCardMetadata{
			{
				Index: "0",
			},
			{
				Index: "1",
			},
		},
		McaMetadataList: []types.McaMetadata{
			{
				Index: "0",
			},
			{
				Index: "1",
			},
		},
		InstallmentMetadataList: []types.InstallmentMetadata{
			{
				Index: "0",
			},
			{
				Index: "1",
			},
		},
		// this line is used by starport scaffolding # genesis/test/state
	}

	k, ctx := keepertest.LoanKeeper(t)
	loan.InitGenesis(ctx, k, genesisState)
	got := loan.ExportGenesis(ctx, k)
	require.NotNil(t, got)

	nullify.Fill(&genesisState)
	nullify.Fill(got)

	require.ElementsMatch(t, genesisState.LoanStateList, got.LoanStateList)
	require.ElementsMatch(t, genesisState.CreditCardMetadataList, got.CreditCardMetadataList)
	require.ElementsMatch(t, genesisState.McaMetadataList, got.McaMetadataList)
	require.ElementsMatch(t, genesisState.InstallmentMetadataList, got.InstallmentMetadataList)
	// this line is used by starport scaffolding # genesis/test/assert
}
