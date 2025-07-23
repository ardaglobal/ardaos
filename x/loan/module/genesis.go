package loan

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"arda-os/x/loan/keeper"
	"arda-os/x/loan/types"
)

// InitGenesis initializes the module's state from a provided genesis state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the loanState
	for _, elem := range genState.LoanStateList {
		k.SetLoanState(ctx, elem)
	}
	// Set all the creditCardMetadata
	for _, elem := range genState.CreditCardMetadataList {
		k.SetCreditCardMetadata(ctx, elem)
	}
	// Set all the mcaMetadata
	for _, elem := range genState.McaMetadataList {
		k.SetMcaMetadata(ctx, elem)
	}
	// Set all the installmentMetadata
	for _, elem := range genState.InstallmentMetadataList {
		k.SetInstallmentMetadata(ctx, elem)
	}
	// this line is used by starport scaffolding # genesis/module/init
	if err := k.SetParams(ctx, genState.Params); err != nil {
		panic(err)
	}
}

// ExportGenesis returns the module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.LoanStateList = k.GetAllLoanState(ctx)
	genesis.CreditCardMetadataList = k.GetAllCreditCardMetadata(ctx)
	genesis.McaMetadataList = k.GetAllMcaMetadata(ctx)
	genesis.InstallmentMetadataList = k.GetAllInstallmentMetadata(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
