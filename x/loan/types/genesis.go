package types

import (
	"fmt"
)

// DefaultIndex is the default global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		LoanStateList:           []LoanState{},
		CreditCardMetadataList:  []CreditCardMetadata{},
		McaMetadataList:         []McaMetadata{},
		InstallmentMetadataList: []InstallmentMetadata{},
		// this line is used by starport scaffolding # genesis/types/default
		Params: DefaultParams(),
	}
}

// Validate performs basic genesis state validation returning an error upon any
// failure.
func (gs GenesisState) Validate() error {
	// Check for duplicated index in loanState
	loanStateIndexMap := make(map[string]struct{})

	for _, elem := range gs.LoanStateList {
		index := string(LoanStateKey(elem.Index))
		if _, ok := loanStateIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for loanState")
		}
		loanStateIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in creditCardMetadata
	creditCardMetadataIndexMap := make(map[string]struct{})

	for _, elem := range gs.CreditCardMetadataList {
		index := string(CreditCardMetadataKey(elem.Index))
		if _, ok := creditCardMetadataIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for creditCardMetadata")
		}
		creditCardMetadataIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in mcaMetadata
	mcaMetadataIndexMap := make(map[string]struct{})

	for _, elem := range gs.McaMetadataList {
		index := string(McaMetadataKey(elem.Index))
		if _, ok := mcaMetadataIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for mcaMetadata")
		}
		mcaMetadataIndexMap[index] = struct{}{}
	}
	// Check for duplicated index in installmentMetadata
	installmentMetadataIndexMap := make(map[string]struct{})

	for _, elem := range gs.InstallmentMetadataList {
		index := string(InstallmentMetadataKey(elem.Index))
		if _, ok := installmentMetadataIndexMap[index]; ok {
			return fmt.Errorf("duplicated index for installmentMetadata")
		}
		installmentMetadataIndexMap[index] = struct{}{}
	}
	// this line is used by starport scaffolding # genesis/types/validate

	return gs.Params.Validate()
}
