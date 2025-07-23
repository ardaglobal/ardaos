package types_test

import (
	"testing"

	"arda-os/x/loan/types"

	"github.com/stretchr/testify/require"
)

func TestGenesisState_Validate(t *testing.T) {
	tests := []struct {
		desc     string
		genState *types.GenesisState
		valid    bool
	}{
		{
			desc:     "default is valid",
			genState: types.DefaultGenesis(),
			valid:    true,
		},
		{
			desc: "valid genesis state",
			genState: &types.GenesisState{

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
				// this line is used by starport scaffolding # types/genesis/validField
			},
			valid: true,
		},
		{
			desc: "duplicated loanState",
			genState: &types.GenesisState{
				LoanStateList: []types.LoanState{
					{
						Index: "0",
					},
					{
						Index: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated creditCardMetadata",
			genState: &types.GenesisState{
				CreditCardMetadataList: []types.CreditCardMetadata{
					{
						Index: "0",
					},
					{
						Index: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated mcaMetadata",
			genState: &types.GenesisState{
				McaMetadataList: []types.McaMetadata{
					{
						Index: "0",
					},
					{
						Index: "0",
					},
				},
			},
			valid: false,
		},
		{
			desc: "duplicated installmentMetadata",
			genState: &types.GenesisState{
				InstallmentMetadataList: []types.InstallmentMetadata{
					{
						Index: "0",
					},
					{
						Index: "0",
					},
				},
			},
			valid: false,
		},
		// this line is used by starport scaffolding # types/genesis/testcase
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.genState.Validate()
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
