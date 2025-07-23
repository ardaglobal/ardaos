package loan

import (
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"arda-os/testutil/sample"
	loansimulation "arda-os/x/loan/simulation"
	"arda-os/x/loan/types"
)

// avoid unused import issue
var (
	_ = loansimulation.FindAccount
	_ = rand.Rand{}
	_ = sample.AccAddress
	_ = sdk.AccAddress{}
	_ = simulation.MsgEntryKind
)

const (
	opWeightMsgCreateLoan = "op_weight_msg_create_loan"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateLoan int = 100

	opWeightMsgCreateLoanState = "op_weight_msg_loan_state"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateLoanState int = 100

	opWeightMsgUpdateLoanState = "op_weight_msg_loan_state"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateLoanState int = 100

	opWeightMsgDeleteLoanState = "op_weight_msg_loan_state"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteLoanState int = 100

	opWeightMsgCreateCreditCardMetadata = "op_weight_msg_credit_card_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateCreditCardMetadata int = 100

	opWeightMsgUpdateCreditCardMetadata = "op_weight_msg_credit_card_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateCreditCardMetadata int = 100

	opWeightMsgDeleteCreditCardMetadata = "op_weight_msg_credit_card_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteCreditCardMetadata int = 100

	opWeightMsgCreateMcaMetadata = "op_weight_msg_mca_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateMcaMetadata int = 100

	opWeightMsgUpdateMcaMetadata = "op_weight_msg_mca_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateMcaMetadata int = 100

	opWeightMsgDeleteMcaMetadata = "op_weight_msg_mca_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteMcaMetadata int = 100

	opWeightMsgCreateInstallmentMetadata = "op_weight_msg_installment_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateInstallmentMetadata int = 100

	opWeightMsgUpdateInstallmentMetadata = "op_weight_msg_installment_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateInstallmentMetadata int = 100

	opWeightMsgDeleteInstallmentMetadata = "op_weight_msg_installment_metadata"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteInstallmentMetadata int = 100

	// this line is used by starport scaffolding # simapp/module/const
)

// GenerateGenesisState creates a randomized GenState of the module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	accs := make([]string, len(simState.Accounts))
	for i, acc := range simState.Accounts {
		accs[i] = acc.Address.String()
	}
	loanGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		LoanStateList: []types.LoanState{
			{
				Creator: sample.AccAddress(),
				Index:   "0",
			},
			{
				Creator: sample.AccAddress(),
				Index:   "1",
			},
		},
		CreditCardMetadataList: []types.CreditCardMetadata{
			{
				Creator: sample.AccAddress(),
				Index:   "0",
			},
			{
				Creator: sample.AccAddress(),
				Index:   "1",
			},
		},
		McaMetadataList: []types.McaMetadata{
			{
				Creator: sample.AccAddress(),
				Index:   "0",
			},
			{
				Creator: sample.AccAddress(),
				Index:   "1",
			},
		},
		InstallmentMetadataList: []types.InstallmentMetadata{
			{
				Creator: sample.AccAddress(),
				Index:   "0",
			},
			{
				Creator: sample.AccAddress(),
				Index:   "1",
			},
		},
		// this line is used by starport scaffolding # simapp/module/genesisState
	}
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&loanGenesis)
}

// RegisterStoreDecoder registers a decoder.
func (am AppModule) RegisterStoreDecoder(_ simtypes.StoreDecoderRegistry) {}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	operations := make([]simtypes.WeightedOperation, 0)

	var weightMsgCreateLoan int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateLoan, &weightMsgCreateLoan, nil,
		func(_ *rand.Rand) {
			weightMsgCreateLoan = defaultWeightMsgCreateLoan
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateLoan,
		loansimulation.SimulateMsgCreateLoan(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateLoanState int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateLoanState, &weightMsgCreateLoanState, nil,
		func(_ *rand.Rand) {
			weightMsgCreateLoanState = defaultWeightMsgCreateLoanState
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateLoanState,
		loansimulation.SimulateMsgCreateLoanState(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateLoanState int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateLoanState, &weightMsgUpdateLoanState, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateLoanState = defaultWeightMsgUpdateLoanState
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateLoanState,
		loansimulation.SimulateMsgUpdateLoanState(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteLoanState int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteLoanState, &weightMsgDeleteLoanState, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteLoanState = defaultWeightMsgDeleteLoanState
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteLoanState,
		loansimulation.SimulateMsgDeleteLoanState(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateCreditCardMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateCreditCardMetadata, &weightMsgCreateCreditCardMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgCreateCreditCardMetadata = defaultWeightMsgCreateCreditCardMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateCreditCardMetadata,
		loansimulation.SimulateMsgCreateCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateCreditCardMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateCreditCardMetadata, &weightMsgUpdateCreditCardMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateCreditCardMetadata = defaultWeightMsgUpdateCreditCardMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateCreditCardMetadata,
		loansimulation.SimulateMsgUpdateCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteCreditCardMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteCreditCardMetadata, &weightMsgDeleteCreditCardMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteCreditCardMetadata = defaultWeightMsgDeleteCreditCardMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteCreditCardMetadata,
		loansimulation.SimulateMsgDeleteCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateMcaMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateMcaMetadata, &weightMsgCreateMcaMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgCreateMcaMetadata = defaultWeightMsgCreateMcaMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateMcaMetadata,
		loansimulation.SimulateMsgCreateMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateMcaMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateMcaMetadata, &weightMsgUpdateMcaMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateMcaMetadata = defaultWeightMsgUpdateMcaMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateMcaMetadata,
		loansimulation.SimulateMsgUpdateMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteMcaMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteMcaMetadata, &weightMsgDeleteMcaMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteMcaMetadata = defaultWeightMsgDeleteMcaMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteMcaMetadata,
		loansimulation.SimulateMsgDeleteMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgCreateInstallmentMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateInstallmentMetadata, &weightMsgCreateInstallmentMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgCreateInstallmentMetadata = defaultWeightMsgCreateInstallmentMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateInstallmentMetadata,
		loansimulation.SimulateMsgCreateInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateInstallmentMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateInstallmentMetadata, &weightMsgUpdateInstallmentMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateInstallmentMetadata = defaultWeightMsgUpdateInstallmentMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateInstallmentMetadata,
		loansimulation.SimulateMsgUpdateInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteInstallmentMetadata int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteInstallmentMetadata, &weightMsgDeleteInstallmentMetadata, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteInstallmentMetadata = defaultWeightMsgDeleteInstallmentMetadata
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteInstallmentMetadata,
		loansimulation.SimulateMsgDeleteInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	// this line is used by starport scaffolding # simapp/module/operation

	return operations
}

// ProposalMsgs returns msgs used for governance proposals for simulations.
func (am AppModule) ProposalMsgs(simState module.SimulationState) []simtypes.WeightedProposalMsg {
	return []simtypes.WeightedProposalMsg{
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateLoan,
			defaultWeightMsgCreateLoan,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgCreateLoan(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateLoanState,
			defaultWeightMsgCreateLoanState,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgCreateLoanState(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateLoanState,
			defaultWeightMsgUpdateLoanState,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgUpdateLoanState(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteLoanState,
			defaultWeightMsgDeleteLoanState,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgDeleteLoanState(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateCreditCardMetadata,
			defaultWeightMsgCreateCreditCardMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgCreateCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateCreditCardMetadata,
			defaultWeightMsgUpdateCreditCardMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgUpdateCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteCreditCardMetadata,
			defaultWeightMsgDeleteCreditCardMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgDeleteCreditCardMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateMcaMetadata,
			defaultWeightMsgCreateMcaMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgCreateMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateMcaMetadata,
			defaultWeightMsgUpdateMcaMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgUpdateMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteMcaMetadata,
			defaultWeightMsgDeleteMcaMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgDeleteMcaMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateInstallmentMetadata,
			defaultWeightMsgCreateInstallmentMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgCreateInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateInstallmentMetadata,
			defaultWeightMsgUpdateInstallmentMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgUpdateInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteInstallmentMetadata,
			defaultWeightMsgDeleteInstallmentMetadata,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				loansimulation.SimulateMsgDeleteInstallmentMetadata(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		// this line is used by starport scaffolding # simapp/module/OpMsg
	}
}
