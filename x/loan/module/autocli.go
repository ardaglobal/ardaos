package loan

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "arda-os/api/ardaos/loan"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: modulev1.Query_ServiceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod: "LoanStateAll",
					Use:       "list-loan-state",
					Short:     "List all loan-state",
				},
				{
					RpcMethod:      "LoanState",
					Use:            "show-loan-state [id]",
					Short:          "Shows a loan-state",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod: "CreditCardMetadataAll",
					Use:       "list-credit-card-metadata",
					Short:     "List all credit-card-metadata",
				},
				{
					RpcMethod:      "CreditCardMetadata",
					Use:            "show-credit-card-metadata [id]",
					Short:          "Shows a credit-card-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod: "McaMetadataAll",
					Use:       "list-mca-metadata",
					Short:     "List all mca-metadata",
				},
				{
					RpcMethod:      "McaMetadata",
					Use:            "show-mca-metadata [id]",
					Short:          "Shows a mca-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod: "InstallmentMetadataAll",
					Use:       "list-installment-metadata",
					Short:     "List all installment-metadata",
				},
				{
					RpcMethod:      "InstallmentMetadata",
					Use:            "show-installment-metadata [id]",
					Short:          "Shows a installment-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Msg_ServiceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "CreateLoan",
					Use:            "create-loan [borrower] [lender] [principal-amount] [currency] [interest-rate] [term-months] [loan-type] [collateral-description] [jurisdiction]",
					Short:          "Send a create-loan tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "borrower"}, {ProtoField: "lender"}, {ProtoField: "principalAmount"}, {ProtoField: "currency"}, {ProtoField: "interestRate"}, {ProtoField: "termMonths"}, {ProtoField: "loanType"}, {ProtoField: "collateralDescription"}, {ProtoField: "jurisdiction"}},
				},
				{
					RpcMethod:      "CreateLoanState",
					Use:            "create-loan-state [index] [loanId] [status] [currentBalance] [paymentsMade] [lastPaymentDate] [nextPaymentDate] [delinquencyDays]",
					Short:          "Create a new loan-state",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "status"}, {ProtoField: "currentBalance"}, {ProtoField: "paymentsMade"}, {ProtoField: "lastPaymentDate"}, {ProtoField: "nextPaymentDate"}, {ProtoField: "delinquencyDays"}},
				},
				{
					RpcMethod:      "UpdateLoanState",
					Use:            "update-loan-state [index] [loanId] [status] [currentBalance] [paymentsMade] [lastPaymentDate] [nextPaymentDate] [delinquencyDays]",
					Short:          "Update loan-state",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "status"}, {ProtoField: "currentBalance"}, {ProtoField: "paymentsMade"}, {ProtoField: "lastPaymentDate"}, {ProtoField: "nextPaymentDate"}, {ProtoField: "delinquencyDays"}},
				},
				{
					RpcMethod:      "DeleteLoanState",
					Use:            "delete-loan-state [index]",
					Short:          "Delete loan-state",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod:      "CreateCreditCardMetadata",
					Use:            "create-credit-card-metadata [index] [loanId] [creditLimit] [availableCredit] [minimumPayment] [dailyRate] [gracePeriodDays] [overlimitFee] [lateFee]",
					Short:          "Create a new credit-card-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "creditLimit"}, {ProtoField: "availableCredit"}, {ProtoField: "minimumPayment"}, {ProtoField: "dailyRate"}, {ProtoField: "gracePeriodDays"}, {ProtoField: "overlimitFee"}, {ProtoField: "lateFee"}},
				},
				{
					RpcMethod:      "UpdateCreditCardMetadata",
					Use:            "update-credit-card-metadata [index] [loanId] [creditLimit] [availableCredit] [minimumPayment] [dailyRate] [gracePeriodDays] [overlimitFee] [lateFee]",
					Short:          "Update credit-card-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "creditLimit"}, {ProtoField: "availableCredit"}, {ProtoField: "minimumPayment"}, {ProtoField: "dailyRate"}, {ProtoField: "gracePeriodDays"}, {ProtoField: "overlimitFee"}, {ProtoField: "lateFee"}},
				},
				{
					RpcMethod:      "DeleteCreditCardMetadata",
					Use:            "delete-credit-card-metadata [index]",
					Short:          "Delete credit-card-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod:      "CreateMcaMetadata",
					Use:            "create-mca-metadata [index] [loanId] [dailyCollectionPercentage] [merchantId] [processorName] [estimatedTermDays] [totalPaybackAmount] [dailySalesAverage]",
					Short:          "Create a new mca-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "dailyCollectionPercentage"}, {ProtoField: "merchantId"}, {ProtoField: "processorName"}, {ProtoField: "estimatedTermDays"}, {ProtoField: "totalPaybackAmount"}, {ProtoField: "dailySalesAverage"}},
				},
				{
					RpcMethod:      "UpdateMcaMetadata",
					Use:            "update-mca-metadata [index] [loanId] [dailyCollectionPercentage] [merchantId] [processorName] [estimatedTermDays] [totalPaybackAmount] [dailySalesAverage]",
					Short:          "Update mca-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "dailyCollectionPercentage"}, {ProtoField: "merchantId"}, {ProtoField: "processorName"}, {ProtoField: "estimatedTermDays"}, {ProtoField: "totalPaybackAmount"}, {ProtoField: "dailySalesAverage"}},
				},
				{
					RpcMethod:      "DeleteMcaMetadata",
					Use:            "delete-mca-metadata [index]",
					Short:          "Delete mca-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				{
					RpcMethod:      "CreateInstallmentMetadata",
					Use:            "create-installment-metadata [index] [loanId] [paymentAmount] [paymentFrequency] [remainingPayments] [amortizationType] [prepaymentAllowed]",
					Short:          "Create a new installment-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "paymentAmount"}, {ProtoField: "paymentFrequency"}, {ProtoField: "remainingPayments"}, {ProtoField: "amortizationType"}, {ProtoField: "prepaymentAllowed"}},
				},
				{
					RpcMethod:      "UpdateInstallmentMetadata",
					Use:            "update-installment-metadata [index] [loanId] [paymentAmount] [paymentFrequency] [remainingPayments] [amortizationType] [prepaymentAllowed]",
					Short:          "Update installment-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}, {ProtoField: "loanId"}, {ProtoField: "paymentAmount"}, {ProtoField: "paymentFrequency"}, {ProtoField: "remainingPayments"}, {ProtoField: "amortizationType"}, {ProtoField: "prepaymentAllowed"}},
				},
				{
					RpcMethod:      "DeleteInstallmentMetadata",
					Use:            "delete-installment-metadata [index]",
					Short:          "Delete installment-metadata",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "index"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
