package types

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	compliancetypes "github.com/ardaglobal/ardaos/x/compliance/types"
	vaulttypes "github.com/ardaglobal/ardaos/x/vault/types"
)

type VaultKeeper interface {
	GetParams(ctx context.Context) vaulttypes.Params
	SetParams(ctx context.Context, params vaulttypes.Params) error
	GetAuthority() string
}

type ComplianceKeeper interface {
	GetParams(ctx context.Context) compliancetypes.Params
	SetParams(ctx context.Context, params compliancetypes.Params) error
	GetAuthority() string
}

// AccountKeeper defines the expected interface for the Account module.
type AccountKeeper interface {
	GetAccount(context.Context, sdk.AccAddress) sdk.AccountI // only used for simulation
	// Methods imported from account should be defined here
}

// BankKeeper defines the expected interface for the Bank module.
type BankKeeper interface {
	SpendableCoins(context.Context, sdk.AccAddress) sdk.Coins
	// Methods imported from bank should be defined here
}

// ParamSubspace defines the expected Subspace interface for parameters.
type ParamSubspace interface {
	Get(context.Context, []byte, interface{})
	Set(context.Context, []byte, interface{})
}
