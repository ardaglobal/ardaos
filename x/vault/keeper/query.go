package keeper

import (
	"github.com/ardaglobal/ardaos/x/vault/types"
)

var _ types.QueryServer = Keeper{}
