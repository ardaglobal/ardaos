package keeper

import (
	"github.com/ardaglobal/ardaos/x/spv/types"
)

var _ types.QueryServer = Keeper{}
