package integrations

import (
	"context"
	"os"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integrations/extra_settings"
	"github.com/netbirdio/netbird/management/server/types"
)

type ManagerImpl struct {
	globalflowEnabled        bool
	FlowPacketCounterEnabled bool
}

func NewManager(eventStore activity.Store) extra_settings.Manager {
	// Check if the environment variables are set for flow enable and packet counter
	FlowEnabled := os.Getenv("NB_FlowEnabled") == "true"
	FlowPacketCounterEnabled := os.Getenv("NB_FlowPacketCounterEnabled") == "true"

	return &ManagerImpl{globalflowEnabled: FlowEnabled, FlowPacketCounterEnabled: FlowPacketCounterEnabled}
}

func (m *ManagerImpl) GetExtraSettings(ctx context.Context, accountID string) (*types.ExtraSettings, error) {
	return &types.ExtraSettings{FlowEnabled: m.globalflowEnabled, FlowPacketCounterEnabled: m.FlowPacketCounterEnabled}, nil
}

func (m *ManagerImpl) UpdateExtraSettings(ctx context.Context, accountID, userID string, accountExtraSettings *types.ExtraSettings) (changed bool, err error) {
	if accountExtraSettings == nil {
		return false, nil
	}
	if accountExtraSettings.FlowEnabled == m.globalflowEnabled &&
		accountExtraSettings.FlowPacketCounterEnabled == m.FlowPacketCounterEnabled {
		return false, nil // No changes to apply
	}
	m.FlowPacketCounterEnabled = accountExtraSettings.FlowPacketCounterEnabled
	m.globalflowEnabled = accountExtraSettings.FlowEnabled
	return true, nil
}
