package config

import (
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func ExtendNetBirdConfig(peerID string, peerGroups []string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	return config
}
