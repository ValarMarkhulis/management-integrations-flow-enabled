package config

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/types"
	"google.golang.org/protobuf/types/known/durationpb"
)

func ExtendNetBirdConfig(peerID string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	if extraSettings == nil || !extraSettings.FlowEnabled {
		log.Debugf("Flow is disabled, skipping flow config injection")
		return config
	}

	////// INJECT FLOW CONFIG
	if config == nil {
		config = &proto.NetbirdConfig{}
	}

	log.Debugf("Flow is enabled, injecting flow config")
	FlowURL := os.Getenv("NB_FLOW_URL")
	if FlowURL == "" {
		// Hardcoded development URL
		FlowURL = "tcp://localhost:9000"
		log.Infof("Env 'NB_FLOW_URL' is not set, using default: '%s'", FlowURL)
	} else {
		log.Debugf("Env 'NB_FLOW_URL' was set to: '%s'", FlowURL)
	}

	NB_FlowIntervalInMinuets := os.Getenv("NB_FlowIntervalInMinuets")
	if NB_FlowIntervalInMinuets == "" {
		// Default interval is 10 minutes
		NB_FlowIntervalInMinuets = "10"
		log.Infof("Env 'NB_FlowIntervalInMinuets' is not set, using default: '%s'", NB_FlowIntervalInMinuets)
	} else {
		log.Debugf("Env 'NB_FlowIntervalInMinuets' was set to: '%s'", NB_FlowIntervalInMinuets)
	}

	flowInterval, err := time.ParseDuration(NB_FlowIntervalInMinuets + "m")
	if err != nil {
		log.Errorf("Failed to parse 'NB_FlowIntervalInMinuets' value '%s': %v", NB_FlowIntervalInMinuets, err)
		flowInterval = 10 * time.Minute // Fallback to default if parsing fails
	}

	// Convert flowInterval to protobuf duration
	flowIntervalProto := durationpb.New(flowInterval)

	config = &proto.NetbirdConfig{
		Flow: &proto.FlowConfig{
			Url:      FlowURL,
			Interval: flowIntervalProto,
			Enabled:  extraSettings.FlowEnabled,
		},
	}
	log.Debugf("Flow was update to %v ", config.Flow)

	return config
}
