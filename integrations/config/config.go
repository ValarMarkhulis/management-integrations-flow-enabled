package config

import (
	"os"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"

	log "github.com/sirupsen/logrus"

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

	NB_FlowIntervalInMinutes := os.Getenv("NB_FlowIntervalInMinutes")
	if NB_FlowIntervalInMinutes == "" {
		// Default interval is 10 minutes
		NB_FlowIntervalInMinutes = "10"
		log.Infof("Env 'NB_FlowIntervalInMinutes' is not set, using default: '%s'", NB_FlowIntervalInMinutes)
	} else {
		log.Debugf("Env 'NB_FlowIntervalInMinutes' was set to: '%s'", NB_FlowIntervalInMinutes)
	}

	flowInterval, err := time.ParseDuration(NB_FlowIntervalInMinutes + "m")
	if err != nil {
		log.Errorf("Failed to parse 'NB_FlowIntervalInMinutes' value '%s': %v", NB_FlowIntervalInMinutes, err)
		flowInterval = 10 * time.Minute // Fallback to default if parsing fails
	}

	// Convert flowInterval to protobuf duration
	flowIntervalProto := durationpb.New(flowInterval)

	config.Flow = &proto.FlowConfig{
		Url:      FlowURL,
		Interval: flowIntervalProto,
		Enabled:  extraSettings.FlowEnabled,
	}
	log.Debugf("Flow was update to %v ", config.Flow)

	return config
}
