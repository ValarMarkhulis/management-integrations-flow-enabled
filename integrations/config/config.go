package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"

	log "github.com/sirupsen/logrus"

	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	defaultTokenTTL    = 24 * time.Hour
	tokenRefreshBuffer = time.Hour
)

// staticConfig holds env-derived values that never change after startup.
type staticConfig struct {
	flowURL      string
	flowInterval time.Duration
	tokenTTL     time.Duration
	secret       string
}

var (
	staticOnce sync.Once
	cfg        staticConfig

	tokenMu         sync.Mutex
	cachedPayload   string
	cachedSignature string
	cachedExpiry    time.Time
)

// loadStaticConfig reads all env vars exactly once for the lifetime of the process.
func loadStaticConfig() {
	staticOnce.Do(func() {
		cfg = staticConfig{
			flowURL:      readFlowURL(),
			flowInterval: readFlowInterval(),
			tokenTTL:     readTokenTTL(),
			secret:       readFlowSecret(),
		}
	})
}

func readFlowURL() string {
	v := os.Getenv("NB_FLOW_URL")
	if v == "" {
		v = "tcp://localhost:9000"
		log.Infof("Env 'NB_FLOW_URL' is not set, using default: '%s'", v)
		return v
	}
	log.Debugf("Env 'NB_FLOW_URL' was set to: '%s'", v)
	return v
}

func readFlowInterval() time.Duration {
	minutes := os.Getenv("NB_FLOW_INTERVAL_MINUTES")
	if minutes == "" {
		log.Infof("Env 'NB_FLOW_INTERVAL_MINUTES' is not set, using default: 10m")
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(minutes + "m")
	if err != nil {
		log.Errorf("Failed to parse 'NB_FLOW_INTERVAL_MINUTES' value '%s': %v, using default 10m", minutes, err)
		return 10 * time.Minute
	}
	log.Debugf("Env 'NB_FLOW_INTERVAL_MINUTES' was set to: '%s'", minutes)
	return d
}

func readTokenTTL() time.Duration {
	ttlStr := os.Getenv("NB_FLOW_TOKEN_TTL")
	if ttlStr == "" {
		return defaultTokenTTL
	}
	d, err := time.ParseDuration(ttlStr)
	if err != nil {
		log.Errorf("Failed to parse 'NB_FLOW_TOKEN_TTL' value '%s': %v, using default %s", ttlStr, err, defaultTokenTTL)
		return defaultTokenTTL
	}
	if d <= tokenRefreshBuffer {
		log.Errorf("'NB_FLOW_TOKEN_TTL' value '%s' must be greater than the refresh buffer (%s), using default %s", ttlStr, tokenRefreshBuffer, defaultTokenTTL)
		return defaultTokenTTL
	}
	log.Debugf("Env 'NB_FLOW_TOKEN_TTL' was set to: '%s'", ttlStr)
	return d
}

func readFlowSecret() string {
	secret := os.Getenv("NB_FLOW_SECRET")
	if secret == "" {
		log.Warn("NB_FLOW_SECRET is not set — flow tokens will be empty and the flow receiver will not be able to authenticate peers")
	}
	return secret
}

func ExtendNetBirdConfig(peerID string, config *proto.NetbirdConfig, extraSettings *types.ExtraSettings) *proto.NetbirdConfig {
	if extraSettings == nil || !extraSettings.FlowEnabled {
		log.Debugf("Flow is disabled, skipping flow config injection")
		return config
	}

	if config == nil {
		config = &proto.NetbirdConfig{}
	}

	loadStaticConfig()

	log.Debugf("Flow is enabled, injecting flow config")

	tokenPayload, tokenSignature := getOrRefreshToken()

	config.Flow = &proto.FlowConfig{
		Url:            cfg.flowURL,
		Interval:       durationpb.New(cfg.flowInterval),
		Enabled:        extraSettings.FlowEnabled,
		TokenPayload:   tokenPayload,
		TokenSignature: tokenSignature,
	}
	log.Debugf("Flow config updated: %v", config.Flow)

	return config
}

// getOrRefreshToken returns the cached token, regenerating it when it is within
// tokenRefreshBuffer of expiry.
func getOrRefreshToken() (payload, signature string) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	if cfg.secret == "" {
		return "", ""
	}

	if !cachedExpiry.IsZero() && time.Now().Before(cachedExpiry.Add(-tokenRefreshBuffer)) {
		return cachedPayload, cachedSignature
	}

	cachedPayload, cachedSignature = generateFlowToken(cfg.secret, cfg.tokenTTL)
	cachedExpiry = time.Now().Add(cfg.tokenTTL)

	log.Debugf("Flow token refreshed, expires at %s", cachedExpiry.Format(time.RFC3339))
	return cachedPayload, cachedSignature
}

// generateFlowToken is a pure function: it takes the secret and TTL explicitly
// so it can be tested without any package-level state or env var dependencies.
// Payload is a Unix expiration timestamp; signature is base64(HMAC-SHA256(sha256(secret), payload)).
func generateFlowToken(secret string, ttl time.Duration) (payload, signature string) {
	if secret == "" {
		return "", ""
	}

	expiry := time.Now().Add(ttl)
	payload = strconv.FormatInt(expiry.Unix(), 10)

	hashedSecret := sha256.Sum256([]byte(secret))
	h := hmac.New(sha256.New, hashedSecret[:])
	h.Write([]byte(payload))
	signature = base64.StdEncoding.EncodeToString(h.Sum(nil))

	return payload, signature
}
