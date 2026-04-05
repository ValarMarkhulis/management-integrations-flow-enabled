package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const testSecret = "test-secret"

// checkToken mirrors the verification logic in netbird-traffic-event-logging-shared/server.go
// so this test is self-contained and doesn't depend on the server package.
func checkToken(payload, signature, secret string) error {
	if secret == "" {
		return errors.New("no secret provided to verifier")
	}

	hashedSecret := sha256.Sum256([]byte(secret))
	h := hmac.New(sha256.New, hashedSecret[:])
	h.Write([]byte(payload))
	expectedSig := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(signature)) {
		return errors.New("signature mismatch")
	}

	expiry, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	if time.Now().Unix() > expiry {
		return errors.New("token expired")
	}

	return nil
}

func TestGenerateFlowToken_HappyPath(t *testing.T) {
	payload, signature := generateFlowToken(testSecret, 24*time.Hour)

	if payload == "" {
		t.Fatal("expected non-empty payload")
	}
	if signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if err := checkToken(payload, signature, testSecret); err != nil {
		t.Fatalf("token verification failed: %v", err)
	}
}

func TestGenerateFlowToken_PayloadIsFutureTimestamp(t *testing.T) {
	payload, _ := generateFlowToken(testSecret, 24*time.Hour)

	expiry, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		t.Fatalf("payload is not a valid integer: %v", err)
	}
	if time.Now().Unix() >= expiry {
		t.Errorf("expected payload to be a future Unix timestamp, got %d", expiry)
	}
}

func TestGenerateFlowToken_NoSecret(t *testing.T) {
	payload, signature := generateFlowToken("", 24*time.Hour)

	if payload != "" {
		t.Errorf("expected empty payload when secret is empty, got %q", payload)
	}
	if signature != "" {
		t.Errorf("expected empty signature when secret is empty, got %q", signature)
	}
}

func TestGenerateFlowToken_WrongSecretFails(t *testing.T) {
	payload, signature := generateFlowToken("correct-secret", 24*time.Hour)

	if err := checkToken(payload, signature, "wrong-secret"); err == nil {
		t.Fatal("expected verification to fail with wrong secret, but it passed")
	}
}

func TestGenerateFlowToken_ExpiredTokenFails(t *testing.T) {
	secret := testSecret

	// Craft a validly signed token with a past expiry timestamp.
	expiry := time.Now().Add(-1 * time.Hour).Unix()
	payload := strconv.FormatInt(expiry, 10)
	hashedSecret := sha256.Sum256([]byte(secret))
	h := hmac.New(sha256.New, hashedSecret[:])
	h.Write([]byte(payload))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	if err := checkToken(payload, signature, secret); err == nil {
		t.Fatal("expected verification to fail for expired token, but it passed")
	}
}

// resetTokenCache clears package-level token cache between tests.
func resetTokenCache() {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	cachedPayload = ""
	cachedSignature = ""
	cachedExpiry = time.Time{}
}

// setCfgForTesting fires staticOnce (making loadStaticConfig a no-op in the
// function under test) then directly sets cfg to the provided value.
var fireOnce sync.Once

func setCfgForTesting(sc staticConfig) {
	fireOnce.Do(func() { loadStaticConfig() })
	cfg = sc
}

// --- readFlowURL ---

func TestReadFlowURL_Default(t *testing.T) {
	t.Setenv("NB_FLOW_URL", "")
	result := readFlowURL()
	if result != "tcp://localhost:9000" {
		t.Errorf("expected default URL, got %q", result)
	}
}

func TestReadFlowURL_Custom(t *testing.T) {
	t.Setenv("NB_FLOW_URL", "tcp://example.com:9001")
	result := readFlowURL()
	if result != "tcp://example.com:9001" {
		t.Errorf("expected custom URL, got %q", result)
	}
}

// --- readFlowInterval ---

func TestReadFlowInterval_Default(t *testing.T) {
	t.Setenv("NB_FLOW_INTERVAL_MINUTES", "")
	result := readFlowInterval()
	if result != 10*time.Minute {
		t.Errorf("expected 10m, got %v", result)
	}
}

func TestReadFlowInterval_Valid(t *testing.T) {
	t.Setenv("NB_FLOW_INTERVAL_MINUTES", "5")
	result := readFlowInterval()
	if result != 5*time.Minute {
		t.Errorf("expected 5m, got %v", result)
	}
}

func TestReadFlowInterval_Invalid(t *testing.T) {
	t.Setenv("NB_FLOW_INTERVAL_MINUTES", "notanumber")
	result := readFlowInterval()
	if result != 10*time.Minute {
		t.Errorf("expected default 10m on parse error, got %v", result)
	}
}

// --- readTokenTTL ---

func TestReadTokenTTL_Default(t *testing.T) {
	t.Setenv("NB_FLOW_TOKEN_TTL", "")
	result := readTokenTTL()
	if result != defaultTokenTTL {
		t.Errorf("expected default TTL %v, got %v", defaultTokenTTL, result)
	}
}

func TestReadTokenTTL_Valid(t *testing.T) {
	t.Setenv("NB_FLOW_TOKEN_TTL", "48h")
	result := readTokenTTL()
	if result != 48*time.Hour {
		t.Errorf("expected 48h, got %v", result)
	}
}

func TestReadTokenTTL_Invalid(t *testing.T) {
	t.Setenv("NB_FLOW_TOKEN_TTL", "notaduration")
	result := readTokenTTL()
	if result != defaultTokenTTL {
		t.Errorf("expected default TTL on parse error, got %v", result)
	}
}

func TestReadTokenTTL_TooShort(t *testing.T) {
	// tokenRefreshBuffer is 1h, so a 30m TTL must fall back to default.
	t.Setenv("NB_FLOW_TOKEN_TTL", "30m")
	result := readTokenTTL()
	if result != defaultTokenTTL {
		t.Errorf("expected default TTL when value <= refresh buffer, got %v", result)
	}
}

// --- readFlowSecret ---

func TestReadFlowSecret_Empty(t *testing.T) {
	t.Setenv("NB_FLOW_SECRET", "")
	result := readFlowSecret()
	if result != "" {
		t.Errorf("expected empty secret, got %q", result)
	}
}

func TestReadFlowSecret_Set(t *testing.T) {
	t.Setenv("NB_FLOW_SECRET", "my-secret")
	result := readFlowSecret()
	if result != "my-secret" {
		t.Errorf("expected 'my-secret', got %q", result)
	}
}

// --- getOrRefreshToken ---

func TestGetOrRefreshToken_NoSecret(t *testing.T) {
	setCfgForTesting(staticConfig{secret: "", tokenTTL: defaultTokenTTL})
	resetTokenCache()

	payload, signature := getOrRefreshToken()
	if payload != "" || signature != "" {
		t.Errorf("expected empty token when no secret, got payload=%q signature=%q", payload, signature)
	}
}

func TestGetOrRefreshToken_GeneratesToken(t *testing.T) {
	setCfgForTesting(staticConfig{secret: testSecret, tokenTTL: defaultTokenTTL})
	resetTokenCache()

	payload, signature := getOrRefreshToken()
	if payload == "" || signature == "" {
		t.Fatal("expected non-empty token")
	}
	if err := checkToken(payload, signature, testSecret); err != nil {
		t.Fatalf("generated token failed verification: %v", err)
	}
}

func TestGetOrRefreshToken_ReturnsCachedToken(t *testing.T) {
	setCfgForTesting(staticConfig{secret: testSecret, tokenTTL: defaultTokenTTL})
	resetTokenCache()

	payload1, sig1 := getOrRefreshToken()
	payload2, sig2 := getOrRefreshToken()

	if payload1 != payload2 || sig1 != sig2 {
		t.Error("expected same cached token on second call")
	}
}

func TestGetOrRefreshToken_RefreshesNearExpiryToken(t *testing.T) {
	setCfgForTesting(staticConfig{secret: testSecret, tokenTTL: defaultTokenTTL})

	// Seed the cache with a token that expires within the refresh buffer.
	tokenMu.Lock()
	cachedPayload = "old-payload"
	cachedSignature = "old-sig"
	cachedExpiry = time.Now().Add(30 * time.Minute) // within tokenRefreshBuffer (1h)
	tokenMu.Unlock()

	payload, _ := getOrRefreshToken()
	if payload == "old-payload" {
		t.Error("expected token to be refreshed when within refresh buffer of expiry")
	}
}

// --- ExtendNetBirdConfig ---

func TestExtendNetBirdConfig_NilExtraSettings(t *testing.T) {
	original := &proto.NetbirdConfig{}
	result := ExtendNetBirdConfig("peer1", original, nil)
	if result != original {
		t.Error("expected original config returned when extraSettings is nil")
	}
}

func TestExtendNetBirdConfig_FlowDisabled(t *testing.T) {
	original := &proto.NetbirdConfig{}
	result := ExtendNetBirdConfig("peer1", original, &types.ExtraSettings{FlowEnabled: false})
	if result != original {
		t.Error("expected original config returned when flow is disabled")
	}
	if result.Flow != nil {
		t.Error("expected no flow config when flow is disabled")
	}
}

func TestExtendNetBirdConfig_FlowEnabled_NilConfig(t *testing.T) {
	setCfgForTesting(staticConfig{
		flowURL:      "tcp://localhost:9000",
		flowInterval: 10 * time.Minute,
		secret:       testSecret,
		tokenTTL:     defaultTokenTTL,
	})
	resetTokenCache()

	result := ExtendNetBirdConfig("peer1", nil, &types.ExtraSettings{FlowEnabled: true})
	if result == nil {
		t.Fatal("expected non-nil config when input config is nil")
	}
	if result.Flow == nil {
		t.Fatal("expected Flow to be set")
	}
	if !result.Flow.Enabled {
		t.Error("expected Flow.Enabled to be true")
	}
}

func TestExtendNetBirdConfig_FlowEnabled_SetsFlowFields(t *testing.T) {
	setCfgForTesting(staticConfig{
		flowURL:      "tcp://test-host:9000",
		flowInterval: 7 * time.Minute,
		secret:       testSecret,
		tokenTTL:     defaultTokenTTL,
	})
	resetTokenCache()

	result := ExtendNetBirdConfig("peer1", &proto.NetbirdConfig{}, &types.ExtraSettings{FlowEnabled: true})
	if result.Flow == nil {
		t.Fatal("expected Flow config to be set")
	}
	if result.Flow.Url != "tcp://test-host:9000" {
		t.Errorf("expected URL 'tcp://test-host:9000', got %q", result.Flow.Url)
	}
	if result.Flow.Interval.AsDuration() != 7*time.Minute {
		t.Errorf("expected interval 7m, got %v", result.Flow.Interval.AsDuration())
	}
	if result.Flow.TokenPayload == "" || result.Flow.TokenSignature == "" {
		t.Error("expected non-empty token payload and signature")
	}
}
