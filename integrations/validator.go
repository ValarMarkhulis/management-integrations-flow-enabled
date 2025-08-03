package integrations

import (
	"context"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

type IntegratedValidatorImpl struct {
}

func NewIntegratedValidator(_ context.Context, store activity.Store) (*IntegratedValidatorImpl, error) {
	return &IntegratedValidatorImpl{}, nil
}

func (v *IntegratedValidatorImpl) ValidateExtraSettings(context.Context, *types.ExtraSettings, *types.ExtraSettings, map[string]*nbpeer.Peer, string, string) error {
	return nil
}

func (v *IntegratedValidatorImpl) ValidatePeer(_ context.Context, update *nbpeer.Peer, _ *nbpeer.Peer, _ string, _ string, _ string, _ []string, _ *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	return update, false, nil
}

func (v *IntegratedValidatorImpl) PreparePeer(_ context.Context, _ string, peer *nbpeer.Peer, _ []string, _ *types.ExtraSettings) *nbpeer.Peer {
	return peer.Copy()
}

func (v *IntegratedValidatorImpl) IsNotValidPeer(_ context.Context, _ string, _ *nbpeer.Peer, _ []string, _ *types.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

func (v *IntegratedValidatorImpl) GetValidatedPeers(_ context.Context, _ string, _ []*types.Group, peers []*nbpeer.Peer, _ *types.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for _, p := range peers {
		validatedPeers[p.ID] = struct{}{}
	}
	return validatedPeers, nil
}

func (v *IntegratedValidatorImpl) PeerDeleted(ctx context.Context, _, _ string, extraSettings *types.ExtraSettings) error {
	return nil
}

func (v *IntegratedValidatorImpl) SetPeerInvalidationListener(_ func(accountID string)) {

}

func (v *IntegratedValidatorImpl) Stop(ctx context.Context) {
}

func (v *IntegratedValidatorImpl) ValidateFlowResponse(ctx context.Context, peerKey string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow {
	return flowResponse
}
