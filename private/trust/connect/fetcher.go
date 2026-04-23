// Copyright 2025 SCION Association, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connect

import (
	"context"
	"crypto/x509"
	"net"

	"connectrpc.com/connect"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/grpc"
)

type Fetcher struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Client is the HTTP client
	Client func(server net.Addr) connect.HTTPClient
	// BaseUrl retrieves the base URL.
	BaseUrl func(net.Addr) string
}

// Chains fetches certificate chains over the network
func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	client := control_planeconnect.NewTrustMaterialServiceClient(
		f.Client(server),
		f.BaseUrl(server),
	)
	rep, err := client.Chains(ctx, connect.NewRequest(grpc.ChainQueryToReq(query)))
	if err != nil {
		return nil, serrors.Wrap("fetching chains over connect", err)
	}
	chains, _, err := grpc.RepToChains(rep.Msg.Chains)
	if err != nil {
		return nil, serrors.Wrap("parsing chains", err)
	}
	if err := grpc.CheckChainsMatchQuery(query, chains); err != nil {
		return nil, serrors.Wrap("chains do not match query", err)
	}
	return chains, nil
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	client := control_planeconnect.NewTrustMaterialServiceClient(
		f.Client(server),
		f.BaseUrl(server),
	)
	rep, err := client.TRC(ctx, connect.NewRequest(grpc.IDToReq(id)))
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("fetching chains over connect", err)
	}
	//nolint:forbidigo // generated field.
	trc, err := cppki.DecodeSignedTRC(rep.Msg.Trc)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("parse TRC reply", err)
	}
	if trc.TRC.ID != id {
		return cppki.SignedTRC{}, serrors.New("received wrong TRC", "expected", id,
			"actual", trc.TRC.ID)
	}
	return trc, nil
}
