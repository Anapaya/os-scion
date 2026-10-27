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
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/trust"
	"github.com/scionproto/scion/private/trust/grpc"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

type Fetcher struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Client returns the HTTP client for the server. The fetcher closes the
	// client after the RPC. To use one client for many RPCs, return a client
	// whose Close method does nothing.
	Client func(server net.Addr) libconnect.Client
	// BaseUrl retrieves the base URL.
	BaseUrl func(net.Addr) string
	// Options are added to the options of the connect client.
	Options []connect.ClientOption

	// Requests aggregates all the outgoing requests sent by the fetcher.
	// If it is not initialized, nothing is reported.
	Requests func(reqType, peer, result string) metrics.Counter
}

// Chains fetches certificate chains over the network
func (f Fetcher) Chains(ctx context.Context, query trust.ChainQuery,
	server net.Addr) ([][]*x509.Certificate, error) {

	httpClient := f.Client(server)
	defer httpClient.Close()
	client := control_planeconnect.NewTrustMaterialServiceClient(
		httpClient,
		f.BaseUrl(server),
		f.Options...,
	)
	rep, err := client.Chains(ctx, connect.NewRequest(grpc.ChainQueryToReq(query)))
	if err != nil {
		f.updateMetric(trustmetrics.ChainReq, server, trustmetrics.TransmitResult(ctx))
		return nil, serrors.Wrap("fetching chains over connect", err)
	}
	chains, res, err := grpc.RepToChains(rep.Msg.Chains)
	if err != nil {
		f.updateMetric(trustmetrics.ChainReq, server, res)
		return nil, serrors.Wrap("parsing chains", err)
	}
	if err := grpc.CheckChainsMatchQuery(query, chains); err != nil {
		f.updateMetric(trustmetrics.ChainReq, server, trustmetrics.ErrMismatch)
		return nil, serrors.Wrap("chains do not match query", err)
	}
	f.updateMetric(trustmetrics.ChainReq, server, trustmetrics.Success)
	return chains, nil
}

func (f Fetcher) TRC(ctx context.Context, id cppki.TRCID,
	server net.Addr) (cppki.SignedTRC, error) {

	httpClient := f.Client(server)
	defer httpClient.Close()
	client := control_planeconnect.NewTrustMaterialServiceClient(
		httpClient,
		f.BaseUrl(server),
		f.Options...,
	)
	rep, err := client.TRC(ctx, connect.NewRequest(grpc.IDToReq(id)))
	if err != nil {
		f.updateMetric(trustmetrics.TRCReq, server, trustmetrics.TransmitResult(ctx))
		return cppki.SignedTRC{}, serrors.Wrap("fetching TRC over connect", err)
	}
	//nolint:forbidigo // generated field.
	trc, err := cppki.DecodeSignedTRC(rep.Msg.Trc)
	if err != nil {
		f.updateMetric(trustmetrics.TRCReq, server, trustmetrics.ErrParse)
		return cppki.SignedTRC{}, serrors.Wrap("parse TRC reply", err)
	}
	if trc.TRC.ID != id {
		f.updateMetric(trustmetrics.TRCReq, server, trustmetrics.ErrMismatch)
		return cppki.SignedTRC{}, serrors.New("received wrong TRC", "expected", id,
			"actual", trc.TRC.ID)
	}
	f.updateMetric(trustmetrics.TRCReq, server, trustmetrics.Success)
	return trc, nil
}

func (f Fetcher) updateMetric(reqType string, server net.Addr, result string) {
	if f.Requests != nil {
		metrics.CounterInc(f.Requests(reqType, trustmetrics.PeerToLabel(server, f.IA), result))
	}
}
