// Copyright 2026 Anapaya Systems
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

package connect_test

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	libconnect "github.com/scionproto/scion/pkg/connect"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/trust"
	trustconnect "github.com/scionproto/scion/private/trust/connect"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

var (
	localIA = addr.MustParseIA("1-ff00:0:110")
	// server is in the same ISD as localIA. Thus, its peer label is
	// "isd_local".
	server = &snet.UDPAddr{
		IA:   addr.MustParseIA("1-ff00:0:111"),
		Host: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31000},
	}
)

func TestFetcherChains(t *testing.T) {
	dir := genCrypto(t)
	chain110 := xtest.LoadChain(t, filepath.Join(dir, "/certs/ISD1-ASff00_0_110.pem"))
	chain112 := xtest.LoadChain(t, filepath.Join(dir, "/certs/ISD1-ASff00_0_112.pem"))
	queryDate := chain110[0].NotBefore.Add(time.Hour)
	query := trust.ChainQuery{
		IA:           localIA,
		SubjectKeyID: chain110[0].SubjectKeyId,
		Validity: cppki.Validity{
			NotBefore: queryDate,
			NotAfter:  queryDate,
		},
	}

	testCases := map[string]struct {
		Handler   trustHandler
		Query     trust.ChainQuery
		Assertion assert.ErrorAssertionFunc
		Expected  [][]*x509.Certificate
		Result    string
	}{
		"RPC fail": {
			Handler: trustHandler{
				Err: connect.NewError(connect.CodeInternal, serrors.New("internal")),
			},
			Query:     query,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrTransmit,
		},
		"garbage chain": {
			Handler: trustHandler{
				ChainsRep: &cppb.ChainsResponse{Chains: []*cppb.Chain{{}}},
			},
			Query:     query,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrParse,
		},
		"mismatching subject": {
			Handler: trustHandler{
				ChainsRep: &cppb.ChainsResponse{
					Chains: []*cppb.Chain{{
						AsCert: chain112[0].Raw,
						CaCert: chain112[1].Raw,
					}},
				},
			},
			Query:     query,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrMismatch,
		},
		"reply wrong validity": {
			Handler: trustHandler{
				ChainsRep: &cppb.ChainsResponse{
					Chains: []*cppb.Chain{{
						AsCert: chain110[0].Raw,
						CaCert: chain110[1].Raw,
					}},
				},
			},
			Query: trust.ChainQuery{
				IA:           localIA,
				SubjectKeyID: chain110[0].SubjectKeyId,
				Validity: cppki.Validity{
					NotBefore: chain110[0].NotBefore.Add(-time.Hour),
					NotAfter:  chain110[0].NotBefore.Add(-time.Hour),
				},
			},
			Assertion: assert.Error,
			Result:    trustmetrics.ErrMismatch,
		},
		"valid single chain": {
			Handler: trustHandler{
				ChainsRep: &cppb.ChainsResponse{
					Chains: []*cppb.Chain{{
						AsCert: chain110[0].Raw,
						CaCert: chain110[1].Raw,
					}},
				},
			},
			Query:     query,
			Assertion: assert.NoError,
			Expected:  [][]*x509.Certificate{chain110},
			Result:    trustmetrics.Success,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests requestRecorder
			f := newServerFetcher(t, tc.Handler, requests.Requests)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			chains, err := f.Chains(ctx, tc.Query, server)
			tc.Assertion(t, err)
			assert.Equal(t, tc.Expected, chains)
			assert.Equal(t, []requestLabels{{
				Type:   trustmetrics.ChainReq,
				Peer:   "isd_local",
				Result: tc.Result,
			}}, requests.Labels)
		})
	}
}

func TestFetcherTRC(t *testing.T) {
	dir := genCrypto(t)
	updated := xtest.LoadTRC(t, filepath.Join(dir, "/trcs/ISD1-B1-S2.trc"))
	// The TRC files are PEM encoded. Use the DER encoding of the base TRC, such
	// that the fetcher can decode it and detects the wrong ID.
	base := xtest.LoadTRC(t, filepath.Join(dir, "/trcs/ISD1-B1-S1.trc"))

	testCases := map[string]struct {
		Handler   trustHandler
		ID        cppki.TRCID
		Assertion assert.ErrorAssertionFunc
		Expected  cppki.SignedTRC
		Result    string
	}{
		"RPC fail": {
			Handler: trustHandler{
				Err: connect.NewError(connect.CodeInternal, serrors.New("internal")),
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrTransmit,
		},
		"garbage TRC": {
			Handler: trustHandler{
				TRCRep: &cppb.TRCResponse{
					Trc: []byte("garbage"), // nolint - name from published protobuf
				},
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrParse,
		},
		"mismatching ID": {
			Handler: trustHandler{
				TRCRep: &cppb.TRCResponse{
					Trc: base.Raw, // nolint - name from published protobuf
				},
			},
			ID:        updated.TRC.ID,
			Assertion: assert.Error,
			Result:    trustmetrics.ErrMismatch,
		},
		"valid TRC": {
			Handler: trustHandler{
				TRCRep: &cppb.TRCResponse{
					Trc: updated.Raw, // nolint - name from published protobuf
				},
			},
			ID:        updated.TRC.ID,
			Assertion: assert.NoError,
			Expected:  updated,
			Result:    trustmetrics.Success,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests requestRecorder
			f := newServerFetcher(t, tc.Handler, requests.Requests)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			trc, err := f.TRC(ctx, tc.ID, server)
			tc.Assertion(t, err)
			assert.Equal(t, tc.Expected, trc)
			assert.Equal(t, []requestLabels{{
				Type:   trustmetrics.TRCReq,
				Peer:   "isd_local",
				Result: tc.Result,
			}}, requests.Labels)
		})
	}
}

func TestFetcherCanceled(t *testing.T) {
	testCases := map[string]struct {
		Call func(context.Context, trustconnect.Fetcher) error
		Type string
	}{
		"chains": {
			Call: func(ctx context.Context, f trustconnect.Fetcher) error {
				_, err := f.Chains(ctx, trust.ChainQuery{}, server)
				return err
			},
			Type: trustmetrics.ChainReq,
		},
		"trc": {
			Call: func(ctx context.Context, f trustconnect.Fetcher) error {
				_, err := f.TRC(ctx, cppki.TRCID{}, server)
				return err
			},
			Type: trustmetrics.TRCReq,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var requests requestRecorder
			f := newServerFetcher(t, trustHandler{}, requests.Requests)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			assert.Error(t, tc.Call(ctx, f))
			assert.Equal(t, []requestLabels{{
				Type:   tc.Type,
				Peer:   "isd_local",
				Result: trustmetrics.Canceled,
			}}, requests.Labels)
		})
	}
}

func TestFetcherNilRequests(t *testing.T) {
	f := newServerFetcher(t, trustHandler{}, nil)
	_, err := f.Chains(context.Background(), trust.ChainQuery{}, server)
	assert.Error(t, err)
	_, err = f.TRC(context.Background(), cppki.TRCID{}, server)
	assert.Error(t, err)
}

func TestFetcherOptions(t *testing.T) {
	var interceptor recordingInterceptor
	f := newServerFetcher(t, trustHandler{}, nil)
	f.Options = []connect.ClientOption{
		connect.WithInterceptors(connect.UnaryInterceptorFunc(interceptor.Intercept)),
	}
	_, err := f.Chains(context.Background(), trust.ChainQuery{}, server)
	assert.Error(t, err)
	_, err = f.TRC(context.Background(), cppki.TRCID{}, server)
	assert.Error(t, err)
	assert.Equal(t, []string{
		control_planeconnect.TrustMaterialServiceChainsProcedure,
		control_planeconnect.TrustMaterialServiceTRCProcedure,
	}, interceptor.Procedures)
}

func TestFetcherClosesClient(t *testing.T) {
	testCases := map[string]func(trustconnect.Fetcher) error{
		"chains": func(f trustconnect.Fetcher) error {
			_, err := f.Chains(context.Background(), trust.ChainQuery{}, server)
			return err
		},
		"trc": func(f trustconnect.Fetcher) error {
			_, err := f.TRC(context.Background(), cppki.TRCID{}, server)
			return err
		},
	}
	for name, call := range testCases {
		t.Run(name, func(t *testing.T) {
			client := &closingClient{}
			f := trustconnect.Fetcher{
				IA:      localIA,
				Client:  func(net.Addr) libconnect.Client { return client },
				BaseUrl: func(net.Addr) string { return "http://localhost" },
			}
			assert.Error(t, call(f))
			assert.Equal(t, 1, client.closed)
		})
	}
}

// newServerFetcher starts an HTTP server with the handler and returns a
// fetcher that sends its requests to that server.
func newServerFetcher(
	t *testing.T,
	h control_planeconnect.TrustMaterialServiceHandler,
	requests func(reqType, peer, result string) metrics.Counter,
) trustconnect.Fetcher {

	mux := http.NewServeMux()
	mux.Handle(control_planeconnect.NewTrustMaterialServiceHandler(h))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := sharedClient{HTTPClient: srv.Client()}
	return trustconnect.Fetcher{
		IA:       localIA,
		Client:   func(net.Addr) libconnect.Client { return client },
		BaseUrl:  func(net.Addr) string { return srv.URL },
		Requests: requests,
	}
}

// trustHandler returns Err if it is set. Otherwise, it returns ChainsRep and
// TRCRep. If the response is not set, it returns an unimplemented error.
type trustHandler struct {
	control_planeconnect.UnimplementedTrustMaterialServiceHandler
	ChainsRep *cppb.ChainsResponse
	TRCRep    *cppb.TRCResponse
	Err       error
}

func (h trustHandler) Chains(
	ctx context.Context,
	req *connect.Request[cppb.ChainsRequest],
) (*connect.Response[cppb.ChainsResponse], error) {

	if h.Err != nil {
		return nil, h.Err
	}
	if h.ChainsRep == nil {
		return h.UnimplementedTrustMaterialServiceHandler.Chains(ctx, req)
	}
	return connect.NewResponse(h.ChainsRep), nil
}

func (h trustHandler) TRC(
	ctx context.Context,
	req *connect.Request[cppb.TRCRequest],
) (*connect.Response[cppb.TRCResponse], error) {

	if h.Err != nil {
		return nil, h.Err
	}
	if h.TRCRep == nil {
		return h.UnimplementedTrustMaterialServiceHandler.TRC(ctx, req)
	}
	return connect.NewResponse(h.TRCRep), nil
}

type requestLabels struct {
	Type   string
	Peer   string
	Result string
}

// requestRecorder records the labels of each request metric.
type requestRecorder struct {
	Labels []requestLabels
}

func (r *requestRecorder) Requests(reqType, peer, result string) metrics.Counter {
	r.Labels = append(r.Labels, requestLabels{Type: reqType, Peer: peer, Result: result})
	return metrics.NewTestCounter()
}

// recordingInterceptor records the procedure of each unary call.
type recordingInterceptor struct {
	Procedures []string
}

func (i *recordingInterceptor) Intercept(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		i.Procedures = append(i.Procedures, req.Spec().Procedure)
		return next(ctx, req)
	}
}

// sharedClient is an HTTP client for many RPCs. Its Close method does nothing.
type sharedClient struct {
	connect.HTTPClient
}

func (sharedClient) Close() error {
	return nil
}

// closingClient is an HTTP client that fails every request and counts the
// calls to Close.
type closingClient struct {
	closed int
}

func (*closingClient) Do(*http.Request) (*http.Response, error) {
	return nil, serrors.New("no network")
}

func (c *closingClient) Close() error {
	c.closed++
	return nil
}
