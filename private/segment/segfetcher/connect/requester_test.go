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
	"net"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/squic"
	"github.com/scionproto/scion/private/segment/segfetcher"
	segfetcherconnect "github.com/scionproto/scion/private/segment/segfetcher/connect"
)

func TestRequesterOptions(t *testing.T) {
	var interceptor recordingInterceptor
	r := segfetcherconnect.Requester{
		Dialer: failingDialer,
		Options: []connect.ClientOption{
			connect.WithInterceptors(connect.UnaryInterceptorFunc(interceptor.Intercept)),
		},
	}
	server := &snet.UDPAddr{
		IA:   addr.MustParseIA("1-ff00:0:110"),
		Host: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 31000},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := r.Segments(ctx, segfetcher.Request{
		Src: addr.MustParseIA("1-ff00:0:111"),
		Dst: addr.MustParseIA("1-ff00:0:110"),
	}, server)
	assert.Error(t, err)
	assert.Equal(t, []string{
		control_planeconnect.SegmentLookupServiceSegmentsProcedure,
	}, interceptor.Procedures)
}

// failingDialer returns a dialer that fails to dial, because it cannot
// resolve the address.
func failingDialer(net.Addr, ...squic.EarlyDialerOption) squic.EarlyDialer {
	return squic.EarlyDialer{Rewriter: failingRewriter{}}
}

type failingRewriter struct{}

func (failingRewriter) RedirectToQUIC(context.Context, net.Addr) (net.Addr, error) {
	return nil, serrors.New("no route")
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
