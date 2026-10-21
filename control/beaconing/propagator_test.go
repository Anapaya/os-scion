// Copyright 2019 Anapaya Systems
// Copyright 2025 SCION Association
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

package beaconing_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/control/beacon"
	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/control/beaconing/mock_beaconing"
	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/xtest/graph"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/discovery"
	"github.com/scionproto/scion/private/topology"
	"github.com/scionproto/scion/private/trust"
)

func TestPropagatorRunNonCore(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	beacons := [][]uint16{
		{graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_110_X_120_A, graph.If_120_X_111_B},
		{graph.If_110_X_120_A, graph.If_120_X_111_B},
	}
	// Use fewer slots than beacons to exercise the in-flight bound.
	const maxInFlight = 2

	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoNonCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	filter := func(intf *ifstate.Interface) bool {
		return intf.TopoInfo().LinkType == topology.Child
	}
	p := beaconing.Propagator{
		MaxInFlight: maxInFlight,
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(filter)
		},
		Tick:     beaconing.NewTick(time.Hour),
		Provider: provider,
	}
	g := graph.NewDefaultGraph(mctrl)
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(1).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)

	// Every Send blocks on release until the test has observed that all
	// slots are taken. The counter tracks how many sends are in flight at
	// the same time and must never exceed maxInFlight.
	var (
		inFlight    atomic.Int32
		maxObserved atomic.Int32
		slotsFull   = make(chan struct{})
		release     = make(chan struct{})
		fullOnce    sync.Once
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Times(1).DoAndReturn(

		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(len(beacons)).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					cur := inFlight.Add(1)
					defer inFlight.Add(-1)
					for {
						prev := maxObserved.Load()
						if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
							break
						}
					}
					if cur == maxInFlight {
						fullOnce.Do(func() { close(slotsFull) })
					}
					<-release
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)

			return sender, nil
		},
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(context.Background())
	}()
	select {
	case <-slotsFull:
	case <-time.After(5 * time.Second):
		t.Fatal("slots never filled up")
	}
	// All slots are taken and no send has returned yet. A third send must
	// not start while the first two block.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(maxInFlight), inFlight.Load())
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not finish")
	}
	assert.Equal(t, int32(maxInFlight), maxObserved.Load())

	// Check that no beacons are sent, since the period has not passed yet.
	p.Run(context.Background())
}

// propagatedCounter records the propagation results per result label.
type propagatedCounter struct {
	mtx      sync.Mutex
	counters map[string]*metrics.TestCounter
}

func newPropagatedCounter() *propagatedCounter {
	return &propagatedCounter{counters: make(map[string]*metrics.TestCounter)}
}

func (c *propagatedCounter) Propagated(
	_ addr.IA, _, _ uint16, result string,
) metrics.Counter {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	counter, ok := c.counters[result]
	if !ok {
		counter = metrics.NewTestCounter()
		c.counters[result] = counter
	}
	return counter
}

func (c *propagatedCounter) Value(result string) float64 {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	counter, ok := c.counters[result]
	if !ok {
		return 0
	}
	return metrics.CounterValue(counter)
}

// newTestPropagator creates a non-core propagator that propagates the given
// beacons on the child interface and reports the results to the returned
// counter. Each Send call of the sender runs the given function.
func newTestPropagator(
	t *testing.T,
	mctrl *gomock.Controller,
	beacons [][]uint16,
	send func(ctx context.Context, b *seg.PathSegment) error,
) (*beaconing.Propagator, *propagatedCounter) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	topo, err := topology.FromJSONFile(topoNonCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	filter := func(intf *ifstate.Interface) bool {
		return intf.TopoInfo().LinkType == topology.Child
	}
	counter := newPropagatedCounter()
	p := &beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(filter)
		},
		Tick:       beaconing.NewTick(time.Hour),
		Provider:   provider,
		Propagated: counter.Propagated,
	}
	g := graph.NewDefaultGraph(mctrl)
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(1).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Times(1).DoAndReturn(
		func(context.Context, addr.IA, uint16, *net.UDPAddr) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(send)
			sender.EXPECT().Close().Times(1)
			return sender, nil
		},
	)
	return p, counter
}

func TestPropagatorSendTimeout(t *testing.T) {
	beacons := [][]uint16{
		{graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_110_X_120_A, graph.If_120_X_111_B},
	}
	const sendTimeout = 100 * time.Millisecond

	mctrl := gomock.NewController(t)
	var deadlineErrs atomic.Int32
	p, counter := newTestPropagator(t, mctrl, beacons,
		// Block longer than the send timeout and report the context error.
		func(ctx context.Context, _ *seg.PathSegment) error {
			select {
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					deadlineErrs.Add(1)
				}
				return ctx.Err()
			case <-time.After(10 * sendTimeout):
				return serrors.New("send was not canceled by the send timeout")
			}
		},
	)
	p.SendTimeout = sendTimeout

	start := time.Now()
	p.Run(context.Background())
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 5*sendTimeout, "run must return shortly after the send timeout")
	assert.Equal(t, int32(len(beacons)), deadlineErrs.Load())
	assert.Equal(t, float64(len(beacons)), counter.Value(prom.ErrNetwork))
	assert.Equal(t, float64(0), counter.Value(prom.Success))
}

func TestPropagatorCanceledWhileWaitingForSlot(t *testing.T) {
	beacons := [][]uint16{
		{graph.If_120_X_111_B},
		{graph.If_130_B_120_A, graph.If_120_X_111_B},
		{graph.If_110_X_120_A, graph.If_120_X_111_B},
		{graph.If_110_X_120_A, graph.If_120_X_111_B},
	}

	mctrl := gomock.NewController(t)
	var (
		entered = make(chan struct{})
		release = make(chan struct{})
		once    sync.Once
		sends   atomic.Int32
	)
	p, counter := newTestPropagator(t, mctrl, beacons,
		// The single slot is held until the test releases it. All other
		// beacons wait for the slot.
		func(ctx context.Context, _ *seg.PathSegment) error {
			sends.Add(1)
			once.Do(func() { close(entered) })
			<-release
			return ctx.Err()
		},
	)
	p.MaxInFlight = 1

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first send never started")
	}
	// Cancel the run while the remaining beacons wait for the slot. They
	// must be counted as network errors without being sent.
	cancel()
	remaining := float64(len(beacons) - 1)
	assert.Eventually(t, func() bool {
		return counter.Value(prom.ErrNetwork) == remaining
	}, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(1), sends.Load())

	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
	assert.Equal(t, float64(len(beacons)), counter.Value(prom.ErrNetwork))
	assert.Equal(t, float64(0), counter.Value(prom.Success))
}

func TestPropagatorRunCore(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := priv.Public()

	beacons := [][]uint16{
		{graph.If_120_A_110_X},
		{graph.If_130_B_120_A, graph.If_120_A_110_X},
	}

	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	filter := func(intf *ifstate.Interface) bool {
		return intf.TopoInfo().LinkType == topology.Core
	}
	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(filter)
		},
		Tick:     beaconing.NewTick(time.Hour),
		Provider: provider,
	}
	g := graph.NewDefaultGraph(mctrl)
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(2).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			res := make([]beacon.Beacon, 0, len(beacons))
			for _, desc := range beacons {
				res = append(res, testBeacon(g, desc))
			}
			return res, nil
		},
	)

	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), graph.If_110_X_210_X,
		gomock.Any()).DoAndReturn(
		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)
			return sender, nil
		},
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), graph.If_110_X_130_A,
		gomock.Any()).DoAndReturn(
		func(_ context.Context, _ addr.IA, egIfID uint16,
			nextHop *net.UDPAddr,
		) (beaconing.Sender, error) {
			sender := mock_beaconing.NewMockSender(mctrl)
			sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
				func(ctx context.Context, b *seg.PathSegment) error {
					validateSend(ctx, t, b, egIfID, nextHop, pub, topo)
					return nil
				},
			)
			sender.EXPECT().Close().Times(1)
			return sender, nil
		},
	)
	p.Run(context.Background())
	// Check that no beacons are sent, since the period has not passed yet.
	p.Run(context.Background())
}

func TestPropagatorFastRecovery(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	beacons := [][]uint16{
		{graph.If_120_A_110_X},
		{graph.If_130_B_120_A, graph.If_120_A_110_X},
	}
	mctrl := gomock.NewController(t)
	topo, err := topology.FromJSONFile(topoCore)
	require.NoError(t, err)
	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})
	provider := mock_beaconing.NewMockBeaconProvider(mctrl)
	senderFactory := mock_beaconing.NewMockSenderFactory(mctrl)
	sender := mock_beaconing.NewMockSender(mctrl)
	filter := func(intf *ifstate.Interface) bool {
		return intf.TopoInfo().LinkType == topology.Core
	}

	p := beaconing.Propagator{
		Extender: &beaconing.DefaultExtender{
			IA:  topo.IA(),
			MTU: topo.MTU(),
			SignerGen: testSignerGen{
				Signers: []trust.Signer{testSigner(t, priv, topo.IA())},
			},
			Intfs:                intfs,
			MAC:                  macFactory,
			MaxExpTime:           func() uint8 { return beacon.DefaultMaxExpTime },
			StaticInfo:           func() *beaconing.StaticInfoCfg { return nil },
			DiscoveryInformation: func() *discovery.Extension { return nil },
		},
		SenderFactory: senderFactory,
		IA:            topo.IA(),
		Signer:        testSigner(t, priv, topo.IA()),
		AllInterfaces: intfs,
		PropagationInterfaces: func() []*ifstate.Interface {
			return intfs.Filtered(filter)
		},
		Tick:     beaconing.NewTick(2 * time.Second),
		Provider: provider,
	}

	g := graph.NewDefaultGraph(mctrl)
	// We call run 4 times in this test, since the interface to 1-ff00:0:120
	// will never be beaconed on, because the beacons are filtered for loops.
	provider.EXPECT().BeaconsToPropagate(gomock.Any()).Times(4).DoAndReturn(
		func(_ any) ([]beacon.Beacon, error) {
			return []beacon.Beacon{testBeacon(g, beacons[0])}, nil
		},
	)
	senderFactory.EXPECT().NewSender(gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).Times(5).Return(sender, nil)

	// 1. Initial run where one beacon fails to send. -> 2 calls
	// 2. Second run where the beacon is delivered. -> 1 call
	// 3. Run where no beacon is sent. -> no call
	// 4. Run where beacons are sent on all interfaces. -> 2 calls
	first := sender.EXPECT().Send(gomock.Any(), gomock.Any())
	first.Return(serrors.New("fail"))

	sender.EXPECT().Send(gomock.Any(), gomock.Any()).Times(4).Return(nil)
	sender.EXPECT().Close().Times(5)

	// Initial run. Two writes expected, one write will fail.
	p.Run(context.Background())
	time.Sleep(1 * time.Second)
	// Second run. One write expected.
	p.Run(context.Background())
	// Third run. No write expected
	p.Run(context.Background())
	time.Sleep(1 * time.Second)
	// Fourth run. Since period has passed, two writes are expected.
	p.Run(context.Background())
}

func validateSend(
	ctx context.Context,
	t *testing.T,
	b *seg.PathSegment,
	egIfID uint16,
	nextHop *net.UDPAddr,
	pub crypto.PublicKey,
	topo topology.Topology,
) {
	// Check the beacon is valid and verifiable.
	assert.NoError(t, b.Validate(seg.ValidateBeacon))
	assert.NoError(t, b.VerifyASEntry(ctx,
		segVerifier{pubKey: pub}, b.MaxIdx()))
	// Extract the hop field from the current AS entry to compare.
	hopF := b.ASEntries[b.MaxIdx()].HopEntry.HopField
	// Check the interface matches.
	assert.Equal(t, hopF.ConsEgress, egIfID)
	// Check that the beacon is sent to the correct border router.
	br := net.UDPAddrFromAddrPort(interfaceInfos(topo)[egIfID].InternalAddr)
	assert.Equal(t, br, nextHop)
}
