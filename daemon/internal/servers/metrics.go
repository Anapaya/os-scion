// Copyright 2018 ETH Zurich, Anapaya Systems
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

package servers

import (
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Metrics can be used to inject metrics into the SCION daemon server. Each
// field may be set individually.
type Metrics struct {
	PathsRequests              PathRequestMetrics
	ASRequests                 RequestMetrics
	InterfacesRequests         RequestMetrics
	ServicesRequests           RequestMetrics
	InterfaceDownNotifications InterfaceDownNotificationMetrics
}

// RequestMetrics contains the metrics for a given request.
type RequestMetrics struct {
	Requests func(result string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m RequestMetrics) inc(result string, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type PathRequestMetrics struct {
	Requests func(result string, dstISD addr.ISD) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m PathRequestMetrics) inc(result string, dstISD addr.ISD, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result, dstISD))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type InterfaceDownNotificationMetrics struct {
	Requests func(result, src string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

func (m InterfaceDownNotificationMetrics) inc(result, src string, latency float64) {
	if m.Requests != nil {
		metrics.CounterInc(m.Requests(result, src))
	}
	if m.Latency != nil {
		metrics.HistogramObserve(m.Latency(result), latency)
	}
}

type metricsError struct {
	err    error
	result string
}

func (e metricsError) Error() string {
	return e.err.Error()
}

func errToMetricResult(err error) string {
	if err == nil {
		return prom.Success
	}
	if merr, ok := err.(metricsError); ok && merr.result != "" {
		if serrors.IsTimeout(merr.err) {
			return prom.ErrTimeout
		}
		return merr.result
	}
	if serrors.IsTimeout(err) {
		return prom.ErrTimeout
	}
	return prom.ErrNotClassified
}

func unwrapMetricsError(err error) error {
	if err == nil {
		return nil
	}
	if merr, ok := err.(metricsError); ok {
		return merr.err
	}
	return err
}
