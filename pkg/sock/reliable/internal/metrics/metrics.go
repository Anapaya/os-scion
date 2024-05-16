// Copyright 2019 ETH Zurich
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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Namespace is the metrics namespace for the metrics in this package.
const Namespace = "lib"

const sub = "reliable"

var (
	// M exposes all the initialized metrics for this package.
	M = newMetrics()
)

// DialLabels contains the labels for Dial calls.
type DialLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l DialLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l DialLabels) Values() []string {
	return []string{l.Result}
}

// RegisterLabels contains the labels for Register calls.
type RegisterLabels struct {
	Result string
	SVC    string
}

// Labels returns the list of labels.
func (l RegisterLabels) Labels() []string {
	return []string{prom.LabelResult, "svc"}
}

// Values returns the label values in the order defined by Labels.
func (l RegisterLabels) Values() []string {
	return []string{l.Result, l.SVC}
}

// IOLabels contains the labels for Read and Write calls.
type IOLabels struct {
	Result string
}

// Labels returns the list of labels.
func (l IOLabels) Labels() []string {
	return []string{prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l IOLabels) Values() []string {
	return []string{l.Result}
}

type metrics struct {
	dials         *prometheus.CounterVec
	registers     *prometheus.CounterVec
	readsSuccess  prometheus.Observer
	readsTimeout  prometheus.Observer
	readsErrors   prometheus.Observer
	writesSuccess prometheus.Observer
	writesTimeout prometheus.Observer
	writesErrors  prometheus.Observer
}

func newMetrics() metrics {
	readsHist := prom.NewHistogramVecWithLabels(Namespace, sub, "reads_total",
		"Total number of Read calls", IOLabels{}, prom.DefaultSizeBuckets)
	writesHist := prom.NewHistogramVecWithLabels(Namespace, sub, "writes_total",
		"Total number of Write calls", IOLabels{}, prom.DefaultSizeBuckets)

	return metrics{
		dials: prom.NewCounterVecWithLabels(Namespace, sub, "dials_total",
			"Total number of Dial calls.", DialLabels{}),
		registers: prom.NewCounterVecWithLabels(Namespace, sub, "registers_total",
			"Total number of Register calls.", RegisterLabels{}),
		readsSuccess:  readsHist.WithLabelValues(prom.Success),
		readsTimeout:  readsHist.WithLabelValues(prom.ErrTimeout),
		readsErrors:   readsHist.WithLabelValues(prom.ErrNotClassified),
		writesSuccess: writesHist.WithLabelValues(prom.Success),
		writesTimeout: writesHist.WithLabelValues(prom.ErrTimeout),
		writesErrors:  writesHist.WithLabelValues(prom.ErrNotClassified),
	}
}

func (m metrics) Dials(l DialLabels) prometheus.Counter {
	return m.dials.WithLabelValues(l.Values()...)
}

func (m metrics) Registers(l RegisterLabels) prometheus.Counter {
	return m.registers.WithLabelValues(l.Values()...)
}

func (m metrics) Reads(err error) prometheus.Observer {
	switch {
	case err == nil:
		return m.readsSuccess
	case serrors.IsTimeout(err):
		return m.readsTimeout
	default:
		return m.readsErrors
	}
}

func (m metrics) Writes(err error) prometheus.Observer {
	switch {
	case err == nil:
		return m.writesSuccess
	case serrors.IsTimeout(err):
		return m.writesTimeout
	default:
		return m.writesErrors
	}
}
