// Copyright 2018 ETH Zurich, Anapaya Systems
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

package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/daemon/drkey"
	"github.com/scionproto/scion/daemon/fetcher"
	"github.com/scionproto/scion/daemon/internal/servers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/metrics/v2"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/env"
	"github.com/scionproto/scion/private/revcache"
	"github.com/scionproto/scion/private/trust"
	trustgrpc "github.com/scionproto/scion/private/trust/grpc"
	trustmetrics "github.com/scionproto/scion/private/trust/metrics"
)

// InitTracer initializes the global tracer.
func InitTracer(tracing env.Tracing, id string) (io.Closer, error) {
	tracer, trCloser, err := tracing.NewTracer(id)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tracer)
	return trCloser, nil
}

// TrustEngine builds the trust engine backed by the trust database.
func TrustEngine(
	ctx context.Context,
	cfgDir string,
	ia addr.IA,
	db trust.DB,
	dialer libgrpc.Dialer,
	metrics trustmetrics.Metrics,
) (trust.Engine, error) {
	certsDir := filepath.Join(cfgDir, "certs")
	loaded, err := trust.LoadTRCs(ctx, certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.Wrap("loading TRCs", err)
	}
	log.Info("TRCs loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing TRC", "file", f)
			continue
		}
		log.Info("Ignoring non-TRC", "file", f, "reason", r)
	}
	loaded, err = trust.LoadChains(ctx, certsDir, db)
	if err != nil {
		return trust.Engine{}, serrors.Wrap("loading certificate chains",
			err)
	}
	log.Info("Certificate chains loaded", "files", loaded.Loaded)
	for f, r := range loaded.Ignored {
		if errors.Is(r, trust.ErrAlreadyExists) {
			log.Debug("Ignoring existing certificate chain", "file", f)
			continue
		}
		if errors.Is(r, trust.ErrOutsideValidity) {
			log.Debug("Ignoring certificate chain outside validity", "file", f)
			continue
		}
		log.Info("Ignoring non-certificate chain", "file", f, "reason", r)
	}
	return trust.Engine{
		Inspector: trust.DBInspector{DB: db},
		Provider: trust.FetchingProvider{
			DB: db,
			Fetcher: trustgrpc.Fetcher{
				IA:       ia,
				Dialer:   dialer,
				Requests: metrics.RPCFetches,
			},
			Recurser: trust.LocalOnlyRecurser{},
			Router:   trust.LocalRouter{IA: ia},
			Requests: metrics.ProviderRequests,
		},
		DB: db,
	}, nil
}

// ServerConfig is the configuration for the daemon API server.
type ServerConfig struct {
	IA          addr.IA
	MTU         uint16
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	Engine      trust.Engine
	Topology    servers.Topology
	DRKeyClient *drkey.ClientEngine
	Metrics     ServerMetrics
}

// NewServer constructs a daemon API server.
func NewServer(cfg ServerConfig) *servers.DaemonServer {
	return &servers.DaemonServer{
		IA:  cfg.IA,
		MTU: cfg.MTU,
		// TODO(JordiSubira): This will be changed in the future to fetch
		// the information from the CS instead of feeding the configuration
		// file into.
		Topology:    cfg.Topology,
		Fetcher:     cfg.Fetcher,
		ASInspector: cfg.Engine.Inspector,
		RevCache:    cfg.RevCache,
		DRKeyClient: cfg.DRKeyClient,
		Metrics:     cfg.Metrics.AsServerMetrics(),
	}
}

type ServerMetrics struct {
	PathsRequests              PathRequestMetrics
	ASRequests                 RequestMetrics
	InterfacesRequests         RequestMetrics
	ServicesRequests           RequestMetrics
	InterfaceDownNotifications InterfaceDownNotificationMetrics
}

func NewServerMetrics(opts ...metrics.Option) ServerMetrics {
	auto := metrics.ApplyOptions(opts...).Auto()
	pathRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_path_requests_total",
		Help: "The amount of path requests received.",
	}, []string{prom.LabelResult, prom.LabelDst})
	pathLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_path_request_duration_seconds",
		Help:    "Time to handle path requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	asRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_as_info_requests_total",
		Help: "The amount of AS requests received.",
	}, []string{prom.LabelResult})
	asLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_as_info_request_duration_seconds",
		Help:    "Time to handle AS requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	interfacesRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_if_info_requests_total",
		Help: "The amount of interfaces requests received.",
	}, []string{prom.LabelResult})
	interfacesLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_if_info_request_duration_seconds",
		Help:    "Time to handle interfaces requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	servicesRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_service_info_requests_total",
		Help: "The amount of services requests received.",
	}, []string{prom.LabelResult})
	servicesLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_service_info_request_duration_seconds",
		Help:    "Time to handle services requests.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	ifDownRequests := auto.NewCounterVec(prometheus.CounterOpts{
		Name: "sd_received_revocations_total",
		Help: "The amount of revocations received.",
	}, []string{prom.LabelResult, prom.LabelSrc})
	ifDownLatency := auto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sd_revocation_notification_duration_seconds",
		Help:    "Time to handle interface down notifications.",
		Buckets: prom.DefaultLatencyBuckets,
	}, []string{prom.LabelResult})

	return ServerMetrics{
		PathsRequests: PathRequestMetrics{
			Requests: func(result string, dstISD addr.ISD) metrics.Counter {
				return pathRequests.With(prometheus.Labels{
					prom.LabelResult: result,
					prom.LabelDst:    dstISD.String(),
				})
			},
			Latency: func(result string) metrics.Histogram {
				return pathLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		ASRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return asRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return asLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		InterfacesRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return interfacesRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return interfacesLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		ServicesRequests: RequestMetrics{
			Requests: func(result string) metrics.Counter {
				return servicesRequests.With(prometheus.Labels{prom.LabelResult: result})
			},
			Latency: func(result string) metrics.Histogram {
				return servicesLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
		InterfaceDownNotifications: InterfaceDownNotificationMetrics{
			Requests: func(result, src string) metrics.Counter {
				return ifDownRequests.With(prometheus.Labels{
					prom.LabelResult: result,
					prom.LabelSrc:    src,
				})
			},
			Latency: func(result string) metrics.Histogram {
				return ifDownLatency.With(prometheus.Labels{prom.LabelResult: result})
			},
		},
	}
}

func (m ServerMetrics) AsServerMetrics() servers.Metrics {
	return servers.Metrics{
		PathsRequests:      servers.PathRequestMetrics(m.PathsRequests),
		ASRequests:         servers.RequestMetrics(m.ASRequests),
		InterfacesRequests: servers.RequestMetrics(m.InterfacesRequests),
		ServicesRequests:   servers.RequestMetrics(m.ServicesRequests),
		InterfaceDownNotifications: servers.InterfaceDownNotificationMetrics(
			m.InterfaceDownNotifications,
		),
	}
}

type RequestMetrics struct {
	Requests func(result string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

type PathRequestMetrics struct {
	Requests func(result string, dstISD addr.ISD) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

type InterfaceDownNotificationMetrics struct {
	Requests func(result, src string) metrics.Counter
	Latency  func(result string) metrics.Histogram
}

// APIAddress returns the API address to listen on, based on the provided
// address. Addresses with missing or zero port are returned with the default
// daemon port. All other addresses are returned without modification. If the
// input is garbage, the output will also be garbage.
func APIAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	switch {
	case err != nil:
		return net.JoinHostPort(listen, strconv.Itoa(daemon.DefaultAPIPort))
	case port == "0", port == "":
		return net.JoinHostPort(host, strconv.Itoa(daemon.DefaultAPIPort))
	default:
		return listen
	}
}
