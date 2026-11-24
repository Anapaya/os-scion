// Copyright 2020 Anapaya Systems
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

package grpc

import (
	"context"
	"runtime/debug"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/grpc-ecosystem/grpc-opentracing/go/otgrpc"
	opentracing "github.com/opentracing/opentracing-go"
	jaeger "github.com/uber/jaeger-client-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/scionproto/scion/pkg/log"
)

func LogIDClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, resp any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Outgoing RPC", "method", method, "target", cc.Target())
		ctx = log.CtxWith(ctx, logger)
		return invoker(ctx, method, req, resp, cc, opts...)
	}
}

func LogIDClientStreamInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {

		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Outgoing RPC", "method", method, "target", cc.Target())
		ctx = log.CtxWith(ctx, logger)

		return streamer(ctx, desc, cc, method, opts...)
	}
}

func LogIDServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Serving RPC", "method", info.FullMethod)
		ctx = log.CtxWith(ctx, logger)
		return handler(ctx, req)
	}
}

func LogIDServerStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {

		ctx := ss.Context()
		logger := loggerFromSpan(opentracing.SpanFromContext(ctx))
		logger.Debug("Serving RPC", "method", info.FullMethod)
		ctx = log.CtxWith(ctx, logger)

		ss = &serverStream{
			ServerStream: ss,
			ctx:          ctx,
		}
		return handler(srv, ss)
	}
}

func loggerFromSpan(span opentracing.Span) log.Logger {
	if span == nil {
		return log.New("debug_id", log.NewDebugID())
	}
	spanCtx, ok := span.Context().(jaeger.SpanContext)
	if !ok {
		return log.New("debug_id", log.NewDebugID())
	}
	id := spanCtx.TraceID()
	return log.New("debug_id", log.NewDebugID(), "trace_id", id)
}

func openTracingInterceptorWithTarget() grpc.UnaryClientInterceptor {
	// Need to declare a new function here because the span decorator binds to one of the
	// args of the previous interceptor.
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		spanDecorator := func(
			span opentracing.Span,
			method string,
			req, resp any,
			grpcError error,
		) {
			if span != nil {
				span.SetTag("target", cc.Target())
			}
		}

		return otgrpc.OpenTracingClientInterceptor(
			opentracing.GlobalTracer(),
			otgrpc.SpanDecorator(spanDecorator),
		)(ctx, method, req, reply, cc, invoker, opts...)
	}
}

// UnaryClientInterceptor constructs the default unary RPC client-side interceptor for
// SCION control-plane applications.
func UnaryClientInterceptor(extraInterceptors ...grpc.UnaryClientInterceptor) grpc.DialOption {
	return grpc.WithChainUnaryInterceptor(
		append([]grpc.UnaryClientInterceptor{
			grpc_retry.UnaryClientInterceptor(
				grpc_retry.WithMax(3),
			),
			openTracingInterceptorWithTarget(),
			LogIDClientInterceptor(),
		}, extraInterceptors...)...)
}

// StreamClientInterceptor constructs the default stream RPC client-side interceptor for
// SCION control-plane applications.
func StreamClientInterceptor(extraInterceptors ...grpc.StreamClientInterceptor) grpc.DialOption {
	return grpc.WithChainStreamInterceptor(
		append([]grpc.StreamClientInterceptor{
			otgrpc.OpenTracingStreamClientInterceptor(opentracing.GlobalTracer()),
			LogIDClientStreamInterceptor(),
		}, extraInterceptors...)...)
}

// DefaultMaxConcurrentStreams constructs the default grpc.MaxConcurrentStreams Server Option.
// grpc-go prohibits more than MaxConcurrentStreams handlers from running at once, and setting this
// option so prevents easy resource exhaustion attacks from malicious clients.
func DefaultMaxConcurrentStreams() grpc.ServerOption {
	// A very generic default value; this is the default that nginx appears to use.
	return grpc.MaxConcurrentStreams(128)
}

// UnaryServerInterceptor constructs the default unary RPC server-side interceptor for
// SCION control-plane applications.
func UnaryServerInterceptor(extraInterceptors ...grpc.UnaryServerInterceptor) grpc.ServerOption {
	interceptors := []grpc.UnaryServerInterceptor{
		otgrpc.OpenTracingServerInterceptor(opentracing.GlobalTracer()),
		LogIDServerInterceptor(),
	}
	interceptors = append(interceptors, extraInterceptors...)
	// Recovery runs last so that the other interceptors still observe the RPC
	// failing with codes.Internal.
	interceptors = append(interceptors, RecoveryServerInterceptor())
	return grpc.ChainUnaryInterceptor(interceptors...)
}

// RecoveryServerInterceptor constructs a unary RPC server-side interceptor that
// recovers from panics in the RPC handler. The panic and its stack trace are
// logged, and the RPC fails with codes.Internal instead of crashing the
// process. It only covers the handler's goroutine; panics in goroutines
// spawned by the handler are not recovered.
func RecoveryServerInterceptor() grpc.UnaryServerInterceptor {
	return grpc_recovery.UnaryServerInterceptor(
		grpc_recovery.WithRecoveryHandlerContext(recoverPanic),
	)
}

func recoverPanic(ctx context.Context, p any) error {
	log.FromCtx(ctx).Error("Recovered from panic in RPC handler",
		"panic", p, "stack", string(debug.Stack()))
	return status.Error(codes.Internal, "internal error")
}

// StreamServerInterceptor constructs the default stream RPC server-side interceptor for
// SCION control-plane applications.
func StreamServerInterceptor(extraInterceptors ...grpc.StreamServerInterceptor) grpc.ServerOption {
	return grpc.ChainStreamInterceptor(
		append([]grpc.StreamServerInterceptor{
			otgrpc.OpenTracingStreamServerInterceptor(opentracing.GlobalTracer()),
			LogIDServerStreamInterceptor(),
		}, extraInterceptors...)...)
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss *serverStream) Context() context.Context {
	return ss.ctx
}
