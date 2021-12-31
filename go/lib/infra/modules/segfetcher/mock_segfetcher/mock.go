// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/infra/modules/segfetcher (interfaces: DstProvider,ReplyHandler,Requester,Resolver,RPC,Splitter,LocalInfo)

// Package mock_segfetcher is a generated GoMock package.
package mock_segfetcher

import (
	context "context"
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	segfetcher "github.com/scionproto/scion/go/lib/infra/modules/segfetcher"
	seghandler "github.com/scionproto/scion/go/lib/infra/modules/seghandler"
)

// MockDstProvider is a mock of DstProvider interface.
type MockDstProvider struct {
	ctrl     *gomock.Controller
	recorder *MockDstProviderMockRecorder
}

// MockDstProviderMockRecorder is the mock recorder for MockDstProvider.
type MockDstProviderMockRecorder struct {
	mock *MockDstProvider
}

// NewMockDstProvider creates a new mock instance.
func NewMockDstProvider(ctrl *gomock.Controller) *MockDstProvider {
	mock := &MockDstProvider{ctrl: ctrl}
	mock.recorder = &MockDstProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDstProvider) EXPECT() *MockDstProviderMockRecorder {
	return m.recorder
}

// Dst mocks base method.
func (m *MockDstProvider) Dst(arg0 context.Context, arg1 segfetcher.Request) (net.Addr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Dst", arg0, arg1)
	ret0, _ := ret[0].(net.Addr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Dst indicates an expected call of Dst.
func (mr *MockDstProviderMockRecorder) Dst(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Dst", reflect.TypeOf((*MockDstProvider)(nil).Dst), arg0, arg1)
}

// MockReplyHandler is a mock of ReplyHandler interface.
type MockReplyHandler struct {
	ctrl     *gomock.Controller
	recorder *MockReplyHandlerMockRecorder
}

// MockReplyHandlerMockRecorder is the mock recorder for MockReplyHandler.
type MockReplyHandlerMockRecorder struct {
	mock *MockReplyHandler
}

// NewMockReplyHandler creates a new mock instance.
func NewMockReplyHandler(ctrl *gomock.Controller) *MockReplyHandler {
	mock := &MockReplyHandler{ctrl: ctrl}
	mock.recorder = &MockReplyHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReplyHandler) EXPECT() *MockReplyHandlerMockRecorder {
	return m.recorder
}

// Handle mocks base method.
func (m *MockReplyHandler) Handle(arg0 context.Context, arg1 seghandler.Segments, arg2 net.Addr) *seghandler.ProcessedResult {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Handle", arg0, arg1, arg2)
	ret0, _ := ret[0].(*seghandler.ProcessedResult)
	return ret0
}

// Handle indicates an expected call of Handle.
func (mr *MockReplyHandlerMockRecorder) Handle(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Handle", reflect.TypeOf((*MockReplyHandler)(nil).Handle), arg0, arg1, arg2)
}

// MockRequester is a mock of Requester interface.
type MockRequester struct {
	ctrl     *gomock.Controller
	recorder *MockRequesterMockRecorder
}

// MockRequesterMockRecorder is the mock recorder for MockRequester.
type MockRequesterMockRecorder struct {
	mock *MockRequester
}

// NewMockRequester creates a new mock instance.
func NewMockRequester(ctrl *gomock.Controller) *MockRequester {
	mock := &MockRequester{ctrl: ctrl}
	mock.recorder = &MockRequesterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRequester) EXPECT() *MockRequesterMockRecorder {
	return m.recorder
}

// Request mocks base method.
func (m *MockRequester) Request(arg0 context.Context, arg1 segfetcher.Requests) <-chan segfetcher.ReplyOrErr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Request", arg0, arg1)
	ret0, _ := ret[0].(<-chan segfetcher.ReplyOrErr)
	return ret0
}

// Request indicates an expected call of Request.
func (mr *MockRequesterMockRecorder) Request(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Request", reflect.TypeOf((*MockRequester)(nil).Request), arg0, arg1)
}

// MockResolver is a mock of Resolver interface.
type MockResolver struct {
	ctrl     *gomock.Controller
	recorder *MockResolverMockRecorder
}

// MockResolverMockRecorder is the mock recorder for MockResolver.
type MockResolverMockRecorder struct {
	mock *MockResolver
}

// NewMockResolver creates a new mock instance.
func NewMockResolver(ctrl *gomock.Controller) *MockResolver {
	mock := &MockResolver{ctrl: ctrl}
	mock.recorder = &MockResolverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResolver) EXPECT() *MockResolverMockRecorder {
	return m.recorder
}

// Resolve mocks base method.
func (m *MockResolver) Resolve(arg0 context.Context, arg1 segfetcher.Requests, arg2 bool) (segfetcher.Segments, segfetcher.Requests, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolve", arg0, arg1, arg2)
	ret0, _ := ret[0].(segfetcher.Segments)
	ret1, _ := ret[1].(segfetcher.Requests)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Resolve indicates an expected call of Resolve.
func (mr *MockResolverMockRecorder) Resolve(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolve", reflect.TypeOf((*MockResolver)(nil).Resolve), arg0, arg1, arg2)
}

// MockRPC is a mock of RPC interface.
type MockRPC struct {
	ctrl     *gomock.Controller
	recorder *MockRPCMockRecorder
}

// MockRPCMockRecorder is the mock recorder for MockRPC.
type MockRPCMockRecorder struct {
	mock *MockRPC
}

// NewMockRPC creates a new mock instance.
func NewMockRPC(ctrl *gomock.Controller) *MockRPC {
	mock := &MockRPC{ctrl: ctrl}
	mock.recorder = &MockRPCMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRPC) EXPECT() *MockRPCMockRecorder {
	return m.recorder
}

// Segments mocks base method.
func (m *MockRPC) Segments(arg0 context.Context, arg1 segfetcher.Request, arg2 net.Addr) (segfetcher.SegmentsReply, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Segments", arg0, arg1, arg2)
	ret0, _ := ret[0].(segfetcher.SegmentsReply)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Segments indicates an expected call of Segments.
func (mr *MockRPCMockRecorder) Segments(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Segments", reflect.TypeOf((*MockRPC)(nil).Segments), arg0, arg1, arg2)
}

// MockSplitter is a mock of Splitter interface.
type MockSplitter struct {
	ctrl     *gomock.Controller
	recorder *MockSplitterMockRecorder
}

// MockSplitterMockRecorder is the mock recorder for MockSplitter.
type MockSplitterMockRecorder struct {
	mock *MockSplitter
}

// NewMockSplitter creates a new mock instance.
func NewMockSplitter(ctrl *gomock.Controller) *MockSplitter {
	mock := &MockSplitter{ctrl: ctrl}
	mock.recorder = &MockSplitterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSplitter) EXPECT() *MockSplitterMockRecorder {
	return m.recorder
}

// Split mocks base method.
func (m *MockSplitter) Split(arg0 context.Context, arg1 addr.IAInt) (segfetcher.Requests, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Split", arg0, arg1)
	ret0, _ := ret[0].(segfetcher.Requests)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Split indicates an expected call of Split.
func (mr *MockSplitterMockRecorder) Split(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Split", reflect.TypeOf((*MockSplitter)(nil).Split), arg0, arg1)
}

// MockLocalInfo is a mock of LocalInfo interface.
type MockLocalInfo struct {
	ctrl     *gomock.Controller
	recorder *MockLocalInfoMockRecorder
}

// MockLocalInfoMockRecorder is the mock recorder for MockLocalInfo.
type MockLocalInfoMockRecorder struct {
	mock *MockLocalInfo
}

// NewMockLocalInfo creates a new mock instance.
func NewMockLocalInfo(ctrl *gomock.Controller) *MockLocalInfo {
	mock := &MockLocalInfo{ctrl: ctrl}
	mock.recorder = &MockLocalInfoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLocalInfo) EXPECT() *MockLocalInfoMockRecorder {
	return m.recorder
}

// IsSegLocal mocks base method.
func (m *MockLocalInfo) IsSegLocal(arg0 segfetcher.Request) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSegLocal", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsSegLocal indicates an expected call of IsSegLocal.
func (mr *MockLocalInfoMockRecorder) IsSegLocal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSegLocal", reflect.TypeOf((*MockLocalInfo)(nil).IsSegLocal), arg0)
}
