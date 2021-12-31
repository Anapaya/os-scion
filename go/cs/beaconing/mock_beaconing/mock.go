// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/cs/beaconing (interfaces: BeaconInserter,BeaconProvider,Sender,RPC,SegmentProvider,SegmentStore,SenderFactory)

// Package mock_beaconing is a generated GoMock package.
package mock_beaconing

import (
	context "context"
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	beacon "github.com/scionproto/scion/go/cs/beacon"
	beaconing "github.com/scionproto/scion/go/cs/beaconing"
	addr "github.com/scionproto/scion/go/lib/addr"
	seg "github.com/scionproto/scion/go/lib/ctrl/seg"
	seghandler "github.com/scionproto/scion/go/lib/infra/modules/seghandler"
)

// MockBeaconInserter is a mock of BeaconInserter interface.
type MockBeaconInserter struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconInserterMockRecorder
}

// MockBeaconInserterMockRecorder is the mock recorder for MockBeaconInserter.
type MockBeaconInserterMockRecorder struct {
	mock *MockBeaconInserter
}

// NewMockBeaconInserter creates a new mock instance.
func NewMockBeaconInserter(ctrl *gomock.Controller) *MockBeaconInserter {
	mock := &MockBeaconInserter{ctrl: ctrl}
	mock.recorder = &MockBeaconInserterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBeaconInserter) EXPECT() *MockBeaconInserterMockRecorder {
	return m.recorder
}

// InsertBeacon mocks base method.
func (m *MockBeaconInserter) InsertBeacon(arg0 context.Context, arg1 beacon.Beacon) (beacon.InsertStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertBeacon", arg0, arg1)
	ret0, _ := ret[0].(beacon.InsertStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertBeacon indicates an expected call of InsertBeacon.
func (mr *MockBeaconInserterMockRecorder) InsertBeacon(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertBeacon", reflect.TypeOf((*MockBeaconInserter)(nil).InsertBeacon), arg0, arg1)
}

// PreFilter mocks base method.
func (m *MockBeaconInserter) PreFilter(arg0 beacon.Beacon) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PreFilter", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// PreFilter indicates an expected call of PreFilter.
func (mr *MockBeaconInserterMockRecorder) PreFilter(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PreFilter", reflect.TypeOf((*MockBeaconInserter)(nil).PreFilter), arg0)
}

// MockBeaconProvider is a mock of BeaconProvider interface.
type MockBeaconProvider struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconProviderMockRecorder
}

// MockBeaconProviderMockRecorder is the mock recorder for MockBeaconProvider.
type MockBeaconProviderMockRecorder struct {
	mock *MockBeaconProvider
}

// NewMockBeaconProvider creates a new mock instance.
func NewMockBeaconProvider(ctrl *gomock.Controller) *MockBeaconProvider {
	mock := &MockBeaconProvider{ctrl: ctrl}
	mock.recorder = &MockBeaconProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBeaconProvider) EXPECT() *MockBeaconProviderMockRecorder {
	return m.recorder
}

// BeaconsToPropagate mocks base method.
func (m *MockBeaconProvider) BeaconsToPropagate(arg0 context.Context) ([]beacon.Beacon, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeaconsToPropagate", arg0)
	ret0, _ := ret[0].([]beacon.Beacon)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeaconsToPropagate indicates an expected call of BeaconsToPropagate.
func (mr *MockBeaconProviderMockRecorder) BeaconsToPropagate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeaconsToPropagate", reflect.TypeOf((*MockBeaconProvider)(nil).BeaconsToPropagate), arg0)
}

// MockSender is a mock of Sender interface.
type MockSender struct {
	ctrl     *gomock.Controller
	recorder *MockSenderMockRecorder
}

// MockSenderMockRecorder is the mock recorder for MockSender.
type MockSenderMockRecorder struct {
	mock *MockSender
}

// NewMockSender creates a new mock instance.
func NewMockSender(ctrl *gomock.Controller) *MockSender {
	mock := &MockSender{ctrl: ctrl}
	mock.recorder = &MockSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSender) EXPECT() *MockSenderMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockSender) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockSenderMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockSender)(nil).Close))
}

// Send mocks base method.
func (m *MockSender) Send(arg0 context.Context, arg1 *seg.PathSegment) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Send", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Send indicates an expected call of Send.
func (mr *MockSenderMockRecorder) Send(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Send", reflect.TypeOf((*MockSender)(nil).Send), arg0, arg1)
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

// RegisterSegment mocks base method.
func (m *MockRPC) RegisterSegment(arg0 context.Context, arg1 seg.Meta, arg2 net.Addr) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterSegment", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterSegment indicates an expected call of RegisterSegment.
func (mr *MockRPCMockRecorder) RegisterSegment(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterSegment", reflect.TypeOf((*MockRPC)(nil).RegisterSegment), arg0, arg1, arg2)
}

// MockSegmentProvider is a mock of SegmentProvider interface.
type MockSegmentProvider struct {
	ctrl     *gomock.Controller
	recorder *MockSegmentProviderMockRecorder
}

// MockSegmentProviderMockRecorder is the mock recorder for MockSegmentProvider.
type MockSegmentProviderMockRecorder struct {
	mock *MockSegmentProvider
}

// NewMockSegmentProvider creates a new mock instance.
func NewMockSegmentProvider(ctrl *gomock.Controller) *MockSegmentProvider {
	mock := &MockSegmentProvider{ctrl: ctrl}
	mock.recorder = &MockSegmentProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSegmentProvider) EXPECT() *MockSegmentProviderMockRecorder {
	return m.recorder
}

// SegmentsToRegister mocks base method.
func (m *MockSegmentProvider) SegmentsToRegister(arg0 context.Context, arg1 seg.Type) ([]beacon.Beacon, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SegmentsToRegister", arg0, arg1)
	ret0, _ := ret[0].([]beacon.Beacon)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SegmentsToRegister indicates an expected call of SegmentsToRegister.
func (mr *MockSegmentProviderMockRecorder) SegmentsToRegister(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SegmentsToRegister", reflect.TypeOf((*MockSegmentProvider)(nil).SegmentsToRegister), arg0, arg1)
}

// MockSegmentStore is a mock of SegmentStore interface.
type MockSegmentStore struct {
	ctrl     *gomock.Controller
	recorder *MockSegmentStoreMockRecorder
}

// MockSegmentStoreMockRecorder is the mock recorder for MockSegmentStore.
type MockSegmentStoreMockRecorder struct {
	mock *MockSegmentStore
}

// NewMockSegmentStore creates a new mock instance.
func NewMockSegmentStore(ctrl *gomock.Controller) *MockSegmentStore {
	mock := &MockSegmentStore{ctrl: ctrl}
	mock.recorder = &MockSegmentStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSegmentStore) EXPECT() *MockSegmentStoreMockRecorder {
	return m.recorder
}

// StoreSegs mocks base method.
func (m *MockSegmentStore) StoreSegs(arg0 context.Context, arg1 []*seg.Meta) (seghandler.SegStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreSegs", arg0, arg1)
	ret0, _ := ret[0].(seghandler.SegStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StoreSegs indicates an expected call of StoreSegs.
func (mr *MockSegmentStoreMockRecorder) StoreSegs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreSegs", reflect.TypeOf((*MockSegmentStore)(nil).StoreSegs), arg0, arg1)
}

// MockSenderFactory is a mock of SenderFactory interface.
type MockSenderFactory struct {
	ctrl     *gomock.Controller
	recorder *MockSenderFactoryMockRecorder
}

// MockSenderFactoryMockRecorder is the mock recorder for MockSenderFactory.
type MockSenderFactoryMockRecorder struct {
	mock *MockSenderFactory
}

// NewMockSenderFactory creates a new mock instance.
func NewMockSenderFactory(ctrl *gomock.Controller) *MockSenderFactory {
	mock := &MockSenderFactory{ctrl: ctrl}
	mock.recorder = &MockSenderFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSenderFactory) EXPECT() *MockSenderFactoryMockRecorder {
	return m.recorder
}

// NewSender mocks base method.
func (m *MockSenderFactory) NewSender(arg0 context.Context, arg1 addr.IAInt, arg2 uint16, arg3 *net.UDPAddr) (beaconing.Sender, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewSender", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(beaconing.Sender)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewSender indicates an expected call of NewSender.
func (mr *MockSenderFactoryMockRecorder) NewSender(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewSender", reflect.TypeOf((*MockSenderFactory)(nil).NewSender), arg0, arg1, arg2, arg3)
}
