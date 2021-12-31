// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/daemon (interfaces: Connector)

// Package mock_daemon is a generated GoMock package.
package mock_daemon

import (
	context "context"
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	common "github.com/scionproto/scion/go/lib/common"
	path_mgmt "github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	daemon "github.com/scionproto/scion/go/lib/daemon"
	snet "github.com/scionproto/scion/go/lib/snet"
)

// MockConnector is a mock of Connector interface.
type MockConnector struct {
	ctrl     *gomock.Controller
	recorder *MockConnectorMockRecorder
}

// MockConnectorMockRecorder is the mock recorder for MockConnector.
type MockConnectorMockRecorder struct {
	mock *MockConnector
}

// NewMockConnector creates a new mock instance.
func NewMockConnector(ctrl *gomock.Controller) *MockConnector {
	mock := &MockConnector{ctrl: ctrl}
	mock.recorder = &MockConnectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnector) EXPECT() *MockConnectorMockRecorder {
	return m.recorder
}

// ASInfo mocks base method.
func (m *MockConnector) ASInfo(arg0 context.Context, arg1 addr.IAInt) (daemon.ASInfo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ASInfo", arg0, arg1)
	ret0, _ := ret[0].(daemon.ASInfo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ASInfo indicates an expected call of ASInfo.
func (mr *MockConnectorMockRecorder) ASInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ASInfo", reflect.TypeOf((*MockConnector)(nil).ASInfo), arg0, arg1)
}

// Close mocks base method.
func (m *MockConnector) Close(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockConnectorMockRecorder) Close(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockConnector)(nil).Close), arg0)
}

// IFInfo mocks base method.
func (m *MockConnector) IFInfo(arg0 context.Context, arg1 []common.IFIDType) (map[common.IFIDType]*net.UDPAddr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IFInfo", arg0, arg1)
	ret0, _ := ret[0].(map[common.IFIDType]*net.UDPAddr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IFInfo indicates an expected call of IFInfo.
func (mr *MockConnectorMockRecorder) IFInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IFInfo", reflect.TypeOf((*MockConnector)(nil).IFInfo), arg0, arg1)
}

// LocalIA mocks base method.
func (m *MockConnector) LocalIA(arg0 context.Context) (addr.IAInt, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalIA", arg0)
	ret0, _ := ret[0].(addr.IAInt)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LocalIA indicates an expected call of LocalIA.
func (mr *MockConnectorMockRecorder) LocalIA(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalIA", reflect.TypeOf((*MockConnector)(nil).LocalIA), arg0)
}

// Paths mocks base method.
func (m *MockConnector) Paths(arg0 context.Context, arg1, arg2 addr.IAInt, arg3 daemon.PathReqFlags) ([]snet.Path, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Paths", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]snet.Path)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Paths indicates an expected call of Paths.
func (mr *MockConnectorMockRecorder) Paths(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Paths", reflect.TypeOf((*MockConnector)(nil).Paths), arg0, arg1, arg2, arg3)
}

// RevNotification mocks base method.
func (m *MockConnector) RevNotification(arg0 context.Context, arg1 *path_mgmt.RevInfo) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevNotification", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevNotification indicates an expected call of RevNotification.
func (mr *MockConnectorMockRecorder) RevNotification(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevNotification", reflect.TypeOf((*MockConnector)(nil).RevNotification), arg0, arg1)
}

// SVCInfo mocks base method.
func (m *MockConnector) SVCInfo(arg0 context.Context, arg1 []addr.HostSVC) (map[addr.HostSVC]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SVCInfo", arg0, arg1)
	ret0, _ := ret[0].(map[addr.HostSVC]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SVCInfo indicates an expected call of SVCInfo.
func (mr *MockConnectorMockRecorder) SVCInfo(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SVCInfo", reflect.TypeOf((*MockConnector)(nil).SVCInfo), arg0, arg1)
}
