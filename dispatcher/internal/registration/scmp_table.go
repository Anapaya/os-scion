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

package registration

import (
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

type SCMPTableDump map[addr.IA]map[uint64]SCMPTableDumpEntry

type SCMPTableDumpEntry struct {
	Reference string
	LastUsed  time.Time
}

type scmpEntry struct {
	reference interface{}
	lastUsed  time.Time
}

// SCMPTable tracks SCMP General class IDs.
//
// Attempting to register the same ID more than once will return an error.
type SCMPTable struct {
	m map[addr.IA]map[uint64]scmpEntry
}

func NewSCMPTable() *SCMPTable {
	return &SCMPTable{m: make(map[addr.IA]map[uint64]scmpEntry)}
}

func (t *SCMPTable) Lookup(id uint64, dst addr.IA) (interface{}, bool) {
	v, ok := t.m[dst][id]
	return v.reference, ok
}

func (t *SCMPTable) Register(id uint64, dst addr.IA, reference interface{}) (bool, error) {
	if reference == nil {
		return false, serrors.New("cannot register nil value")
	}
	m, ok := t.m[dst]
	if !ok {
		m = make(map[uint64]scmpEntry)
		t.m[dst] = m
	}

	now := time.Now()
	v, ok := m[id]
	sameRef := v.reference == reference

	// If the ID is already registered by a different reference within the last
	// 10 seconds, return an error.
	if ok && !sameRef && now.Sub(v.lastUsed) < 10*time.Second {
		return false, serrors.New("id already registered", "id", id)
	}
	m[id] = scmpEntry{reference: reference, lastUsed: now}
	return !sameRef, nil
}

func (t *SCMPTable) Remove(id uint64, dst addr.IA, reference interface{}) {
	m, ok := t.m[dst]
	if ok {
		// Only clean up the ID if the value still matches.
		// It could have been overwritten in the meantime.
		if v, ok := m[id]; ok && v.reference == reference {
			delete(m, id)
		}
	}

	if len(m) == 0 {
		delete(t.m, dst)
	}
}

func (t *SCMPTable) Dump() SCMPTableDump {
	dump := make(SCMPTableDump)
	for ia, m := range t.m {
		dump[ia] = make(map[uint64]SCMPTableDumpEntry)
		for id, entry := range m {
			dump[ia][id] = SCMPTableDumpEntry{
				Reference: func() string {
					if id, ok := entry.reference.(interface{ ID() string }); ok {
						return id.ID()
					}
					return "none"
				}(),
				LastUsed: entry.lastUsed,
			}
		}
	}
	return dump
}
