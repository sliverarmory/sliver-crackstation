package crackstation

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"sync"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"google.golang.org/protobuf/proto"
)

const (
	// Size is arbitrary, just want to avoid weird cases where we'd block on channel sends
	eventBufSize = 5
)

type eventBroker struct {
	mu          sync.Mutex
	subscribers map[chan *clientpb.CrackstationStatus]struct{}
	stopped     bool
}

// Start is retained for source compatibility; newBroker starts ready to use.
func (broker *eventBroker) Start() {}

// Stop - Close the broker channel
func (broker *eventBroker) Stop() {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.stopped {
		return
	}
	broker.stopped = true
	for subscriber := range broker.subscribers {
		close(subscriber)
		delete(broker.subscribers, subscriber)
	}
}

// Subscribe - Generate a new subscription channel
func (broker *eventBroker) Subscribe() chan *clientpb.CrackstationStatus {
	events := make(chan *clientpb.CrackstationStatus, eventBufSize)
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.stopped {
		close(events)
		return events
	}
	broker.subscribers[events] = struct{}{}
	return events
}

// Unsubscribe - Remove a subscription channel
func (broker *eventBroker) Unsubscribe(events chan *clientpb.CrackstationStatus) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if _, ok := broker.subscribers[events]; !ok {
		return
	}
	delete(broker.subscribers, events)
	close(events)
}

// Publish - Push a message to all subscribers
func (broker *eventBroker) Publish(event *clientpb.CrackstationStatus) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.stopped {
		return
	}
	for subscriber := range broker.subscribers {
		snapshot := event
		if event != nil {
			snapshot = proto.Clone(event).(*clientpb.CrackstationStatus)
		}
		select {
		case subscriber <- snapshot:
		default:
			// Status is a periodic snapshot; dropping an obsolete snapshot is
			// preferable to blocking the worker behind a slow UI subscriber.
		}
	}
}

func newBroker() *eventBroker {
	return &eventBroker{subscribers: map[chan *clientpb.CrackstationStatus]struct{}{}}
}
