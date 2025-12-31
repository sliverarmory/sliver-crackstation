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

import "github.com/bishopfox/sliver/protobuf/clientpb"

const (
	// Size is arbitrary, just want to avoid weird cases where we'd block on channel sends
	eventBufSize = 5
)

type eventBroker struct {
	stop        chan struct{}
	publish     chan *clientpb.CrackstationStatus
	subscribe   chan chan *clientpb.CrackstationStatus
	unsubscribe chan chan *clientpb.CrackstationStatus
	send        chan *clientpb.CrackstationStatus
}

// Start - Start a broker channel
func (broker *eventBroker) Start() {
	subscribers := map[chan *clientpb.CrackstationStatus]struct{}{}
	for {
		select {
		case <-broker.stop:
			for sub := range subscribers {
				close(sub)
			}
			return
		case sub := <-broker.subscribe:
			subscribers[sub] = struct{}{}
		case sub := <-broker.unsubscribe:
			delete(subscribers, sub)
		case event := <-broker.publish:
			for sub := range subscribers {
				sub <- event
			}
		}
	}
}

// Stop - Close the broker channel
func (broker *eventBroker) Stop() {
	close(broker.stop)
}

// Subscribe - Generate a new subscription channel
func (broker *eventBroker) Subscribe() chan *clientpb.CrackstationStatus {
	events := make(chan *clientpb.CrackstationStatus, eventBufSize)
	broker.subscribe <- events
	return events
}

// Unsubscribe - Remove a subscription channel
func (broker *eventBroker) Unsubscribe(events chan *clientpb.CrackstationStatus) {
	broker.unsubscribe <- events
	close(events)
}

// Publish - Push a message to all subscribers
func (broker *eventBroker) Publish(event *clientpb.CrackstationStatus) {
	broker.publish <- event
}

func newBroker() *eventBroker {
	broker := &eventBroker{
		stop:        make(chan struct{}),
		publish:     make(chan *clientpb.CrackstationStatus, eventBufSize),
		subscribe:   make(chan chan *clientpb.CrackstationStatus, eventBufSize),
		unsubscribe: make(chan chan *clientpb.CrackstationStatus, eventBufSize),
		send:        make(chan *clientpb.CrackstationStatus, eventBufSize),
	}
	go broker.Start()
	return broker
}
