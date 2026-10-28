package core

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type Event struct {
	Sequence  uint64          `json:"sequence"`
	Time      time.Time       `json:"time"`
	SessionID string          `json:"session_id"`
	ScriptID  string          `json:"script_id,omitempty"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Data      []byte          `json:"data_base64,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
}

type EventPage struct {
	Events       []Event `json:"events"`
	NextCursor   uint64  `json:"next_cursor"`
	OldestCursor uint64  `json:"oldest_cursor"`
	Dropped      bool    `json:"dropped"`
}

// Events bounds both the number and size of retained events. Readers never
// consume events, so multiple clients can independently recover after reconnect.
type Events struct {
	mu                                sync.Mutex
	items                             []Event
	bytes                             int
	sequence                          uint64
	capacity, maxBytes, maxEventBytes int
	changed                           chan struct{}
}

func NewEvents(capacity, maxBytes, maxEventBytes int) *Events {
	if capacity < 1 {
		capacity = 2048
	}
	if maxBytes < 1024 {
		maxBytes = 8 << 20
	}
	if maxEventBytes < 128 {
		maxEventBytes = 64 << 10
	}
	if maxEventBytes > maxBytes {
		maxEventBytes = maxBytes
	}
	return &Events{capacity: capacity, maxBytes: maxBytes, maxEventBytes: maxEventBytes, changed: make(chan struct{})}
}

func eventBytes(e Event) int {
	return len(e.Payload) + len(e.Data) + len(e.SessionID) + len(e.ScriptID) + len(e.Type) + 128
}

func (b *Events) Add(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sequence++
	e.Sequence, e.Time = b.sequence, time.Now().UTC()
	if eventBytes(e) > b.maxEventBytes {
		e.Payload = json.RawMessage(`{"message":"event exceeded size limit; payload omitted"}`)
		e.Data, e.Truncated = nil, true
	}
	e.Payload = append(json.RawMessage(nil), e.Payload...)
	e.Data = append([]byte(nil), e.Data...)
	b.items = append(b.items, e)
	b.bytes += eventBytes(e)
	for len(b.items) > b.capacity || b.bytes > b.maxBytes {
		b.bytes -= eventBytes(b.items[0])
		b.items[0] = Event{}
		b.items = b.items[1:]
	}
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *Events) Read(ctx context.Context, sessionID string, cursor uint64, limit int, wait time.Duration) (EventPage, error) {
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > 1000 || wait < 0 || wait > 20*time.Second {
		return EventPage{}, Error("invalid_argument", "limit must be 1..1000 and wait_ms must be 0..20000")
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		if cursor > b.sequence {
			b.mu.Unlock()
			return EventPage{}, Error("invalid_cursor", "cursor is ahead of this server; cursors reset when the server restarts")
		}
		page := EventPage{Events: []Event{}, NextCursor: cursor, OldestCursor: b.sequence}
		if len(b.items) > 0 {
			page.OldestCursor = b.items[0].Sequence - 1
			page.Dropped = cursor < page.OldestCursor
		}
		for _, e := range b.items {
			if e.Sequence <= cursor {
				continue
			}
			page.NextCursor = e.Sequence
			if sessionID == "" || e.SessionID == sessionID {
				e.Payload = append(json.RawMessage(nil), e.Payload...)
				e.Data = append([]byte(nil), e.Data...)
				page.Events = append(page.Events, e)
				if len(page.Events) == limit {
					break
				}
			}
		}
		changed := b.changed
		b.mu.Unlock()
		if len(page.Events) > 0 || page.Dropped || wait == 0 {
			return page, nil
		}
		cursor = page.NextCursor
		select {
		case <-ctx.Done():
			return EventPage{}, ctx.Err()
		case <-deadline.C:
			return page, nil
		case <-changed:
		}
	}
}
