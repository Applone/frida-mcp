package core_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/applone/frida-mcp/internal/core"
)

func TestEventsOverflowAndIndependentReaders(t *testing.T) {
	events := core.NewEvents(2, 4096, 1024)
	for _, id := range []string{"a", "b", "a"} {
		events.Add(core.Event{SessionID: id, Type: "message", Payload: json.RawMessage(`{"type":"send"}`)})
	}
	for i := 0; i < 2; i++ {
		page, err := events.Read(context.Background(), "a", 0, 10, 0)
		if err != nil || !page.Dropped || len(page.Events) != 1 || page.NextCursor != 3 || page.OldestCursor != 1 {
			t.Fatalf("%+v %v", page, err)
		}
	}
	if _, err := events.Read(context.Background(), "", 999, 10, 0); err == nil {
		t.Fatal("accepted future cursor")
	}
}

func TestEventsTruncationAndPayloadOwnership(t *testing.T) {
	events := core.NewEvents(10, 4096, 512)
	data := []byte{1, 2}
	payload := json.RawMessage(`{"message":"ok"}`)
	events.Add(core.Event{SessionID: "s", Payload: payload, Data: data})
	payload[0] = '!'
	data[0] = 9
	events.Add(core.Event{SessionID: "s", Payload: json.RawMessage(`"` + strings.Repeat("x", 1000) + `"`)})
	page, err := events.Read(context.Background(), "", 0, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Events[0].Data[0] != 1 || !json.Valid(page.Events[0].Payload) || !page.Events[1].Truncated {
		t.Fatalf("%+v", page)
	}
	page.Events[0].Data[0] = 8
	again, _ := events.Read(context.Background(), "", 0, 10, 0)
	if again.Events[0].Data[0] != 1 {
		t.Fatal("reader mutated retained data")
	}
}

func TestEventLongPollAndCancellation(t *testing.T) {
	events := core.NewEvents(10, 4096, 512)
	done := make(chan core.EventPage, 1)
	go func() {
		page, err := events.Read(context.Background(), "wanted", 0, 10, time.Second)
		if err != nil {
			t.Error(err)
		}
		done <- page
	}()
	events.Add(core.Event{SessionID: "other"})
	events.Add(core.Event{SessionID: "wanted"})
	select {
	case page := <-done:
		if len(page.Events) != 1 || page.NextCursor != 2 {
			t.Fatal(page)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not wake")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := events.Read(ctx, "", 2, 10, time.Second); err == nil {
		t.Fatal("cancellation ignored")
	}
}
