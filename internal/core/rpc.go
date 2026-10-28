package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
)

type rpcReply struct {
	value json.RawMessage
	err   error
}

// rpcPeer owns correlation independently of Frida callbacks. Late responses are
// discarded, never returned to a subsequent call or a reused channel.
type rpcPeer struct {
	mu      sync.Mutex
	next    atomic.Uint64
	pending map[string]chan rpcReply
	closed  bool
}

func newRPC() *rpcPeer { return &rpcPeer{pending: make(map[string]chan rpcReply)} }

func (p *rpcPeer) call(ctx context.Context, post func(context.Context, json.RawMessage, []byte) error, method string, args []any) (json.RawMessage, error) {
	id := fmt.Sprintf("mcp-%d", p.next.Add(1))
	ch := make(chan rpcReply, 1)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, Error("script_destroyed", "script is no longer available")
	}
	p.pending[id] = ch
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, id); p.mu.Unlock() }()
	if args == nil {
		args = []any{}
	}
	message, err := json.Marshal([]any{"frida:rpc", id, "call", method, args})
	if err != nil {
		return nil, err
	}
	if err = post(ctx, message, nil); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-ch:
		return reply.value, reply.err
	}
}

func (p *rpcPeer) receive(message json.RawMessage) bool {
	var envelope struct {
		Type    string            `json:"type"`
		Payload []json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(message, &envelope) != nil || envelope.Type != "send" || len(envelope.Payload) < 4 {
		return false
	}
	var tag, id, status string
	if json.Unmarshal(envelope.Payload[0], &tag) != nil || tag != "frida:rpc" {
		return false
	}
	if json.Unmarshal(envelope.Payload[1], &id) != nil || json.Unmarshal(envelope.Payload[2], &status) != nil {
		return true
	}
	r := rpcReply{value: append(json.RawMessage(nil), envelope.Payload[3]...)}
	if status != "ok" {
		var message string
		if json.Unmarshal(envelope.Payload[3], &message) != nil {
			message = string(envelope.Payload[3])
		}
		if len(envelope.Payload) > 5 {
			var stack string
			if json.Unmarshal(envelope.Payload[5], &stack) == nil && stack != "" {
				message += "\n" + stack
			}
		}
		r.err = Error("javascript_error", message)
	}
	p.mu.Lock()
	if ch := p.pending[id]; ch != nil {
		select {
		case ch <- r:
		default:
		}
	}
	p.mu.Unlock()
	return true
}

func (p *rpcPeer) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, ch := range p.pending {
		select {
		case ch <- rpcReply{err: Error("script_destroyed", "script or session was destroyed")}:
		default:
		}
	}
}

const evaluatorSource = `rpc.exports = {
  async evaluate(source) {
    const value = await (0, eval)(source);
    if (value === undefined) return { value: null, undefined: true };
    // Return JSON values; report cyclic/unserializable results as RPC errors.
    return { value: JSON.parse(JSON.stringify(value, (_, v) =>
      typeof v === 'bigint' ? v.toString() : v)), undefined: false };
  }
};`
