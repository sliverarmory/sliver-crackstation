package hashcat

import "bytes"

// limitedBuffer retains a bounded prefix while reporting successful writes for
// the complete stream. This lets os/exec keep draining a noisy child without
// allowing output capture to consume unbounded memory.
type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	total     uint64
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	b.total += uint64(written)
	remaining := b.limit - b.buffer.Len()
	if remaining > len(data) {
		remaining = len(data)
	}
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:remaining])
	}
	if remaining < len(data) {
		b.truncated = true
	}
	return written, nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *limitedBuffer) TotalBytes() uint64 {
	return b.total
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
