package hashcat

import (
	"strings"
	"testing"
)

func TestLimitedBufferDrainsAndReportsTruncation(t *testing.T) {
	buffer := newLimitedBuffer(5)
	for _, chunk := range []string{"abc", "def", "ghi"} {
		written, err := buffer.Write([]byte(chunk))
		if err != nil || written != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v", chunk, written, err)
		}
	}
	if got := string(buffer.Bytes()); got != "abcde" {
		t.Fatalf("Bytes() = %q; want abcde", got)
	}
	if !buffer.Truncated() || buffer.TotalBytes() != uint64(len(strings.Join([]string{"abc", "def", "ghi"}, ""))) {
		t.Fatalf("truncated = %v, total = %d", buffer.Truncated(), buffer.TotalBytes())
	}
}
