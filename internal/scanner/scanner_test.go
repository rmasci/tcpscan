package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/rmasci/tcpscan/internal/types"
)

func BenchmarkScanTarget(b *testing.B) {
	config := &types.Config{
		Timeout:  500 * time.Millisecond,
		Protocol: "tcp",
	}
	
	scanner := New(config)
	ctx := context.Background()
	
	target := types.ScanTarget{
		Address: "127.0.0.1",
		Port:    "22",
		Index:   0,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanTarget(ctx, target)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPCheckerFast(b *testing.B) {
	config := &types.Config{
		Timeout:  500 * time.Millisecond,
		Protocol: "tcp",
	}
	
	scanner := New(config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.tcpCheckerFast("127.0.0.1:22")
	}
}

func BenchmarkPerformDNSLookup(b *testing.B) {
	config := &types.Config{
		Timeout: 500 * time.Millisecond,
	}
	
	scanner := New(config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = scanner.performDNSLookup("localhost")
	}
}
