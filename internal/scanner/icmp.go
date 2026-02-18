package scanner

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func (s *Scanner) performICMPCheck(ctx context.Context, host string) (time.Duration, error) {
	startTime := time.Now()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", host)
	} else {
		if strings.Count(host, ":") >= 2 {
			host = strings.TrimLeft(host, "[")
			host = strings.TrimRight(host, "]")
			cmd = exec.CommandContext(ctx, "ping6", "-c", "1", "-i", "1", host)
		} else {
			cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-i", "1", host)
		}
	}

	var buf bytes.Buffer
	cmd.Stdout = &buf

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	go func() {
		done <- cmd.Wait()
	}()

	timeout := time.After(s.config.Timeout)
	select {
	case <-timeout:
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return 0, context.DeadlineExceeded
	case err := <-done:
		if err != nil {
			return 0, err
		}
		return time.Since(startTime), nil
	case <-ctx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return 0, ctx.Err()
	}
}
