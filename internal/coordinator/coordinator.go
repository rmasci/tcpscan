package coordinator

import (
	"context"
	"fmt"
	"time"

	"github.com/rmasci/tcpscan/internal/scanner"
	"github.com/rmasci/tcpscan/internal/types"
	"golang.org/x/sync/errgroup"
)

type Coordinator struct {
	scanner *scanner.Scanner
	config  *types.Config
}

func New(config *types.Config) *Coordinator {
	return &Coordinator{
		scanner: scanner.New(config),
		config:  config,
	}
}

func (c *Coordinator) ScanTargets(ctx context.Context, targets []types.ScanTarget) ([]*types.ScanResult, error) {
	if len(targets) > 2048 {
		return nil, fmt.Errorf("cannot scan more than 2048 hosts/ports at a time (requested: %d)", len(targets))
	}

	// If samples > 1, perform multiple scans and aggregate
	if c.config.Samples > 1 {
		return c.scanWithQualityMetrics(ctx, targets)
	}

	results := make([]*types.ScanResult, len(targets))
	g, ctx := errgroup.WithContext(ctx)

	g.SetLimit(512)

	for i := range targets {
		idx := i
		target := targets[idx]

		g.Go(func() error {
			result, err := c.scanner.ScanTarget(ctx, target)
			if err != nil {
				return fmt.Errorf("failed to scan %s:%s: %w", target.Address, target.Port, err)
			}

			if c.shouldIncludeResult(result) {
				results[idx] = result
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return c.compactResults(results), nil
}

func (c *Coordinator) shouldIncludeResult(result *types.ScanResult) bool {
	if c.config.ShowOpen && result.Status != types.StatusOpen {
		return false
	}

	if c.config.ShowClosed && result.Status == types.StatusOpen {
		return false
	}

	return true
}

func (c *Coordinator) scanWithQualityMetrics(ctx context.Context, targets []types.ScanTarget) ([]*types.ScanResult, error) {
	allResults := make([][]*types.ScanResult, c.config.Samples)
	
	// Perform multiple scans
	for sample := 0; sample < c.config.Samples; sample++ {
		results := make([]*types.ScanResult, len(targets))
		g, sampleCtx := errgroup.WithContext(ctx)
		g.SetLimit(512)
		
		for i := range targets {
			idx := i
			target := targets[idx]
			
			g.Go(func() error {
				result, err := c.scanner.ScanTarget(sampleCtx, target)
				if err != nil {
					return fmt.Errorf("failed to scan %s:%s: %w", target.Address, target.Port, err)
				}
				
				if c.shouldIncludeResult(result) {
					results[idx] = result
				}
				
				return nil
			})
		}
		
		if err := g.Wait(); err != nil {
			return nil, err
		}
		
		allResults[sample] = results
	}
	
	// Aggregate results
	return c.aggregateQualityMetrics(allResults), nil
}

func (c *Coordinator) aggregateQualityMetrics(samples [][]*types.ScanResult) []*types.ScanResult {
	if len(samples) == 0 {
		return nil
	}
	
	numTargets := len(samples[0])
	aggregated := make([]*types.ScanResult, numTargets)
	
	for i := 0; i < numTargets; i++ {
		var validResults []*types.ScanResult
		for _, sample := range samples {
			if sample[i] != nil {
				validResults = append(validResults, sample[i])
			}
		}
		
		if len(validResults) == 0 {
			continue
		}
		
		// Use first result as base
		result := validResults[0]
		
		// Calculate success rate and average time for open ports
		if result.Status == types.StatusOpen && len(validResults) > 1 {
			var totalTime int64
			successCount := 0
			
			for _, r := range validResults {
				if r.Status == types.StatusOpen {
					successCount++
					totalTime += r.TCPTime.Nanoseconds()
				}
			}
			
			if successCount > 0 {
				result.TCPTime = time.Duration(totalTime / int64(successCount))
			}
		}
		
		aggregated[i] = result
	}
	
	return c.compactResults(aggregated)
}

func (c *Coordinator) compactResults(results []*types.ScanResult) []*types.ScanResult {
	if len(results) == 0 {
		return results
	}
	
	n := 0
	for _, result := range results {
		if result != nil {
			results[n] = result
			n++
		}
	}
	return results[:n]
}
