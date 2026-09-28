package scan

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/h3yow/binary-static-analyzer-go/internal/binary"
	"github.com/h3yow/binary-static-analyzer-go/internal/rules"
)

func (c *MemoryCache) statsForTest() string {
	e, h, m := c.Stats()
	return fmt.Sprintf("entries=%d hits=%d misses=%d", e, h, m)
}

// slowEvaluator blocks for a fixed delay, honoring context cancellation.
type slowEvaluator struct{ delay time.Duration }

func (e *slowEvaluator) Evaluate(ctx context.Context, _ *binary.Binary, _ []byte) ([]rules.Finding, error) {
	select {
	case <-time.After(e.delay):
		return []rules.Finding{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ = testing.Short
