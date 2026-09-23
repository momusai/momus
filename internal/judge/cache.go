package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
)

// CachingJudge memoizes verdicts within a run so identical (attackID, prompt,
// response, model) tuples reuse a result instead of re-calling the provider.
// The key EXCLUDES the nonce: a cache hit skips the network call entirely, and
// the stored Result was already nonce-verified on first call.
type CachingJudge struct {
	Inner Judge
	mu    sync.Mutex
	cache map[string]*Result
}

// NewCachingJudge wraps j with an in-run memo.
func NewCachingJudge(j Judge) *CachingJudge {
	return &CachingJudge{Inner: j, cache: make(map[string]*Result)}
}

// Name identifies this judge.
func (c *CachingJudge) Name() string { return "caching(" + c.Inner.Name() + ")" }

func cacheKey(r Request) string {
	// hash.Hash.Write never returns an error; blank-assign to satisfy linters.
	h := sha256.New()
	_, _ = io.WriteString(h, r.AttackID+"\x00"+r.Prompt+"\x00"+r.Response+"\x00"+r.Model)
	return hex.EncodeToString(h.Sum(nil))
}

// Judge returns a cached result when present, otherwise calls the inner judge
// and stores the result.
func (c *CachingJudge) Judge(ctx context.Context, req Request) (*Result, error) {
	key := cacheKey(req)

	c.mu.Lock()
	if hit, ok := c.cache[key]; ok {
		c.mu.Unlock()
		clone := *hit
		clone.CacheHit = true
		clone.Key = key
		return &clone, nil
	}
	c.mu.Unlock()

	res, err := c.Inner.Judge(ctx, req)
	if err != nil {
		return res, err
	}
	if res == nil {
		res = inconclusive("nil result from inner judge")
	}
	res.Key = key

	c.mu.Lock()
	c.cache[key] = res
	c.mu.Unlock()

	clone := *res
	return &clone, nil
}
