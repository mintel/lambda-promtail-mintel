package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/go-kit/log"
	"github.com/grafana/loki/pkg/logproto"
	"github.com/stretchr/testify/require"
)

// TestParseS3Log_ALB_ProcessesAllLines tests that parseS3Log processes ALL lines
// in an ALB log file, not just the first line.
//
// This test was created to catch a bug where the function would return after
// processing only the first ALB log line due to a premature `return nil` statement.
func TestParseS3Log_ALB_ProcessesAllLines(t *testing.T) {
	// The test file contains 5 ALB log lines:
	// - Line 1: health check (/healthz)
	// - Line 2: image-service-compere request
	// - Line 3: image-service-compere request
	// - Line 4: health check (/external-health-check)
	// - Line 5: image-service-compere request
	//
	// Without any sampling filters, ALL 5 lines should be processed.

	// Clear any existing sampling filters for this test
	originalFilters := s3SampleFilters
	s3SampleFilters = nil
	defer func() { s3SampleFilters = originalFilters }()

	b := &batch{
		streams: map[string]*logproto.Stream{},
	}

	labels := map[string]string{
		"type":       LB_LOG_TYPE,
		"lb_type":    LB_ALB_TYPE,
		"src":        "test-alb-123456",
		"account_id": "123456789012",
		"region":     "us-east-2",
	}

	obj, err := os.Open("../testdata/alb_multi_line_test.log.gz")
	require.NoError(t, err)
	defer obj.Close()

	batchSize = 131072 // Large enough to not trigger sends

	buf := &bytes.Buffer{}
	logger := log.NewLogfmtLogger(buf)

	err = parseS3Log(context.Background(), b, labels, obj, &logger)
	require.NoError(t, err)

	// Should have exactly 1 stream
	require.Len(t, b.streams, 1, "expected 1 stream in batch")

	// Get the stream
	var stream *logproto.Stream
	for _, s := range b.streams {
		stream = s
		break
	}
	require.NotNil(t, stream)

	// The file has 5 lines. With no sampling, all 5 should be processed.
	// If the bug exists (return nil after first line), only 1 entry will be present.
	require.Len(t, stream.Entries, 5,
		"expected 5 log entries, got %d. If only 1 entry, the bug (premature return nil) exists.",
		len(stream.Entries))

	// Verify each entry contains expected content
	expectedHosts := []string{
		"test.example.com", // healthz
		"image-service-compere.svc.us-prod1.prod.mintel.cloud", // image service
		"image-service-compere.svc.us-prod1.prod.mintel.cloud", // image service
		"test.example.com", // external-health-check
		"image-service-compere.svc.us-prod1.prod.mintel.cloud", // image service
	}

	for i, entry := range stream.Entries {
		require.Contains(t, entry.Line, expectedHosts[i],
			"entry %d should contain host %s", i, expectedHosts[i])
	}
}

// TestParseS3Log_ALB_WithSampling tests that sampling filters work correctly
// when processing multiple ALB log lines.
func TestParseS3Log_ALB_WithSampling(t *testing.T) {
	// Configure sampling to DROP health check requests (keep_rate=0)
	// and KEEP everything else (no filter matches).
	originalFilters := s3SampleFilters
	s3SampleFilters = []*S3SamplingConfig{
		{
			Path:     mustRegexp(`/(external-health-check|healthz|healthy|readiness|readyz|metrics)$`),
			KeepRate: 0, // Drop all health checks
		},
	}
	defer func() { s3SampleFilters = originalFilters }()

	b := &batch{
		streams: map[string]*logproto.Stream{},
	}

	labels := map[string]string{
		"type":       LB_LOG_TYPE,
		"lb_type":    LB_ALB_TYPE,
		"src":        "test-alb-123456",
		"account_id": "123456789012",
		"region":     "us-east-2",
	}

	obj, err := os.Open("../testdata/alb_multi_line_test.log.gz")
	require.NoError(t, err)
	defer obj.Close()

	batchSize = 131072 // Large enough to not trigger sends

	buf := &bytes.Buffer{}
	logger := log.NewLogfmtLogger(buf)

	err = parseS3Log(context.Background(), b, labels, obj, &logger)
	require.NoError(t, err)

	// Should have exactly 1 stream (ALB logs with ALB-specific labels)
	require.Len(t, b.streams, 1, "expected 1 stream in batch")

	// Get the stream
	var stream *logproto.Stream
	for _, s := range b.streams {
		stream = s
		break
	}
	require.NotNil(t, stream)

	// The file has 5 lines:
	// - 2 health check lines (should be DROPPED due to keep_rate=0)
	// - 3 image-service-compere lines (should be KEPT - no filter matches)
	//
	// If the bug exists, only the first non-health-check line would be kept.
	require.Len(t, stream.Entries, 3,
		"expected 3 log entries (health checks filtered), got %d. "+
			"If only 1 entry, the bug (premature return nil) exists.",
		len(stream.Entries))

	// Verify all entries are image-service-compere requests (health checks should be dropped)
	for i, entry := range stream.Entries {
		require.Contains(t, entry.Line, "image-service-compere",
			"entry %d should be an image-service-compere request", i)
		require.NotContains(t, entry.Line, "/healthz",
			"entry %d should not be a health check", i)
		require.NotContains(t, entry.Line, "/external-health-check",
			"entry %d should not be a health check", i)
	}
}

// mustRegexp creates a RegexpString from a pattern, panicking on error.
func mustRegexp(pattern string) *RegexpString {
	rs := &RegexpString{}
	if err := rs.UnmarshalJSON([]byte(`"` + pattern + `"`)); err != nil {
		panic(err)
	}
	return rs
}
