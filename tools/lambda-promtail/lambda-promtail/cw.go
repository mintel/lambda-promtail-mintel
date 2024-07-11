package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/prometheus/common/model"

	"github.com/grafana/loki/pkg/logproto"
)

// CloudWatchSamplingConfig represents some pattern of CloudWatch logs that
// should be dropped probabilistically.
type CloudWatchSamplingConfig struct {
	AccountIDs CommaSeparatedStringSet `json:"account"` // List of AWS account IDs to match on e.g. "123456789012,2345678901234".

	// A regexp that will be matched against the name of the log group.
	LogGroup *RegexpString `json:"log_group"`

	// A regexp that will be matched against the name of the log stream.
	LogStream *RegexpString `json:"log_stream"`

	// A regexp that will be matched against each log line.
	LogLine *RegexpString `json:"log"`

	// A probability between 0 and 1.
	// If a log line matches the filters above, keep that log line with this probability.
	KeepRate float64 `json:"keep"`
}

// MatchStream returns true if a CloudWatch logs events matches this sampling filter.
func (conf *CloudWatchSamplingConfig) MatchStream(accountID, logGroup, logStream string) bool {
	if len(conf.AccountIDs) > 0 {
		if !conf.AccountIDs.Contains(accountID) {
			return false
		}
	}
	if !conf.LogGroup.IsZero() {
		if !conf.LogGroup.MatchString(logGroup) {
			return false
		}
	}
	if !conf.LogStream.IsZero() {
		if !conf.LogStream.MatchString(logStream) {
			return false
		}
	}
	return true
}

// MatchLine returns true if an individual CloudWatch log line matches the LogLine regexp.
func (conf *CloudWatchSamplingConfig) MatchLine(logLine string) bool {
	if !conf.LogLine.IsZero() {
		if !conf.LogLine.MatchString(logLine) {
			return false
		}
	}
	return true
}

// Keep randomly returns true or false at a rate depending on conf.KeepRate.
// A KeepRate of 0.1 will return true on 10% of calls to Keep.
func (conf *CloudWatchSamplingConfig) Keep() bool {
	if conf.KeepRate == 0 {
		return false
	}
	if conf.KeepRate == 1 {
		return true
	}
	return rand.Float64() <= conf.KeepRate
}

func parseCWEvent(ctx context.Context, b *batch, ev *events.CloudwatchLogsEvent) error {
	data, err := ev.AWSLogs.Parse()
	if err != nil {
		return err
	}

	labels := model.LabelSet{
		model.LabelName("__aws_log_type"):             model.LabelValue("cloudwatch"),
		model.LabelName("__aws_cloudwatch_log_group"): model.LabelValue(data.LogGroup),
		model.LabelName("__aws_cloudwatch_owner"):     model.LabelValue(data.Owner),
	}

	if keepStream {
		labels[model.LabelName("__aws_cloudwatch_log_stream")] = model.LabelValue(data.LogStream)
	}

	var matchingSampleConfs []*CloudWatchSamplingConfig
	for _, c := range cloudWatchSampleFilters {
		if c.MatchStream(data.Owner, data.LogGroup, data.LogStream) {
			matchingSampleConfs = append(matchingSampleConfs, c)
		}
	}

	labels = applyLabels(labels)

outer:
	for _, event := range data.LogEvents {
		for _, c := range matchingSampleConfs {
			if c.MatchLine(event.Message) {
				if !c.Keep() {
					continue outer
				}
				break
			}
		}

		timestamp := time.UnixMilli(event.Timestamp)

		if err := b.add(ctx, entry{labels, logproto.Entry{
			Line:      event.Message,
			Timestamp: timestamp,
		}}); err != nil {
			return err
		}
	}

	return nil
}

func processCWEvent(ctx context.Context, ev *events.CloudwatchLogsEvent, pClient Client) error {
	batch, err := newBatch(ctx, pClient)
	if err != nil {
		return err
	}

	err = parseCWEvent(ctx, batch, ev)
	if err != nil {
		return fmt.Errorf("error parsing log event: %s", err)
	}

	err = pClient.sendToPromtail(ctx, batch)
	if err != nil {
		return err
	}

	return nil
}
