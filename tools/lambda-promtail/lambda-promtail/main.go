package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/common/model"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

const (
	// We use snappy-encoded protobufs over http by default.
	contentType = "application/x-protobuf"

	maxErrMsgLen = 1024

	invalidExtraLabelsError = "Invalid value for environment variable EXTRA_LABELS. Expected a comma seperated list with an even number of entries. "
)

var (
	writeAddress                                 *url.URL
	username, password, extraLabelsRaw, tenantID string
	keepStream                                   bool
	batchSize                                    int
	extraLabels                                  model.LabelSet
	cloudWatchSampleFilters                      []*CloudWatchSamplingConfig
	s3SampleFilters                              []*S3SamplingConfig
	lbTagsConf                                   map[string]string
	tgTagsConf                                   map[string]string

	// TTL cache ARN to AWS resource tags.
	tagsCache = ttlcache.New(
		ttlcache.WithTTL[string, map[string]string](30*time.Second),
		ttlcache.WithDisableTouchOnHit[string, map[string]string](),
	)
)

func init() {
	go tagsCache.Start()
}
func setupArguments() {
	addr := os.Getenv("WRITE_ADDRESS")
	if addr == "" {
		panic(errors.New("required environmental variable WRITE_ADDRESS not present, format: https://<hostname>/loki/api/v1/push"))
	}

	var err error
	writeAddress, err = url.Parse(addr)
	if err != nil {
		panic(err)
	}

	fmt.Println("write address: ", writeAddress.String())

	extraLabelsRaw = os.Getenv("EXTRA_LABELS")
	extraLabels, err = parseExtraLabels(extraLabelsRaw)
	if err != nil {
		panic(err)
	}

	username = os.Getenv("USERNAME")
	password = os.Getenv("PASSWORD")
	// If either username or password is set then both must be.
	if (username != "" && password == "") || (username == "" && password != "") {
		panic("both username and password must be set if either one is set")
	}

	tenantID = os.Getenv("TENANT_ID")

	keep := os.Getenv("KEEP_STREAM")
	// Anything other than case-insensitive 'true' is treated as 'false'.
	if strings.EqualFold(keep, "true") {
		keepStream = true
	}
	fmt.Println("keep stream: ", keepStream)

	batch := os.Getenv("BATCH_SIZE")
	batchSize = 131072
	if batch != "" {
		batchSize, _ = strconv.Atoi(batch)
	}

	cloudWatchSampling := os.Getenv("SAMPLE_CLOUDWATCH")
	if cloudWatchSampling != "" {
		if err := json.Unmarshal([]byte(cloudWatchSampling), &cloudWatchSampleFilters); err != nil {
			panic(err)
		}
	}

	s3Sampling := os.Getenv("SAMPLE_S3")
	if s3Sampling != "" {
		if err := json.Unmarshal([]byte(s3Sampling), &s3SampleFilters); err != nil {
			panic(err)
		}
	}

	// Extract tags on the load balancer as Loki labels.
	// This can only work if lambda-promtail is deployed in the same account as the load balancer.
	// Take a comma-separated list of string. Example:
	//
	//   Foo,Bar=baz
	//
	// Tag "Foo" would be extracted as label "Foo", and tag "Bar" would be extracted as label "baz".
	if c := os.Getenv("EXTRACT_LB_TAGS"); c != "" {
		lbTagsConf = make(map[string]string)
		for _, part := range strings.Split(c, ",") {
			tag, label, _ := strings.Cut(part, "=")
			lbTagsConf[tag] = label
		}
	}

	// Extract tags on the target group as Loki labels.
	// This can only work if lambda-promtail is deployed in the same account as the load balancer.
	// Take a comma-separated list of string. Example:
	//
	//   Foo,Bar=baz
	//
	// Tag "Foo" would be extracted as label "Foo", and tag "Bar" would be extracted as label "baz".
	if c := os.Getenv("EXTRACT_TG_TAGS"); c != "" {
		tgTagsConf = make(map[string]string)
		for _, part := range strings.Split(c, ",") {
			tag, label, _ := strings.Cut(part, "=")
			tgTagsConf[tag] = label
		}
	}
}

func parseExtraLabels(extraLabelsRaw string) (model.LabelSet, error) {
	var extractedLabels = model.LabelSet{}
	extraLabelsSplit := strings.Split(extraLabelsRaw, ",")

	if len(extraLabelsRaw) < 1 {
		return extractedLabels, nil
	}

	if len(extraLabelsSplit)%2 != 0 {
		return nil, fmt.Errorf(invalidExtraLabelsError)
	}
	for i := 0; i < len(extraLabelsSplit); i += 2 {
		extractedLabels[model.LabelName("__extra_"+extraLabelsSplit[i])] = model.LabelValue(extraLabelsSplit[i+1])
	}
	err := extractedLabels.Validate()
	if err != nil {
		return nil, err
	}
	fmt.Println("extra labels:", extractedLabels)
	return extractedLabels, nil
}

func applyExtraLabels(labels model.LabelSet) model.LabelSet {
	return labels.Merge(extraLabels)
}

func checkEventType(ev map[string]interface{}) (interface{}, error) {
	var s3Event events.S3Event
	var cwEvent events.CloudwatchLogsEvent

	types := [...]interface{}{&s3Event, &cwEvent}

	j, _ := json.Marshal(ev)
	reader := strings.NewReader(string(j))
	d := json.NewDecoder(reader)
	d.DisallowUnknownFields()

	for _, t := range types {
		err := d.Decode(t)

		if err == nil {
			return t, nil
		}

		reader.Seek(0, 0)
	}

	return nil, fmt.Errorf("unknown event type!")
}

func handler(ctx context.Context, ev map[string]interface{}) error {

	event, err := checkEventType(ev)
	if err != nil {
		fmt.Printf("invalid event: %s\n", ev)
		return err
	}

	switch event.(type) {
	case *events.S3Event:
		return processS3Event(ctx, event.(*events.S3Event))
	case *events.CloudwatchLogsEvent:
		return processCWEvent(ctx, event.(*events.CloudwatchLogsEvent))
	}

	return err
}

func main() {
	setupArguments()
	lambda.Start(handler)
}
