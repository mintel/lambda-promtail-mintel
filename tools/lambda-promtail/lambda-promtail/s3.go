package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/grafana/loki/pkg/logproto"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/common/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	// regex that parses the log file name fields
	// source:  https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-file-format
	// format:  bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_app.load-balancer-id_end-time_ip-address_random-string.log.gz
	// example: my-bucket/AWSLogs/123456789012/elasticloadbalancing/us-east-1/2022/01/24/123456789012_elasticloadbalancing_us-east-1_app.my-loadbalancer.b13ea9d19f16d015_20220124T0000Z_0.0.0.0_2et2e1mx.log.gz
	filenameRegex = regexp.MustCompile(`AWSLogs\/(?P<account_id>\d+)\/elasticloadbalancing\/(?P<region>[\w-]+)\/(?P<year>\d+)\/(?P<month>\d+)\/(?P<day>\d+)\/\d+\_elasticloadbalancing\_\w+-\w+-\d_(?:(?:app|nlb)\.*?)?(?P<lb>[a-zA-Z\-\d]+)`)

	// regex that extracts the timestamp (RFC3339) from message log
	timestampRegex = regexp.MustCompile(`\w+ (?P<timestamp>\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)`)

	// regex that matches the format of a single line of an AWS Load Balancer log
	// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
	// https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html
	loadBalancerLogLineRegex = regexp.MustCompile(`(?P<type>[^ ]*) (?P<time>[^ ]*) (?P<elb>[^ ]*) (?P<client_ip>[^ ]*):(?P<client_port>[0-9]*) (?P<target_ip>[^ ]*)[:-](?P<target_port>[0-9]*) (?P<request_processing_time>[-.0-9]*) (?P<target_processing_time>[-.0-9]*) (?P<response_processing_time>[-.0-9]*) (?P<elb_status_code>|[-0-9]*) (?P<target_status_code>-|[-0-9]*) (?P<received_bytes>[-0-9]*) (?P<sent_bytes>[-0-9]*) \"(?P<request_verb>[^ ]*) (?P<request_url>.*) (?P<request_proto>- |[^ ]*)\" \"(?P<user_agent>[^\"]*)\" (?P<ssl_cipher>[A-Z0-9-_]+) (?P<ssl_protocol>[A-Za-z0-9.-]*) (?P<target_group_arn>[^ ]*) \"(?P<trace_id>[^\"]*)\" \"(?P<domain_name>[^\"]*)\" \"(?P<chosen_cert_arn>[^\"]*)\" (?P<matched_rule_priority>[-.0-9]*) (?P<request_creation_time>[^ ]*) \"(?P<actions_executed>[^\"]*)\" \"(?P<redirect_url>[^\"]*)\" \"(?P<lambda_error_reason>[^ ]*)\" \"(?P<target_port_list>[^\s]+?)\" \"(?P<target_status_code_list>[^\s]+)\" \"(?P<classification>[^ ]*)\" \"(?P<classification_reason>[^ ]*)\"`)

	// the indexes of the fields in the log that we want to create labels for
	clientIPIndex          = loadBalancerLogLineRegex.SubexpIndex("client_ip")
	elbIndex               = loadBalancerLogLineRegex.SubexpIndex("elb")
	elbStatusCodeIndex     = loadBalancerLogLineRegex.SubexpIndex("elb_status_code")
	lambdaErrorReasonIndex = loadBalancerLogLineRegex.SubexpIndex("lambda_error_reason")
	requestURLIndex        = loadBalancerLogLineRegex.SubexpIndex("request_url")
	requestVerbIndex       = loadBalancerLogLineRegex.SubexpIndex("request_verb")
	targetGroupARNIndex    = loadBalancerLogLineRegex.SubexpIndex("target_group_arn")
	targetStatusCodeIndex  = loadBalancerLogLineRegex.SubexpIndex("target_status_code")
	typeIndex              = loadBalancerLogLineRegex.SubexpIndex("type")
)

// S3SamplingConfig represents some pattern of S3 access logs that
// should be dropped probabilistically.
type S3SamplingConfig struct {
	AccountIDs CommaSeparatedStringSet `json:"account"` // List of AWS account IDs to match on e.g. "123456789012,2345678901234".

	// List of load balancer connection types.
	// Valid values are `http`, `https`, `h2`, `grpcs`, `ws`, `wss`.
	// See: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-entry-syntax
	Types CommaSeparatedStringSet `json:"type"`

	ClientIPAddresses CommaSeparatedCIDRSet      `json:"ip"`     // List of client IP CIDR blocks to match on e.g. "1.2.3.4/0,5.6.7.8/16".
	Methods           CommaSeparatedStringSet    `json:"method"` // List of HTTP methods to match on e.g. "GET,PUT".
	StatusCodes       CommaSeparatedStringSet    `json:"status"` // List of response status codes to match on e.g. "200,401".
	Hosts             *CommaSeparatedHostnameSet `json:"host"`   // List of hostnames matched against the hostname of the request. Can include wildcards e.g. `*.example.org`.

	// A regexp that will be matched against the path of the request.
	Path *RegexpString `json:"path"`

	// A probability between 0 and 1.
	// If a log line matches the filters above, keep that log line with this probability.
	KeepRate float64 `json:"keep"`
}

// Match returns true if a log line matches this sampling filter.
func (conf *S3SamplingConfig) Match(accountID string, logLineMatch []string) bool {
	if len(conf.AccountIDs) > 0 {
		if !conf.AccountIDs.Contains(accountID) {
			return false
		}
	}
	if len(conf.Types) > 0 {
		t := logLineMatch[typeIndex]
		if !conf.Types.Contains(t) {
			return false
		}
	}
	if len(conf.Methods) > 0 {
		m := logLineMatch[requestVerbIndex]
		if !conf.Methods.Contains(m) {
			return false
		}
	}
	if len(conf.StatusCodes) > 0 {
		c := logLineMatch[elbStatusCodeIndex]
		if !conf.StatusCodes.Contains(c) {
			return false
		}
	}
	if len(conf.ClientIPAddresses) > 0 {
		ip, err := netip.ParseAddr(logLineMatch[clientIPIndex])
		if err != nil {
			fmt.Println("warn: log IP cannot be parsed:", err)
			return false
		}
		if !conf.ClientIPAddresses.Match(ip) {
			return false
		}
	}
	u, err := url.Parse(logLineMatch[requestURLIndex])
	if err != nil {
		fmt.Println("warn: log URL cannot be parsed:", err)
		return false
	}
	if !conf.Hosts.IsZero() {
		if !conf.Hosts.Match(u.Host) {
			return false
		}
	}
	if !conf.Path.IsZero() {
		if !conf.Path.MatchString(u.Path) {
			return false
		}
	}
	return true
}

// Keep randomly returns true or false at a rate depending on conf.KeepRate.
// A KeepRate of 0.1 will return true on 10% of calls to Keep.
func (conf *S3SamplingConfig) Keep() bool {
	if conf.KeepRate == 0 {
		return false
	}
	if conf.KeepRate == 1 {
		return true
	}
	return rand.Float64() <= conf.KeepRate
}

func getS3Object(ctx context.Context, labels map[string]string) (io.ReadCloser, error) {
	s3Client, err := getS3Client(ctx, labels["bucket_region"])
	if err != nil {
		return nil, err
	}

	obj, err := s3Client.GetObject(ctx,
		&s3.GetObjectInput{
			Bucket:              aws.String(labels["bucket"]),
			Key:                 aws.String(labels["key"]),
			ExpectedBucketOwner: aws.String(labels["bucketOwner"]),
		})

	if err != nil {
		fmt.Printf("Failed to get object %s from bucket %s on account %s\n", labels["key"], labels["bucket"], labels["bucketOwner"])
		return nil, err
	}

	return obj.Body, nil
}

func parseS3Log(ctx context.Context, b *batch, labels map[string]string, obj io.ReadCloser) error {
	gzreader, err := gzip.NewReader(obj)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(gzreader)

	accountId := labels["account_id"]
	ls := model.LabelSet{
		model.LabelName("__aws_log_type"): model.LabelValue("s3_lb"),
		model.LabelName("lb_name"):        model.LabelValue(labels["lb"]),
		model.LabelName("lb_account_id"):  model.LabelValue(accountId),
		model.LabelName("lb_aws_region"):  model.LabelValue(labels["region"]),
	}

	ls = applyExtraLabels(ls)

	var lbTagLabels model.LabelSet

	for scanner.Scan() {
		i := 0
		log_line := scanner.Text()
		timestampMatch := timestampRegex.FindStringSubmatch(log_line)
		logLineMatch := loadBalancerLogLineRegex.FindStringSubmatch(log_line)

		timestamp, err := time.Parse(time.RFC3339, timestampMatch[1])
		if err != nil {
			return err
		}

		if keepLog(accountId, logLineMatch) {
			logLineLabelSet := model.LabelSet{
				model.LabelName("lb_type"):                model.LabelValue(logLineMatch[typeIndex]),
				model.LabelName("lb_elb_status_code"):     model.LabelValue(logLineMatch[elbStatusCodeIndex]),
				model.LabelName("lb_target_status_code"):  model.LabelValue(logLineMatch[targetStatusCodeIndex]),
				model.LabelName("lb_lambda_error_reason"): model.LabelValue(logLineMatch[lambdaErrorReasonIndex]),
			}

			lbARN := ""
			if len(logLineMatch[elbIndex]) > 1 {
				lbARN = arn.ARN{
					Partition: "aws",
					Service:   "elasticloadbalancing",
					Region:    labels["region"],
					AccountID: accountId,
					Resource:  "loadbalancer/" + logLineMatch[elbIndex],
				}.String()
			}

			if lbTagLabels == nil {
				// We only need to do this one since all log lines in the same S3 object belong to the same load balancer.
				lbTagLabels, err = applyLBResourceTags(ctx, lbTagsConf, labels["region"], lbARN)
				if err != nil {
					return err
				}
			}
			logLineLabelSet = logLineLabelSet.Merge(lbTagLabels)

			tgTagLabels, err := applyLBResourceTags(ctx, tgTagsConf, labels["region"], logLineMatch[targetGroupARNIndex])
			if err != nil {
				return err
			}
			logLineLabelSet = logLineLabelSet.Merge(tgTagLabels)

			b.add(ctx, entry{ls.Merge(logLineLabelSet), logproto.Entry{
				Line:      log_line,
				Timestamp: timestamp,
			}})
		}
		i++
	}

	return nil
}

func applyLBResourceTags(ctx context.Context, tagsToExtract map[string]string, awsRegion, ARN string) (model.LabelSet, error) {
	if len(tagsToExtract) == 0 || ARN == "" || ARN == "-" {
		return nil, nil
	}

	lbLabels := make(model.LabelSet, len(lbTagsConf))

	var tags map[string]string
	if cacheEntry := tagsCache.Get(ARN); cacheEntry != nil {
		tags = cacheEntry.Value()
	} else {
		lbClient, err := getLBClient(ctx, awsRegion)
		if err != nil {
			fmt.Println("error getting LB", err)
			return nil, err
		}

		resp, err := lbClient.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{
			ResourceArns: []string{ARN},
		})
		if err != nil {
			fmt.Println("error getting tags", err)
			return nil, err
		}

		tags = make(map[string]string)
		for _, tagDesc := range resp.TagDescriptions {
			for _, tag := range tagDesc.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
		}

		tagsCache.Set(ARN, tags, ttlcache.DefaultTTL)
	}

	for tag, label := range tagsToExtract {
		if label == "" {
			label = tag
		}
		lbLabels[model.LabelName(label)] = model.LabelValue(tags[tag])
	}

	return lbLabels, nil
}

// Return true if record should be pushed to loki.
func keepLog(accountId string, logLineMatch []string) bool {
	for _, conf := range s3SampleFilters {
		if conf.Match(accountId, logLineMatch) {
			return conf.Keep()
		}
	}
	return true
}

func getObjLabels(record events.S3EventRecord) (map[string]string, error) {

	labels := make(map[string]string)

	labels["key"] = record.S3.Object.Key
	labels["bucket"] = record.S3.Bucket.Name
	labels["bucket_owner"] = record.S3.Bucket.OwnerIdentity.PrincipalID
	labels["bucket_region"] = record.AWSRegion

	match := filenameRegex.FindStringSubmatch(labels["key"])
	for i, name := range filenameRegex.SubexpNames() {
		if i != 0 && name != "" {
			labels[name] = match[i]
		}
	}

	return labels, nil
}

func processS3Event(ctx context.Context, ev *events.S3Event) error {

	fmt.Println("processing new S3Event")

	batch, _ := newBatch(ctx)

	for _, record := range ev.Records {
		labels, err := getObjLabels(record)
		if err != nil {
			return err
		}

		obj, err := getS3Object(ctx, labels)
		if err != nil {
			return err
		}

		err = parseS3Log(ctx, batch, labels, obj)
		if err != nil {
			return err
		}

	}

	err := sendToPromtail(ctx, batch)
	if err != nil {
		return err
	}

	return nil
}
