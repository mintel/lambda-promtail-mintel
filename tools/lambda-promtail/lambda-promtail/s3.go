package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/common/model"

	"github.com/grafana/loki/pkg/logproto"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type parserConfig struct {
	// value to use for __aws_log_type label
	logTypeLabel string
	// regex matching filename and and exporting labels from it
	filenameRegex *regexp.Regexp
	// regex that extracts the timestamp from the log sample
	timestampRegex *regexp.Regexp
	// time format to use to convert the timestamp to time.Time
	timestampFormat string
	// if the timestamp is a string that can be parsed or a Unix timestamp
	timestampType string
	// how many lines or jsonToken to skip at the beginning of the file
	skipHeaderCount int
	// key of the metadata label to use as a value for the__aws_<logType>_owner label
	ownerLabelKey string
}

const (
	FLOW_LOG_TYPE              string = "vpcflowlogs"
	LB_LOG_TYPE                string = "elasticloadbalancing"
	CLOUDTRAIL_LOG_TYPE        string = "CloudTrail"
	CLOUDTRAIL_DIGEST_LOG_TYPE string = "CloudTrail-Digest"
	CLOUDFRONT_LOG_TYPE        string = "cloudfront"
	LB_NLB_TYPE                string = "net"
	LB_ALB_TYPE                string = "app"
	WAF_LOG_TYPE               string = "WAFLogs"
)

var (
	// AWS Application Load Balancers
	// source:  https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-file-format
	// format:  bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_app.load-balancer-id_end-time_ip-address_random-string.log.gz
	// example: my-bucket/AWSLogs/123456789012/elasticloadbalancing/us-east-1/2022/01/24/123456789012_elasticloadbalancing_us-east-1_app.my-loadbalancer.b13ea9d19f16d015_20220124T0000Z_0.0.0.0_2et2e1mx.log.gz
	// AWS Network Load Balancers
	// source:  https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html#access-log-file-format
	// format:  bucket[/prefix]/AWSLogs/aws-account-id/elasticloadbalancing/region/yyyy/mm/dd/aws-account-id_elasticloadbalancing_region_net.load-balancer-id_end-time_random-string.log.gz
	// example: my-bucket/prefix/AWSLogs/123456789012/elasticloadbalancing/us-east-2/2016/05/01/123456789012_elasticloadbalancing_us-east-2_net.my-loadbalancer.1234567890abcdef_201605010000Z_2soosksi.log.gz
	// VPC Flow Logs
	// source: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html#flow-logs-s3-path
	// format: bucket-and-optional-prefix/AWSLogs/account_id/vpcflowlogs/region/year/month/day/aws_account_id_vpcflowlogs_region_flow_log_id_YYYYMMDDTHHmmZ_hash.log.gz
	// example: 123456789012_vpcflowlogs_us-east-1_fl-1234abcd_20180620T1620Z_fe123456.log.gz
	// CloudTrail
	// source: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html#cloudtrail-log-filename-format
	// example: 111122223333_CloudTrail_us-east-2_20150801T0210Z_Mu0KsOhtH1ar15ZZ.json.gz
	// CloudFront
	// source https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#AccessLogsFileNaming
	// example: example-prefix/EMLARXS9EXAMPLE.2019-11-14-20.RT4KCN4SGK9.gz
	// AWS WAF logs
	// source: https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html
	// format: aws-waf-logs-suffix[/prefix]/AWSLogs/aws-account-id/WAFLogs/region/webacl-name/year/month/day/hour/minute/aws-account-id_waflogs_region_webacl-name_timestamp_hash.log.gz
	// example: aws-waf-logs-test/AWSLogs/11111111111/WAFLogs/us-east-1/TEST-WEBACL/2021/10/28/19/50/11111111111_waflogs_us-east-1_TEST-WEBACL_20211028T1950Z_e0ca43b5.log.gz
	defaultFilenameRegex     = regexp.MustCompile(`AWSLogs\/(?P<account_id>\d+)\/(?P<type>[a-zA-Z0-9_\-]+)\/(?P<region>[\w-]+)\/(?P<year>\d+)\/(?P<month>\d+)\/(?P<day>\d+)\/\d+\_(?:elasticloadbalancing|vpcflowlogs)_(?:\w+-\w+-(?:\w+-)?\d)_(?:(?P<lb_type>app|net)\.*?)?(?P<src>[a-zA-Z0-9\-]+)`)
	defaultTimestampRegex    = regexp.MustCompile(`(?P<timestamp>\d+-\d+-\d+T\d+:\d+:\d+(?:\.\d+Z)?)`)
	cloudtrailFilenameRegex  = regexp.MustCompile(`AWSLogs\/(?P<organization_id>o-[a-z0-9]{10,32})?\/?(?P<account_id>\d+)\/(?P<type>[a-zA-Z0-9_\-]+)\/(?P<region>[\w-]+)\/(?P<year>\d+)\/(?P<month>\d+)\/(?P<day>\d+)\/\d+\_(?:CloudTrail|CloudTrail-Digest)_(?:\w+-\w+-(?:\w+-)?\d)_(?:(?:app|nlb|net)\.*?)?.+_(?P<src>[a-zA-Z0-9\-]+)`)
	cloudfrontFilenameRegex  = regexp.MustCompile(`(?P<prefix>.*)\/(?P<src>[A-Z0-9]+)\.(?P<year>\d+)-(?P<month>\d+)-(?P<day>\d+)-(.+)`)
	cloudfrontTimestampRegex = regexp.MustCompile(`(?P<timestamp>\d+-\d+-\d+\s\d+:\d+:\d+)`)
	wafFilenameRegex         = regexp.MustCompile(`AWSLogs\/(?P<account_id>\d+)\/(?P<type>WAFLogs)\/(?P<region>[\w-]+)\/(?P<src>[\w-]+)\/(?P<year>\d+)\/(?P<month>\d+)\/(?P<day>\d+)\/(?P<hour>\d+)\/(?P<minute>\d+)\/\d+\_waflogs\_[\w-]+_[\w-]+_\d+T\d+Z_\w+`)
	wafTimestampRegex        = regexp.MustCompile(`"timestamp":\s*(?P<timestamp>\d+),`)
	parsers                  = map[string]parserConfig{
		FLOW_LOG_TYPE: {
			logTypeLabel:    "s3_vpc_flow",
			filenameRegex:   defaultFilenameRegex,
			ownerLabelKey:   "account_id",
			timestampRegex:  defaultTimestampRegex,
			timestampFormat: time.RFC3339,
			timestampType:   "string",
			skipHeaderCount: 1,
		},
		LB_LOG_TYPE: {
			logTypeLabel:    "s3_lb",
			filenameRegex:   defaultFilenameRegex,
			ownerLabelKey:   "account_id",
			timestampFormat: time.RFC3339,
			timestampRegex:  defaultTimestampRegex,
			timestampType:   "string",
		},
		CLOUDTRAIL_LOG_TYPE: {
			logTypeLabel:    "s3_cloudtrail",
			ownerLabelKey:   "account_id",
			skipHeaderCount: 3,
			filenameRegex:   cloudtrailFilenameRegex,
		},
		CLOUDFRONT_LOG_TYPE: {
			logTypeLabel:    "s3_cloudfront",
			filenameRegex:   cloudfrontFilenameRegex,
			ownerLabelKey:   "prefix",
			timestampRegex:  cloudfrontTimestampRegex,
			timestampFormat: "2006-01-02\x0915:04:05",
			timestampType:   "string",
			skipHeaderCount: 2,
		},
		WAF_LOG_TYPE: {
			logTypeLabel:   "s3_waf",
			filenameRegex:  wafFilenameRegex,
			ownerLabelKey:  "account_id",
			timestampRegex: wafTimestampRegex,
			timestampType:  "unix",
		},
	}

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

func getS3Client(ctx context.Context, region string) (*s3.Client, error) {
	var s3Client *s3.Client

	if c, ok := s3Clients[region]; ok {
		s3Client = c
	} else {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return nil, err
		}
		s3Client = s3.NewFromConfig(cfg)
		s3Clients[region] = s3Client
	}
	return s3Client, nil
}

// getS3Client returns an Elastic Load Balancing client for a given region.
func getLBClient(ctx context.Context, region string) (*elasticloadbalancingv2.Client, error) {
	var lbClient *elasticloadbalancingv2.Client

	if c, ok := lbClients[region]; ok {
		lbClient = c
	} else {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return nil, err
		}
		lbClient = elasticloadbalancingv2.NewFromConfig(cfg)
		lbClients[region] = lbClient
	}
	return lbClient, nil
}

func parseS3Log(ctx context.Context, b *batch, labels map[string]string, obj io.ReadCloser, log *log.Logger) error {
	parser, ok := parsers[labels["type"]]
	if !ok {
		if labels["type"] == CLOUDTRAIL_DIGEST_LOG_TYPE {
			return nil
		}
		return fmt.Errorf("could not find parser for type %s", labels["type"])
	}
	gzreader, err := gzip.NewReader(obj)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(gzreader)

	ls := model.LabelSet{
		model.LabelName("__aws_log_type"):                                   model.LabelValue(parser.logTypeLabel),
		model.LabelName(fmt.Sprintf("__aws_%s", parser.logTypeLabel)):       model.LabelValue(labels["src"]),
		model.LabelName(fmt.Sprintf("__aws_%s_owner", parser.logTypeLabel)): model.LabelValue(labels[parser.ownerLabelKey]),
	}

	accountID := labels["account_id"]
	if labels["type"] == LB_LOG_TYPE {
		ls[model.LabelName("lb_name")] = model.LabelValue(labels["src"])
		ls[model.LabelName("lb_account_id")] = model.LabelValue(accountID)
		ls[model.LabelName("lb_aws_region")] = model.LabelValue(labels["region"])
	}

	ls = applyLabels(ls)

	// extract the timestamp of the nested event and sends the rest as raw json
	if labels["type"] == CLOUDTRAIL_LOG_TYPE {
		records := make(chan Record)
		jsonStream := NewJSONStream(records)
		go jsonStream.Start(gzreader, parser.skipHeaderCount)
		// Stream json file
		for record := range jsonStream.records {
			if record.Error != nil {
				return record.Error
			}
			trailEntry, err := parseCloudtrailRecord(record)
			if err != nil {
				return err
			}
			if err := b.add(ctx, entry{ls, trailEntry}); err != nil {
				return err
			}
		}
		return nil
	}

	var lbTagLabels model.LabelSet

	var lineCount int
	for scanner.Scan() {
		log_line := scanner.Text()
		lineCount++
		if lineCount <= parser.skipHeaderCount {
			continue
		}
		if printLogLine {
			fmt.Println(log_line)
		}

		timestamp := time.Now()
		match := parser.timestampRegex.FindStringSubmatch(log_line)
		if len(match) > 0 {
			if labels["lb_type"] == LB_NLB_TYPE {
				// NLB logs don't have .SSSSSSZ suffix. RFC3339 requires a TZ specifier, use UTC
				match[1] += "Z"
			}

			switch parser.timestampType {
			case "string":
				timestamp, err = time.Parse(parser.timestampFormat, match[1])
				if err != nil {
					return err
				}
			case "unix":
				sec, nsec, err := getUnixSecNsec(match[1])
				if err != nil {
					return err
				}
				timestamp = time.Unix(sec, nsec).UTC()
			default:
				level.Warn(*log).Log("msg", fmt.Sprintf("timestamp type of %s parser unknown, using current time", labels["type"]))
			}
		}

		if labels["lb_type"] == LB_ALB_TYPE {
			logLineMatch := loadBalancerLogLineRegex.FindStringSubmatch(log_line)
			if keepLog(accountID, logLineMatch) {
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
						AccountID: accountID,
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

				if err := b.add(ctx, entry{ls.Merge(logLineLabelSet), logproto.Entry{
					Line:      log_line,
					Timestamp: timestamp,
				}}); err != nil {
					return err
				}
				return nil
			}
		}

		if err := b.add(ctx, entry{ls, logproto.Entry{
			Line:      log_line,
			Timestamp: timestamp,
		}}); err != nil {
			return err
		}
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

func getLabels(record events.S3EventRecord) (map[string]string, error) {

	labels := make(map[string]string)

	labels["key"] = record.S3.Object.Key
	labels["bucket"] = record.S3.Bucket.Name
	labels["bucket_owner"] = record.S3.Bucket.OwnerIdentity.PrincipalID
	labels["bucket_region"] = record.AWSRegion
	for key, p := range parsers {
		if p.filenameRegex.MatchString(labels["key"]) {
			if labels["type"] == "" {
				labels["type"] = key
			}
			match := p.filenameRegex.FindStringSubmatch(labels["key"])
			for i, name := range p.filenameRegex.SubexpNames() {
				if i != 0 && name != "" && match[i] != "" {
					labels[name] = match[i]
				}
			}
		}
	}
	if labels["type"] == "" {
		return labels, fmt.Errorf("type of S3 event could not be determined for object %q", record.S3.Object.Key)
	}
	return labels, nil
}

func processS3Event(ctx context.Context, ev *events.S3Event, pc Client, log *log.Logger) error {
	batch, err := newBatch(ctx, pc)
	if err != nil {
		return err
	}
	for _, record := range ev.Records {
		labels, err := getLabels(record)
		if err != nil {
			return err
		}
		level.Info(*log).Log("msg", fmt.Sprintf("fetching s3 file: %s", labels["key"]))
		s3Client, err := getS3Client(ctx, labels["bucket_region"])
		if err != nil {
			return err
		}
		obj, err := s3Client.GetObject(ctx,
			&s3.GetObjectInput{
				Bucket:              aws.String(labels["bucket"]),
				Key:                 aws.String(labels["key"]),
				ExpectedBucketOwner: aws.String(labels["bucketOwner"]),
			})
		if err != nil {
			return fmt.Errorf("Failed to get object %s from bucket %s on account %s\n, %s", labels["key"], labels["bucket"], labels["bucketOwner"], err)
		}
		err = parseS3Log(ctx, batch, labels, obj.Body, log)
		if err != nil {
			return err
		}
	}

	err = pc.sendToPromtail(ctx, batch)
	if err != nil {
		return err
	}

	return nil
}

func processSNSEvent(ctx context.Context, evt *events.SNSEvent, handler func(ctx context.Context, ev map[string]interface{}) error) error {
	for _, record := range evt.Records {
		event, err := stringToRawEvent(record.SNS.Message)
		if err != nil {
			return err
		}
		err = handler(ctx, event)
		if err != nil {
			return err
		}
	}
	return nil
}

func processSQSEvent(ctx context.Context, evt *events.SQSEvent, handler func(ctx context.Context, ev map[string]interface{}) error) error {
	for _, record := range evt.Records {
		// retrieve nested
		event, err := stringToRawEvent(record.Body)
		if err != nil {
			return err
		}
		err = handler(ctx, event)
		if err != nil {
			return err
		}
	}
	return nil
}

func stringToRawEvent(body string) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	err := json.Unmarshal([]byte(body), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// getUnixSecNsec returns the Unix time seconds and nanoseconds in the string s.
// It assumes that the first 10 digits of the parsed int is the Unix time in seconds and the rest is the nanoseconds part.
// This assumption will hold until 2286-11-20 17:46:40 UTC, so it's a safe assumption.
// It also makes use of the fact that the log10 of a number in base 10 is its number of digits - 1.
// It returns early if the fractional seconds is 0 because getting the log10 of 0 results in -Inf.
// For example, given a string 1234567890123:
//
//	iLog10 = 12  // the parsed int is 13 digits long
//	multiplier = 0.001  // to get the seconds part it must be divided by 1000
//	sec = 1234567890123 * 0.001 = 1234567890  // this is the seconds part of the Unix time
//	fractionalSec = 123  // the rest of the parsed int
//	fractionalSecLog10 = 2  // it is 3 digits long
//	multiplier = 1000000  // nano is 10^-9, so the nanoseconds part is 9 digits long
//	nsec = 123000000  // this is the nanoseconds part of the Unix time
func getUnixSecNsec(s string) (sec int64, nsec int64, err error) {
	const (
		UNIX_SEC_LOG10     = 9
		UNIX_NANOSEC_LOG10 = 8
	)

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return sec, nsec, err
	}

	iLog10 := int(math.Log10(float64(i)))
	multiplier := math.Pow10(UNIX_SEC_LOG10 - iLog10)
	sec = int64(float64(i) * multiplier)

	fractionalSec := float64(i % sec)
	if fractionalSec == 0 {
		return sec, 0, err
	}

	fractionalSecLog10 := int(math.Log10(fractionalSec))
	multiplier = math.Pow10(UNIX_NANOSEC_LOG10 - fractionalSecLog10)
	nsec = int64(fractionalSec * multiplier)

	return sec, nsec, err
}
