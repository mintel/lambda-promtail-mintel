package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/grafana/loki/pkg/logproto"
	"github.com/prometheus/common/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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
	typeIndex              = loadBalancerLogLineRegex.SubexpIndex("type")
	requestUrlIndex        = loadBalancerLogLineRegex.SubexpIndex("request_url") // we create a label for the endpoint of the url, not the full url
	elbStatusCodeIndex     = loadBalancerLogLineRegex.SubexpIndex("elb_status_code")
	targetStatusCodeIndex  = loadBalancerLogLineRegex.SubexpIndex("target_status_code")
	lambdaErrorReasonIndex = loadBalancerLogLineRegex.SubexpIndex("lambda_error_reason")

	// regex that matches the endpoint of a request url in a load balancer log line
	// format:  protocol://host:port/uri
	// example: https://omni-web.svc.us-dev1.dev.mintel.cloud:443/internal/sso/retrieveAccessRights
	// result:  retrieveAccessRights
	requestUrlEndpointRegex = regexp.MustCompile(`([^0-9/]*$)`)

	// for all accounts, don't push load balancer logs with traffic to these endpoints to loki
	skipEndpoints = map[string]struct{}{"external-health-check": {}, "healthz": {}, "readiness": {}, "healthy": {}, "metrics": {}, "readyz": {}}

	// if the load balancer is in the 'logs' aws account, don't push load balancer logs with traffic to these endpoints to loki
	skipLogsAccountEndpoints = map[string]struct{}{"push": {}, "prometheus": {}}
	logsAccountId            = "529633446764"
)

func getS3Object(ctx context.Context, labels map[string]string) (io.ReadCloser, error) {
	var s3Client *s3.Client

	if c, ok := s3Clients[labels["bucket_region"]]; ok {
		s3Client = c
	} else {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(labels["bucket_region"]))
		if err != nil {
			return nil, err
		}
		s3Client = s3.NewFromConfig(cfg)
		s3Clients[labels["bucket_region"]] = s3Client
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
		model.LabelName("lb_aws_region"):  model.LabelValue(labels["bucket_region"]),
	}

	ls = applyExtraLabels(ls)

	for scanner.Scan() {
		i := 0
		log_line := scanner.Text()
		timestampMatch := timestampRegex.FindStringSubmatch(log_line)
		logLineMatch := loadBalancerLogLineRegex.FindStringSubmatch(log_line)

		timestamp, err := time.Parse(time.RFC3339, timestampMatch[1])
		if err != nil {
			return err
		}

		targetEndpoint := requestUrlEndpointRegex.FindStringSubmatch(logLineMatch[requestUrlIndex])[1]

		if !skipLog(targetEndpoint, accountId) {
			logLineLabelSet := model.LabelSet{
				model.LabelName("lb_type"):                model.LabelValue(logLineMatch[typeIndex]),
				model.LabelName("lb_elb_status_code"):     model.LabelValue(logLineMatch[elbStatusCodeIndex]),
				model.LabelName("lb_target_status_code"):  model.LabelValue(logLineMatch[targetStatusCodeIndex]),
				model.LabelName("lb_lambda_error_reason"): model.LabelValue(logLineMatch[lambdaErrorReasonIndex]),
			}

			b.add(ctx, entry{ls.Merge(logLineLabelSet), logproto.Entry{
				Line:      log_line,
				Timestamp: timestamp,
			}})
		}
		i++
	}

	return nil
}

// Return true if record should be skipped and not pushed to loki.
// We want to skip records containing a target endpoint that would clutter the logs, such as
// health checks, readiness checks, and api calls to loki and prometheus on the monitoring cluster.
func skipLog(targetEndpoint string, accountId string) bool {
	_, skipFromAllAccounts := skipEndpoints[targetEndpoint]
	_, skipFromLogsAccount := skipLogsAccountEndpoints[targetEndpoint]
	return skipFromAllAccounts || (skipFromLogsAccount && accountId == logsAccountId)
}

func getLabels(record events.S3EventRecord) (map[string]string, error) {

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
		labels, err := getLabels(record)
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
