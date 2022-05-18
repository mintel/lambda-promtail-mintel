package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS3SamplingConfig_Match(t *testing.T) {
	type args struct {
		accountID string
		logLine   string
		confJSON  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "health",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:01.039648Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 65.175.50.10:35362 10.14.102.123:80 0.000 0.030 0.000 200 200 6514 167 "GET https://onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud:443/external-health-check HTTP/1.1" "Prometheus/2.23.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b55-735a492258a7d74058509db2" "onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/974741ab-49bd-46ab-81b6-beeea653799a" 1 2022-05-18T02:35:01.009000Z "forward" "-" "-" "10.14.102.123:80" "200" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"path": "/(external-health-check|healthz|healthy|readiness|readyz|metrics)$"
					}
				`,
			},
			want: true,
		},
		{
			name: "not-health",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:00.892913Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 5.148.102.70:57512 10.14.102.123:80 0.000 0.004 0.000 401 401 777 316 "POST https://onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud:443/loki/api/v1/push HTTP/1.1" "promtail/2.0.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b54-03322dfe71483c2658d8e32a" "onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/d04ec6bf-79af-45c9-bd52-c4352efe0e56" 1 2022-05-18T02:35:00.888000Z "forward" "-" "-" "10.14.102.123:80" "401" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"path": "/(external-health-check|healthz|healthy|readiness|readyz|metrics)$"
					}
				`,
			},
			want: false,
		},
		{
			name: "health-substring",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:00.892913Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 5.148.102.70:57512 10.14.102.123:80 0.000 0.004 0.000 401 401 777 316 "POST https://onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud:443/example/healthz HTTP/1.1" "promtail/2.0.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b54-03322dfe71483c2658d8e32a" "onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/d04ec6bf-79af-45c9-bd52-c4352efe0e56" 1 2022-05-18T02:35:00.888000Z "forward" "-" "-" "10.14.102.123:80" "401" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"path": "/(external-health-check|healthz|healthy|readiness|readyz|metrics)$"
					}
				`,
			},
			want: true,
		},
		{
			name: "loki",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:00.892913Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 5.148.102.70:57512 10.14.102.123:80 0.000 0.004 0.000 401 401 777 316 "POST https://onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud:443/loki/api/v1/push HTTP/1.1" "promtail/2.0.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b54-03322dfe71483c2658d8e32a" "onprem-qa.loki.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/d04ec6bf-79af-45c9-bd52-c4352efe0e56" 1 2022-05-18T02:35:00.888000Z "forward" "-" "-" "10.14.102.123:80" "401" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"host": "*.loki.*",
						"path": "^/loki/api/v1/push"
					}
				`,
			},
			want: true,
		},
		{
			name: "cortex",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:01.039648Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 65.175.50.10:35362 10.14.102.123:80 0.000 0.030 0.000 200 200 6514 167 "POST https://onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud:443/api/v1/push HTTP/1.1" "Prometheus/2.23.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b55-735a492258a7d74058509db2" "onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/974741ab-49bd-46ab-81b6-beeea653799a" 1 2022-05-18T02:35:01.009000Z "forward" "-" "-" "10.14.102.123:80" "200" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"host": "*.cortex.*",
						"path": "^(/api/v1/push|/api/prom/push|/prometheus/api/v1/write)"
					}
				`,
			},
			want: true,
		},
		{
			name: "ip",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:01.039648Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 65.175.50.10:35362 10.14.102.123:80 0.000 0.030 0.000 200 200 6514 167 "GET https://onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud:443/external-health-check HTTP/1.1" "Prometheus/2.23.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b55-735a492258a7d74058509db2" "onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/974741ab-49bd-46ab-81b6-beeea653799a" 1 2022-05-18T02:35:01.009000Z "forward" "-" "-" "10.14.102.123:80" "200" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"ip": "65.175.0.0/16"
					}
				`,
			},
			want: true,
		},
		{
			name: "not-ip",
			args: args{
				accountID: "123456789012",
				logLine:   `https 2022-05-18T02:35:01.039648Z app/k8s-albdefault-d03a586d74/0b1519348a786e51 65.175.50.10:35362 10.14.102.123:80 0.000 0.030 0.000 200 200 6514 167 "GET https://onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud:443/external-health-check HTTP/1.1" "Prometheus/2.23.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:529633446764:targetgroup/k8s-ingressc-haproxyi-294703d4c5/7a4aad31d5cea679 "Root=1-62845b55-735a492258a7d74058509db2" "onprem-qa.cortex.svc.us-monitoring1.logs.mintel.cloud" "arn:aws:acm:us-east-2:529633446764:certificate/974741ab-49bd-46ab-81b6-beeea653799a" 1 2022-05-18T02:35:01.009000Z "forward" "-" "-" "10.14.102.123:80" "200" "-" "-"`,
				confJSON: `
					{
						"keep": 0.1,
						"ip": "10.0.0.0/16"
					}
				`,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conf *S3SamplingConfig
			err := json.Unmarshal([]byte(strings.TrimSpace(tt.args.confJSON)), &conf)
			if err != nil {
				t.Fatal(err)
			}
			logLineMatch := loadBalancerLogLineRegex.FindStringSubmatch(tt.args.logLine)
			if len(logLineMatch) == 0 {
				t.Fatal("log line does not match regexp")
			}
			got := conf.Match(tt.args.accountID, logLineMatch)
			if tt.want {
				require.True(t, got)
			} else {
				require.False(t, got)
			}
		})
	}
}
