package syntax

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/stretchr/testify/require"

	"github.com/grafana/loki/pkg/logql/log"
)

var labelBar, _ = ParseLabels("{app=\"bar\"}")

func Test_logSelectorExpr_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		selector     string
		expectFilter bool
	}{
		{`{foo="bar"}`, false},
		{`{foo="bar", bar!="baz"}`, false},
		{`{foo="bar", bar!="baz"} != "bip" !~ ".+bop"`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap"`, true},
		{`{foo="bar", bar!="baz"} |= ""`, false},
		{`{foo="bar", bar!="baz"} |= "" |= ip("::1")`, true},
		{`{foo="bar", bar!="baz"} |= "" != ip("127.0.0.1")`, true},
		{`{foo="bar", bar!="baz"} |~ ""`, false},
		{`{foo="bar", bar!="baz"} |~ ".*"`, false},
		{`{foo="bar", bar!="baz"} |= "" |= ""`, false},
		{`{foo="bar", bar!="baz"} |~ "" |= "" |~ ".*"`, false},
		{`{foo="bar", bar!="baz"} != "bip" !~ ".+bop" | json`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | logfmt`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | unpack | foo>5`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | pattern "<foo> bar <buzz>" | foo>5`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | logfmt | b>=10GB`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | logfmt | b=ip("127.0.0.1")`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | logfmt | b=ip("127.0.0.1") | level="error"`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | logfmt | b=ip("127.0.0.1") | level="error" | c=ip("::1")`, true}, // chain inside label filters.
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | regexp "(?P<foo>foo|bar)"`, true},
		{`{foo="bar"} |= "baz" |~ "blip" != "flip" !~ "flap" | regexp "(?P<foo>foo|bar)" | ( ( foo<5.01 , bar>20ms ) or foo="bar" ) | line_format "blip{{.boop}}bap" | label_format foo=bar,bar="blip{{.blop}}"`, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.selector, func(t *testing.T) {
			t.Parallel()
			expr, err := ParseLogSelector(tt.selector, true)
			if err != nil {
				t.Fatalf("failed to parse log selector: %s", err)
			}
			p, err := expr.Pipeline()
			if err != nil {
				t.Fatalf("failed to get filter: %s", err)
			}
			if !tt.expectFilter {
				require.Equal(t, log.NewNoopPipeline(), p)
			}
			if expr.String() != tt.selector {
				t.Fatalf("error expected: %s got: %s", tt.selector, expr.String())
			}
		})
	}
}

func Test_SampleExpr_String(t *testing.T) {
	t.Parallel()
	for _, tc := range []string{
		`rate( ( {job="mysql"} |="error" !="timeout" ) [10s] )`,
		`absent_over_time( ( {job="mysql"} |="error" !="timeout" ) [10s] )`,
		`absent_over_time( ( {job="mysql"} |="error" !="timeout" ) [10s] offset 10d )`,
		`sum without(a) ( rate ( ( {job="mysql"} |="error" !="timeout" ) [10s] ) )`,
		`sum by(a) (rate( ( {job="mysql"} |="error" !="timeout" ) [10s] ) )`,
		`sum(count_over_time({job="mysql"}[5m]))`,
		`sum(count_over_time({job="mysql"}[5m] offset 10m))`,
		`sum(count_over_time({job="mysql"} | json [5m]))`,
		`sum(count_over_time({job="mysql"} | json [5m] offset 10m))`,
		`sum(count_over_time({job="mysql"} | logfmt [5m]))`,
		`sum(count_over_time({job="mysql"} | logfmt [5m] offset 10m))`,
		`sum(count_over_time({job="mysql"} | pattern "<foo> bar <buzz>" | json [5m]))`,
		`sum(count_over_time({job="mysql"} | unpack | json [5m]))`,
		`sum(count_over_time({job="mysql"} | regexp "(?P<foo>foo|bar)" [5m]))`,
		`sum(count_over_time({job="mysql"} | regexp "(?P<foo>foo|bar)" [5m] offset 10y))`,
		`topk(10,sum(rate({region="us-east1"}[5m])) by (name))`,
		`topk by (name)(10,sum(rate({region="us-east1"}[5m])))`,
		`avg( rate( ( {job="nginx"} |= "GET" ) [10s] ) ) by (region)`,
		`avg(min_over_time({job="nginx"} |= "GET" | unwrap foo[10s])) by (region)`,
		`avg(min_over_time({job="nginx"} |= "GET" | unwrap foo[10s] offset 10m)) by (region)`,
		`sum by (cluster) (count_over_time({job="mysql"}[5m]))`,
		`sum by (cluster) (count_over_time({job="mysql"}[5m] offset 10m))`,
		`sum by (cluster) (count_over_time({job="mysql"}[5m])) / sum by (cluster) (count_over_time({job="postgres"}[5m])) `,
		`sum by (cluster) (count_over_time({job="mysql"}[5m] offset 10m)) / sum by (cluster) (count_over_time({job="postgres"}[5m] offset 10m)) `,
		`
		sum by (cluster) (count_over_time({job="postgres"}[5m])) /
		sum by (cluster) (count_over_time({job="postgres"}[5m])) /
		sum by (cluster) (count_over_time({job="postgres"}[5m]))
		`,
		`sum by (cluster) (count_over_time({job="mysql"}[5m])) / min(count_over_time({job="mysql"}[5m])) `,
		`sum by (job) (
			count_over_time({namespace="tns"} |= "level=error"[5m])
		/
			count_over_time({namespace="tns"}[5m])
		)`,
		`stdvar_over_time({app="foo"} |= "bar" | json | latency >= 250ms or ( status_code < 500 and status_code > 200)
		| line_format "blip{{ .foo }}blop {{.status_code}}" | label_format foo=bar,status_code="buzz{{.bar}}" | unwrap foo [5m])`,
		`stdvar_over_time({app="foo"} |= "bar" | json | latency >= 250ms or ( status_code < 500 and status_code > 200)
		| line_format "blip{{ .foo }}blop {{.status_code}}" | label_format foo=bar,status_code="buzz{{.bar}}" | unwrap foo [5m] offset 10m)`,
		`sum_over_time({namespace="tns"} |= "level=error" | json |foo>=5,bar<25ms|unwrap latency [5m])`,
		`sum by (job) (
			sum_over_time({namespace="tns"} |= "level=error" | json | foo=5 and bar<25ms | unwrap latency[5m])
		/
			count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m])
		)`,
		`sum by (job) (
			sum_over_time({namespace="tns"} |= "level=error" | json | foo=5 and bar<25ms | unwrap bytes(latency)[5m])
		/
			count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m])
		)`,
		`sum by (job) (
			sum_over_time(
				{namespace="tns"} |= "level=error" | json | avg=5 and bar<25ms | unwrap duration(latency) [5m]
			)
		/
			count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m])
		)`,
		`sum_over_time({namespace="tns"} |= "level=error" | json |foo>=5,bar<25ms | unwrap latency | __error__!~".*" | foo >5[5m])`,
		`last_over_time({namespace="tns"} |= "level=error" | json |foo>=5,bar<25ms | unwrap latency | __error__!~".*" | foo >5[5m])`,
		`first_over_time({namespace="tns"} |= "level=error" | json |foo>=5,bar<25ms | unwrap latency | __error__!~".*" | foo >5[5m])`,
		`absent_over_time({namespace="tns"} |= "level=error" | json |foo>=5,bar<25ms | unwrap latency | __error__!~".*" | foo >5[5m])`,
		`sum by (job) (
			sum_over_time(
				{namespace="tns"} |= "level=error" | json | avg=5 and bar<25ms | unwrap duration(latency)  | __error__!~".*" [5m]
			)
		/
			count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m])
		)`,
		`label_replace(
			sum by (job) (
				sum_over_time(
					{namespace="tns"} |= "level=error" | json | avg=5 and bar<25ms | unwrap duration(latency)  | __error__!~".*" [5m]
				)
			/
				count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m])
			),
			"foo",
			"$1",
			"service",
			"(.*):.*"
		)
		`,
		`10 / (5/2)`,
		`10 / (count_over_time({job="postgres"}[5m])/2)`,
		`{app="foo"} | json response_status="response.status.code", first_param="request.params[0]"`,
		`label_replace(
			sum by (job) (
				sum_over_time(
					{namespace="tns"} |= "level=error" | json | avg=5 and bar<25ms | unwrap duration(latency)  | __error__!~".*" [5m] offset 1h
				)
			/
				count_over_time({namespace="tns"} | logfmt | label_format foo=bar[5m] offset 1h)
			),
			"foo",
			"$1",
			"service",
			"(.*):.*"
		)
		`,
	} {
		t.Run(tc, func(t *testing.T) {
			expr, err := ParseExpr(tc)
			require.Nil(t, err)

			expr2, err := ParseExpr(expr.String())
			require.Nil(t, err)
			require.Equal(t, expr, expr2)
		})
	}
}

func Test_NilFilterDoesntPanic(t *testing.T) {
	t.Parallel()
	for _, tc := range []string{
		`{namespace="dev", container_name="cart"} |= "" |= "bloop"`,
		`{namespace="dev", container_name="cart"} |= "bleep" |= ""`,
		`{namespace="dev", container_name="cart"} |= "bleep" |= "" |= "bloop"`,
		`{namespace="dev", container_name="cart"} |= "bleep" |= "" |= "bloop"`,
		`{namespace="dev", container_name="cart"} |= "bleep" |= "bloop" |= ""`,
	} {
		t.Run(tc, func(t *testing.T) {
			expr, err := ParseLogSelector(tc, true)
			require.Nil(t, err)

			p, err := expr.Pipeline()
			require.Nil(t, err)
			_, _, ok := p.ForStream(labelBar).Process([]byte("bleepbloop"))

			require.True(t, ok)
		})
	}
}

type linecheck struct {
	l string
	e bool
}

func Test_FilterMatcher(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		q string

		expectedMatchers []*labels.Matcher
		// test line against the resulting filter, if empty filter should also be nil
		lines []linecheck
	}{
		{
			`{app="foo",cluster=~".+bar"}`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
				mustNewMatcher(labels.MatchRegexp, "cluster", ".+bar"),
			},
			nil,
		},
		{
			`{app!="foo",cluster=~".+bar",bar!~".?boo"}`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchNotEqual, "app", "foo"),
				mustNewMatcher(labels.MatchRegexp, "cluster", ".+bar"),
				mustNewMatcher(labels.MatchNotRegexp, "bar", ".?boo"),
			},
			nil,
		},
		{
			`{app="foo"} |= "foo"`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"foobar", true}, {"bar", false}},
		},
		{
			`{app="foo"} |= "foo" != "bar"`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"foobuzz", true}, {"bar", false}},
		},
		{
			`{app="foo"} |= "foo" !~ "f.*b"`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"foo", true}, {"bar", false}, {"foobar", false}},
		},
		{
			`{app="foo"} |= "foo" |~ "f.*b"`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"foo", false}, {"bar", false}, {"foobar", true}},
		},
		{
			`{app="foo"} |~ "foo"`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"foo", true}, {"bar", false}, {"foobar", true}},
		},
		{
			`{app="foo"} | logfmt | duration > 1s and total_bytes < 1GB`,
			[]*labels.Matcher{
				mustNewMatcher(labels.MatchEqual, "app", "foo"),
			},
			[]linecheck{{"duration=5m total_bytes=5kB", true}, {"duration=1s total_bytes=256B", false}, {"duration=0s", false}},
		},
	} {
		tt := tt
		t.Run(tt.q, func(t *testing.T) {
			t.Parallel()
			expr, err := ParseLogSelector(tt.q, true)
			require.Nil(t, err)
			require.Equal(t, tt.expectedMatchers, expr.Matchers())
			p, err := expr.Pipeline()
			require.Nil(t, err)
			if tt.lines == nil {
				require.Equal(t, p, log.NewNoopPipeline())
			} else {
				sp := p.ForStream(labelBar)
				for _, lc := range tt.lines {
					_, _, ok := sp.Process([]byte(lc.l))
					require.Equalf(t, lc.e, ok, "query for line '%s' was %v and not %v", lc.l, ok, lc.e)
				}
			}
		})
	}
}

func TestStringer(t *testing.T) {
	for _, tc := range []struct {
		in  string
		out string
	}{
		{
			in:  `1 > 1 > 1`,
			out: `0`,
		},
		{
			in:  `1.6`,
			out: `1.6`,
		},
		{
			in:  `1 > 1 > bool 1`,
			out: `0`,
		},
		{
			in:  `1 > bool 1 > count_over_time({foo="bar"}[1m])`,
			out: `(0 > count_over_time({foo="bar"}[1m]))`,
		},
		{
			in:  `1 > bool 1 > bool count_over_time({foo="bar"}[1m])`,
			out: `(0 > bool count_over_time({foo="bar"}[1m]))`,
		},
		{
			in:  `0 > count_over_time({foo="bar"}[1m])`,
			out: `(0 > count_over_time({foo="bar"}[1m]))`,
		},
	} {
		t.Run(tc.in, func(t *testing.T) {
			expr, err := ParseExpr(tc.in)
			require.Nil(t, err)
			require.Equal(t, tc.out, expr.String())
		})
	}
}

func BenchmarkContainsFilter(b *testing.B) {
	lines := [][]byte{
		[]byte("hello world foo bar"),
		[]byte("bar hello world for"),
		[]byte("hello world foobar and the bar and more bar until the end"),
		[]byte("hello world foobar and the bar and more bar and more than one hundred characters for sure until the end"),
		[]byte("hello world foobar and the bar and more bar and more than one hundred characters for sure until the end and yes bar"),
	}

	benchmarks := []struct {
		name string
		expr string
	}{
		{
			"AllMatches",
			`{app="foo"} |= "foo" |= "hello" |= "world" |= "bar"`,
		},
		{
			"OneMatches",
			`{app="foo"} |= "foo" |= "not" |= "in" |= "there"`,
		},
		{
			"MixedFiltersTrue",
			`{app="foo"} |= "foo" != "not" |~ "hello.*bar" != "there" |= "world"`,
		},
		{
			"MixedFiltersFalse",
			`{app="foo"} |= "baz" != "not" |~ "hello.*bar" != "there" |= "world"`,
		},
		{
			"GreedyRegex",
			`{app="foo"} |~ "hello.*bar.*"`,
		},
		{
			"NonGreedyRegex",
			`{app="foo"} |~ "hello.*?bar.*?"`,
		},
		{
			"ReorderedRegex",
			`{app="foo"} |~ "hello.*?bar.*?" |= "not"`,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			expr, err := ParseLogSelector(bm.expr, false)
			if err != nil {
				b.Fatal(err)
			}

			p, err := expr.Pipeline()
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			sp := p.ForStream(labelBar)
			for i := 0; i < b.N; i++ {
				for _, line := range lines {
					sp.Process(line)
				}
			}
		})
	}
}

func Test_parserExpr_Parser(t *testing.T) {
	tests := []struct {
		name    string
		op      string
		param   string
		want    log.Stage
		wantErr bool
	}{
		{"json", OpParserTypeJSON, "", log.NewJSONParser(), false},
		{"unpack", OpParserTypeUnpack, "", log.NewUnpackParser(), false},
		{"logfmt", OpParserTypeLogfmt, "", log.NewLogfmtParser(), false},
		// NewSyslogParser() returns a struct pointer with pointer fields
		// Two instances cannot be compared on equality, even reflect.DeepEqual() returns false
		// {"syslog", OpParserTypeSyslog, "", log.NewSyslogParser(), false},
		{"pattern", OpParserTypePattern, "<foo> bar <buzz>", mustNewPatternParser("<foo> bar <buzz>"), false},
		{"pattern err", OpParserTypePattern, "bar", nil, true},
		{"regexp", OpParserTypeRegexp, "(?P<foo>foo)", mustNewRegexParser("(?P<foo>foo)"), false},
		{"regexp err ", OpParserTypeRegexp, "foo", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &LabelParserExpr{
				Op:    tt.op,
				Param: tt.param,
			}
			got, err := e.Stage()
			if (err != nil) != tt.wantErr {
				t.Errorf("parserExpr.Parser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				require.Nil(t, got)
			} else {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func mustNewRegexParser(re string) log.Stage {
	r, err := log.NewRegexpParser(re)
	if err != nil {
		panic(err)
	}
	return r
}

func mustNewPatternParser(p string) log.Stage {
	r, err := log.NewPatternParser(p)
	if err != nil {
		panic(err)
	}
	return r
}

func Test_canInjectVectorGrouping(t *testing.T) {
	tests := []struct {
		vecOp   string
		rangeOp string
		want    bool
	}{
		{OpTypeSum, OpRangeTypeBytes, true},
		{OpTypeSum, OpRangeTypeBytesRate, true},
		{OpTypeSum, OpRangeTypeSum, true},
		{OpTypeSum, OpRangeTypeRate, true},
		{OpTypeSum, OpRangeTypeCount, true},

		{OpTypeSum, OpRangeTypeAvg, false},
		{OpTypeSum, OpRangeTypeMax, false},
		{OpTypeSum, OpRangeTypeQuantile, false},
		{OpTypeSum, OpRangeTypeStddev, false},
		{OpTypeSum, OpRangeTypeStdvar, false},
		{OpTypeSum, OpRangeTypeMin, false},
		{OpTypeSum, OpRangeTypeMax, false},

		{OpTypeAvg, OpRangeTypeBytes, false},
		{OpTypeCount, OpRangeTypeBytesRate, false},
		{OpTypeBottomK, OpRangeTypeSum, false},
		{OpTypeMax, OpRangeTypeRate, false},
		{OpTypeMin, OpRangeTypeCount, false},
		{OpTypeTopK, OpRangeTypeCount, false},
	}
	for _, tt := range tests {
		t.Run(tt.vecOp+"_"+tt.rangeOp, func(t *testing.T) {
			if got := canInjectVectorGrouping(tt.vecOp, tt.rangeOp); got != tt.want {
				t.Errorf("canInjectVectorGrouping() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_MergeBinOpVectors_Filter(t *testing.T) {
	res := MergeBinOp(
		OpTypeGT,
		&promql.Sample{
			Point: promql.Point{V: 2},
		},
		&promql.Sample{
			Point: promql.Point{V: 0},
		},
		true,
		true,
	)

	// ensure we return the left hand side's value (2) instead of the
	// comparison operator's result (1: the truthy answer)
	require.Equal(t, &promql.Sample{
		Point: promql.Point{V: 2},
	}, res)
}
