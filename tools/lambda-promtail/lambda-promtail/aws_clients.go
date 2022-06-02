package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	s3Clients = make(map[string]*s3.Client)
	lbClients = make(map[string]*elasticloadbalancingv2.Client)
)

// getS3Client returns an S3 client for a given region.
func getS3Client(ctx context.Context, awsRegion string) (*s3.Client, error) {
	if c, ok := s3Clients[awsRegion]; ok {
		return c, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return nil, err
	}
	c := s3.NewFromConfig(cfg)
	s3Clients[awsRegion] = c
	return c, nil
}

// getS3Client returns an Elastic Load Balancing client for a given region.
func getLBClient(ctx context.Context, awsRegion string) (*elasticloadbalancingv2.Client, error) {
	if c, ok := lbClients[awsRegion]; ok {
		return c, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return nil, err
	}
	c := elasticloadbalancingv2.NewFromConfig(cfg)
	lbClients[awsRegion] = c
	return c, nil
}
