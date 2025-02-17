/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package awsoidc

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gravitational/trace"
)

// AWSClientRequest contains the required fields to set up an AWS service client.
type AWSClientRequest struct {
	// IntegrationName is the integration name that is going to issue an API Call.
	IntegrationName string

	// Token is the token used to issue the API Call.
	Token string

	// RoleARN is the IAM Role ARN to assume.
	RoleARN string

	// Region where the API call should be made.
	Region string

	// httpClient used in tests.
	httpClient aws.HTTPClient
}

// CheckAndSetDefaults checks if the required fields are present.
func (req *AWSClientRequest) CheckAndSetDefaults() error {
	if req.IntegrationName == "" {
		return trace.BadParameter("integration name is required")
	}

	if req.Token == "" {
		return trace.BadParameter("token is required")
	}

	if req.RoleARN == "" {
		return trace.BadParameter("role arn is required")
	}

	if req.Region == "" {
		return trace.BadParameter("region is required")
	}

	return nil
}

// newAWSConfig creates a new [aws.Config] using the [AWSClientRequest] fields.
func newAWSConfig(ctx context.Context, req *AWSClientRequest) (*aws.Config, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(req.Region))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.httpClient != nil {
		cfg.HTTPClient = req.httpClient
	}

	cfg.Credentials = stscreds.NewWebIdentityRoleProvider(
		sts.NewFromConfig(cfg),
		req.RoleARN,
		IdentityToken(req.Token),
	)

	return &cfg, nil
}

func newEKSClient(ctx context.Context, req *AWSClientRequest) (*eks.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return eks.NewFromConfig(*cfg), nil
}

// newRDSClient creates an [rds.Client] using the provided Token, RoleARN and Region.
func newRDSClient(ctx context.Context, req *AWSClientRequest) (*rds.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return rds.NewFromConfig(*cfg), nil
}

// newECSClient creates an [ecs.Client] using the provided Token, RoleARN and Region.
func newECSClient(ctx context.Context, req *AWSClientRequest) (*ecs.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ecs.NewFromConfig(*cfg), nil
}

// newSTSClient creates an [sts.Client] using the provided Token, RoleARN and Region.
func newSTSClient(ctx context.Context, req *AWSClientRequest) (*sts.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return sts.NewFromConfig(*cfg), nil
}

// newEC2Client creates an [ec2.Client] using the provided Token, RoleARN and Region.
func newEC2Client(ctx context.Context, req *AWSClientRequest) (*ec2.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ec2.NewFromConfig(*cfg), nil
}

// newEC2InstanceConnectClient creates an [ec2instanceconnect.Client] using the provided Token, RoleARN and Region.
func newEC2InstanceConnectClient(ctx context.Context, req *AWSClientRequest) (*ec2instanceconnect.Client, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return ec2instanceconnect.NewFromConfig(*cfg), nil
}

// newAWSCredentialsProvider creates an [aws.CredentialsProvider] using the provided Token, RoleARN and Region.
func newAWSCredentialsProvider(ctx context.Context, req *AWSClientRequest) (aws.CredentialsProvider, error) {
	cfg, err := newAWSConfig(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return cfg.Credentials, nil
}

// IdentityToken is an implementation of [stscreds.IdentityTokenRetriever] for returning a static token.
type IdentityToken string

// GetIdentityToken returns the token configured.
func (j IdentityToken) GetIdentityToken() ([]byte, error) {
	return []byte(j), nil
}
