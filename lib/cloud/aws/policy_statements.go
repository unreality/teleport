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

package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/gravitational/trace"
)

var (
	allResources = []string{"*"}
)

// StatementForIAMEditRolePolicy returns a IAM Policy Statement which allows editting Role Policy
// of the resources.
func StatementForIAMEditRolePolicy(resources ...string) *Statement {
	return &Statement{
		Effect:    EffectAllow,
		Actions:   []string{"iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"},
		Resources: resources,
	}
}

// StatementForIAMEditUserPolicy returns a IAM Policy Statement which allows editting User Policy
// of the resources.
func StatementForIAMEditUserPolicy(resources ...string) *Statement {
	return &Statement{
		Effect:    EffectAllow,
		Actions:   []string{"iam:GetUserPolicy", "iam:PutUserPolicy", "iam:DeleteUserPolicy"},
		Resources: resources,
	}
}

// StatementForECSManageService returns the statement that allows managing the ECS Service deployed
// by DeployService (AWS OIDC Integration).
func StatementForECSManageService() *Statement {
	return &Statement{
		Effect: EffectAllow,
		Actions: []string{
			"ecs:DescribeClusters", "ecs:CreateCluster", "ecs:PutClusterCapacityProviders",
			"ecs:DescribeServices", "ecs:CreateService", "ecs:UpdateService", "ecs:ListServices",
			"ecs:RegisterTaskDefinition", "ecs:DescribeTaskDefinition", "ecs:DeregisterTaskDefinition",

			// EC2 DescribeSecurityGroups is required so that the user can list the SG and then pick which ones they want to apply to the ECS Service.
			"ec2:DescribeSecurityGroups",
		},
		Resources: allResources,
	}
}

// StatementForWritingLogs returns the statement that allows the writing logs to CloudWatch.
// This is used by the DeployService (ECS Service) to write teleport logs.
// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html
func StatementForWritingLogs() *Statement {
	return &Statement{
		Effect:    EffectAllow,
		Actions:   []string{"logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"},
		Resources: allResources,
	}
}

// StatementForIAMPassRole returns a statement that allows to iam:PassRole the target role.
// Usage example: when setting up the TaskRole for the ECS Task.
// https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-iam-roles.html#specify-task-iam-roles
func StatementForIAMPassRole(targetRole string) *Statement {
	return &Statement{
		Effect:  EffectAllow,
		Actions: SliceOrString{"iam:PassRole"},
		Resources: SliceOrString{
			targetRole,
		},
	}
}

// StatementForECSTaskRoleTrustRelationships returns the Trust Relationship to allow the ECS Tasks service to.
// It allows the usage of this Role by the ECS Tasks service.
func StatementForECSTaskRoleTrustRelationships() *Statement {
	return &Statement{
		Effect:  EffectAllow,
		Actions: SliceOrString{"sts:AssumeRole"},
		Principals: map[string]SliceOrString{
			"Service": {"ecs-tasks.amazonaws.com"},
		},
	}
}

// StatementForRDSDBConnect returns a statement that allows the `rds-db:connect` for all RDS DBs.
func StatementForRDSDBConnect() *Statement {
	return &Statement{
		Effect:    EffectAllow,
		Actions:   SliceOrString{"rds-db:connect"},
		Resources: allResources,
	}
}

// StatementForEC2InstanceConnectEndpoint returns the statement that allows the flow for accessing
// an EC2 instance using its private IP, using EC2 Instance Connect Endpoint.
func StatementForEC2InstanceConnectEndpoint() *Statement {
	return &Statement{
		Effect: EffectAllow,
		Actions: []string{
			"ec2:DescribeInstances",
			"ec2:DescribeInstanceConnectEndpoints",
			"ec2:DescribeSecurityGroups",

			// Create ICE requires the following actions:
			// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/permissions-for-ec2-instance-connect-endpoint.html
			"ec2:CreateInstanceConnectEndpoint",
			"ec2:CreateTags",
			"ec2:CreateNetworkInterface",
			"iam:CreateServiceLinkedRole",

			"ec2-instance-connect:SendSSHPublicKey",
			"ec2-instance-connect:OpenTunnel",
		},
		Resources: allResources,
	}
}

// StatementForEKSAccess returns the statement that allows enrolling of EKS clusters into Teleport.
func StatementForEKSAccess() *Statement {
	return &Statement{
		Effect: EffectAllow,
		Actions: []string{
			"eks:ListClusters",
			"eks:DescribeCluster",
			"eks:ListAccessEntries",
			"eks:CreateAccessEntry",
			"eks:DeleteAccessEntry",
			"eks:AssociateAccessPolicy",
		},
		Resources: allResources,
	}
}

// StatementForAWSOIDCRoleTrustRelationship returns the Trust Relationship to allow the OpenID Connect Provider
// set up during the AWS OIDC Onboarding to assume this Role.
func StatementForAWSOIDCRoleTrustRelationship(accountID, providerURL string, audiences []string) *Statement {
	federatedARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, providerURL)
	federatedAudience := fmt.Sprintf("%s:aud", providerURL)

	return &Statement{
		Effect:  EffectAllow,
		Actions: SliceOrString{"sts:AssumeRoleWithWebIdentity"},
		Principals: map[string]SliceOrString{
			"Federated": []string{federatedARN},
		},
		Conditions: map[string]map[string]SliceOrString{
			"StringEquals": {
				federatedAudience: audiences,
			},
		},
	}
}

// StatementForListRDSDatabases returns the statement that allows listing RDS DB Clusters and Instances.
func StatementForListRDSDatabases() *Statement {
	return &Statement{
		Effect: EffectAllow,
		Actions: []string{
			"rds:DescribeDBInstances",
			"rds:DescribeDBClusters",
			"ec2:DescribeSecurityGroups",
		},
		Resources: allResources,
	}
}

// ExternalAuditStoragePolicyConfig holds options for the External Audit Storage
// IAM policy.
type ExternalAuditStoragePolicyConfig struct {
	// Partition is the AWS partition to use.
	Partition string
	// Region is the AWS region to use.
	Region string
	// Account is the AWS account ID to use.
	Account string
	// S3ARNs is a list of all S3 resource ARNs used for audit events, session
	// recordings, and Athena query results. For each location, it should include an ARN for the
	// base bucket and another wildcard ARN for all objects within the bucket
	// and an optional path/prefix.
	S3ARNs []string
	// AthenaWorkgroupName is the name of the Athena workgroup used for queries.
	AthenaWorkgroupName string
	// GlueDatabaseName is the name of the AWS Glue database.
	GlueDatabaseName string
	// GlueTabelName is the name of the AWS Glue table.
	GlueTableName string
}

func (c *ExternalAuditStoragePolicyConfig) CheckAndSetDefaults() error {
	if len(c.Partition) == 0 {
		c.Partition = "aws"
	}
	if len(c.Region) == 0 {
		return trace.BadParameter("region is required")
	}
	if len(c.Account) == 0 {
		return trace.BadParameter("account is required")
	}
	if len(c.S3ARNs) < 2 {
		return trace.BadParameter("at least two distinct S3 ARNs are required")
	}
	if len(c.AthenaWorkgroupName) == 0 {
		return trace.BadParameter("athena workgroup name is required")
	}
	if len(c.GlueDatabaseName) == 0 {
		return trace.BadParameter("glue database name is required")
	}
	if len(c.GlueTableName) == 0 {
		return trace.BadParameter("glue table name is required")
	}
	return nil
}

// PolicyDocumentForExternalAuditStorage returns a PolicyDocument with the
// necessary IAM permissions for the External Audit Storage feature.
func PolicyDocumentForExternalAuditStorage(cfg *ExternalAuditStoragePolicyConfig) (*PolicyDocument, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &PolicyDocument{
		Version: PolicyVersion,
		Statements: []*Statement{
			&Statement{
				StatementID: "ReadWriteSessionsAndEvents",
				Effect:      EffectAllow,
				Actions: []string{
					"s3:PutObject",
					"s3:GetObject",
					"s3:GetObjectVersion",
					"s3:ListMultipartUploadParts",
					"s3:AbortMultipartUpload",
					"s3:ListBucket",
					"s3:ListBucketVersions",
					"s3:ListBucketMultipartUploads",
					"s3:GetBucketOwnershipControls",
					"s3:GetBucketPublicAccessBlock",
					"s3:GetBucketObjectLockConfiguration",
					"s3:GetBucketVersioning",
					"s3:GetBucketLocation",
				},
				Resources: cfg.S3ARNs,
			},
			&Statement{
				StatementID: "AllowAthenaQuery",
				Effect:      EffectAllow,
				Actions: []string{
					"athena:StartQueryExecution",
					"athena:GetQueryResults",
					"athena:GetQueryExecution",
				},
				Resources: []string{
					arn.ARN{
						Partition: cfg.Partition,
						Service:   "athena",
						Region:    cfg.Region,
						AccountID: cfg.Account,
						Resource:  "workgroup/" + cfg.AthenaWorkgroupName,
					}.String(),
				},
			},
			&Statement{
				StatementID: "FullAccessOnGlueTable",
				Effect:      EffectAllow,
				Actions: []string{
					"glue:GetTable",
					"glue:GetTableVersion",
					"glue:GetTableVersions",
					"glue:UpdateTable",
				},
				Resources: []string{
					arn.ARN{
						Partition: cfg.Partition,
						Service:   "glue",
						Region:    cfg.Region,
						AccountID: cfg.Account,
						Resource:  "catalog",
					}.String(),
					arn.ARN{
						Partition: cfg.Partition,
						Service:   "glue",
						Region:    cfg.Region,
						AccountID: cfg.Account,
						Resource:  "database/" + cfg.GlueDatabaseName,
					}.String(),
					arn.ARN{
						Partition: cfg.Partition,
						Service:   "glue",
						Region:    cfg.Region,
						AccountID: cfg.Account,
						Resource:  "table/" + cfg.GlueDatabaseName + "/" + cfg.GlueTableName,
					}.String(),
				},
			},
		},
	}, nil
}
