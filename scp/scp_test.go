package scp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//TestDirectorCheckTrue tests directoryCheck returns true for
//existing directory
func TestDirectoryCheckTrue(t *testing.T) {
	directory := "../scp/"
	actual, _ := directoryCheck(directory)

	assert.True(t, true, actual)
}

//TestDirectoryCheckFalse test directoryCheck returns false for
//a non existent directory
func TestDirectoryCheckFalse(t *testing.T) {
	directory := "../scpfalse/"
	expected := false

	actual, _ := directoryCheck(directory)

	assert.False(t, expected, actual)

}

//TestGetUsageFiles checks that getUsageFiles returns
//Files to process
func TestGetUsageFiles(t *testing.T) {
	directory := "../test_data/"
	expected := 1

	actual, _ := GetFileUsage(directory)

	assert.Equal(t, expected, len(actual))
}

//TestDecodeFile decodes the file to a map
func TestDecodeFile(t *testing.T) {
	jsonData := `{
    "results": {
      "role_usage": [
        {
          "event_name": "ListApplications",
          "count": 1
        },
        {
          "event_name": "DescribeChangeSet",
          "count": 1
        }
      ]
    }
}
	`
	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	report, _ := GenerateReport(testData)

	assert.NotNil(t, report)
	assert.Equal(t, 2, len(report.Results.RoleUsage))
}

//TestDecodeFileError returns an error
func TestDecodeFileError(t *testing.T) {

	jsonData := `
  {
    "account": {
      "identifier": "132732819912",
      "name": "platsec-development"
    },
    "description": "AWS RoleSecurityReadOnly usage scan",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "role_usage": [
        {
          "event_source": "application-insights.amazonaws.com",
          "event_name": "ListApplications",
          "count": 1
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeChangeSet",
          "count": 1
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeStackEvents",
          "count": 1
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeStackResources",
          "count": 9
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeStacks",
          "count": 2
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "ListStacks",
          "count": 5
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "DescribeTrails",
          "count": 10
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "GetEventSelectors",
          "count": 1
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "GetInsightSelectors",
          "count": 1
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "GetTrailStatus",
          "count": 10
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "ListTags",
          "count": 1
        },
        {
          "event_source": "cloudtrail.amazonaws.com",
          "event_name": "LookupEvents",
          "count": 31
        },
        {
          "event_source": "codebuild.amazonaws.com",
          "event_name": "BatchGetBuilds",
          "count": 26
        },
        {
          "event_source": "codebuild.amazonaws.com",
          "event_name": "BatchGetProjects",
          "count": 14
        },
        {
          "event_source": "codebuild.amazonaws.com",
          "event_name": "ListBuildsForProject",
          "count": 24
        },
        {
          "event_source": "codebuild.amazonaws.com",
          "event_name": "ListProjects",
          "count": 7
        },
        {
          "event_source": "codecommit.amazonaws.com",
          "event_name": "ListRepositories",
          "count": 3
        },
        {
          "event_source": "codestar-notifications.amazonaws.com",
          "event_name": "ListNotificationRules",
          "count": 1
        },
        {
          "event_source": "compute-optimizer.amazonaws.com",
          "event_name": "GetLambdaFunctionRecommendations",
          "count": 9
        },
        {
          "event_source": "config.amazonaws.com",
          "event_name": "DescribeConfigurationRecorderStatus",
          "count": 8
        },
        {
          "event_source": "config.amazonaws.com",
          "event_name": "DescribeConfigurationRecorders",
          "count": 8
        },
        {
          "event_source": "ec2.amazonaws.com",
          "event_name": "DescribeSecurityGroups",
          "count": 4
        },
        {
          "event_source": "ec2.amazonaws.com",
          "event_name": "DescribeSubnets",
          "count": 4
        },
        {
          "event_source": "ec2.amazonaws.com",
          "event_name": "DescribeVpcs",
          "count": 5
        },
        {
          "event_source": "ecr.amazonaws.com",
          "event_name": "DescribeImages",
          "count": 5
        },
        {
          "event_source": "ecr.amazonaws.com",
          "event_name": "DescribeRepositories",
          "count": 7
        },
        {
          "event_source": "events.amazonaws.com",
          "event_name": "ListRules",
          "count": 3
        },
        {
          "event_source": "events.amazonaws.com",
          "event_name": "ListTargetsByRule",
          "count": 2
        },
        {
          "event_source": "events.amazonaws.com",
          "event_name": "TestEventPattern",
          "count": 1
        },
        {
          "event_source": "kms.amazonaws.com",
          "event_name": "Decrypt",
          "count": 127
        },
        {
          "event_source": "kms.amazonaws.com",
          "event_name": "ListAliases",
          "count": 1
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetAccountSettings20160819",
          "count": 109
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetFunction20150331v2",
          "count": 18
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetFunctionCodeSigningConfig",
          "count": 6
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetFunctionConfiguration20150331v2",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetFunctionEventInvokeConfig",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "GetPolicy20150331v2",
          "count": 21
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListAliases20150331",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListCodeSigningConfigs",
          "count": 1
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListEventSourceMappings20150331",
          "count": 12
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListFunctions20150331",
          "count": 32
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListLayers20181031",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListProvisionedConcurrencyConfigs",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListTags20170331",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "ListVersionsByFunction20150331",
          "count": 9
        },
        {
          "event_source": "lambda.amazonaws.com",
          "event_name": "UpdateFunctionConfiguration20150331v2",
          "count": 1
        },
        {
          "event_source": "logs.amazonaws.com",
          "event_name": "DescribeLogGroups",
          "count": 2
        },
        {
          "event_source": "logs.amazonaws.com",
          "event_name": "DescribeLogStreams",
          "count": 133
        },
        {
          "event_source": "logs.amazonaws.com",
          "event_name": "DescribeMetricFilters",
          "count": 25
        },
        {
          "event_source": "logs.amazonaws.com",
          "event_name": "StartQuery",
          "count": 4
        },
        {
          "event_source": "monitoring.amazonaws.com",
          "event_name": "DescribeAlarms",
          "count": 43
        },
        {
          "event_source": "monitoring.amazonaws.com",
          "event_name": "DescribeInsightRules",
          "count": 2
        },
        {
          "event_source": "monitoring.amazonaws.com",
          "event_name": "GetDashboard",
          "count": 1
        },
        {
          "event_source": "resource-groups.amazonaws.com",
          "event_name": "ListGroups",
          "count": 2
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetAccountPublicAccessBlock",
          "count": 12
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketAcl",
          "count": 84
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketLocation",
          "count": 1
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketPolicy",
          "count": 2
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketPolicyStatus",
          "count": 84
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketPublicAccessBlock",
          "count": 84
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketVersioning",
          "count": 2
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "GetBucketWebsite",
          "count": 2
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "HeadBucket",
          "count": 89
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "ListAccessPoints",
          "count": 85
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "ListBuckets",
          "count": 5
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "ListObjectVersions",
          "count": 2
        },
        {
          "event_source": "s3.amazonaws.com",
          "event_name": "ListObjects",
          "count": 2
        },
        {
          "event_source": "signin.amazonaws.com",
          "event_name": "RenewRole",
          "count": 2
        },
        {
          "event_source": "sns.amazonaws.com",
          "event_name": "ListSubscriptionsByTopic",
          "count": 3
        },
        {
          "event_source": "states.amazonaws.com",
          "event_name": "ListStateMachines",
          "count": 8
        },
        {
          "event_source": "tagging.amazonaws.com",
          "event_name": "GetResources",
          "count": 11
        },
        {
          "event_source": "xray.amazonaws.com",
          "event_name": "GetGroups",
          "count": 6
        },
        {
          "event_source": "xray.amazonaws.com",
          "event_name": "GetInsightSummaries",
          "count": 6
        }
      ]
    }
  }
]
	`
	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	_, err := GenerateReport(testData)
	assert.Error(t, err)
}

//TestGenerateAllowListData tests that
//API actions above a threshold are mapped to
//A new data structure
func TestGenerateAllowListData(t *testing.T) {
    //TODO add table test for different thresholds
	threshold := int64(50)
    testData := getTestReport()
    allowList, _ := GenerateAllowList(threshold, testData)

    assert.NotNil(t, allowList)
    assert.Equal(t, 3, len(allowList))
}

//TestGenerateAllowListGeneratesError tests for
//An error being returned for zero and negative
//Thresholds
func TestGenerateAllowListGeneratesError (t *testing.T) {
	testData := getTestReport()
	cases :=[]struct{
		threshold int64
		report *Report
		expected error
	}{
		{
			threshold: 0,
			report: testData,
			expected: ErrInvalidParameters,
		},
		{
			threshold: -1,
			report: testData,
			expected: ErrInvalidParameters,
		},
	}

	for _,c := range cases {
		_, err := GenerateAllowList(c.threshold,c.report)
		assert.Error(t,err)
	}
}


//JSONFileDataStub
type jsonFileStub struct {
	inputData string
	err       error
}

func (j jsonFileStub) getData() []byte {
	return []byte(j.inputData)
}

//getTestAllowListFilteredData returns a filtered data set
func getTestAllowListFilteredData() map[string]int {
	filteredData := map[string]int{
		"LookupEvents":10,
		"ListTags":1656,
		"GetEventSelectors":12,
		"BatchGetBuilds":223,
		"GetLambdaFunctionRecommendations":2343,
		"DescribeSecurityGroups":543,
		"DescribeVpcs":48,
		"ListStacks":348,
	}

	return filteredData
}
//getTestDenyListFilteredData returns a filtered data set
func getTestDenyListFilteredData() map[string]int {
	filteredData := map[string]int{
		"LookupEvents":1,
		"ListTags":1,
		"GetEventSelectors":2,
		"BatchGetBuilds":2,
		"GetLambdaFunctionRecommendations":3,
		"DescribeSecurityGroups":5,
		"DescribeVpcs":8,
		"ListStacks":3,
	}

	return filteredData
}
//getTestFilteredData returns a filtered data set
func getTestFilteredData() map[string]int {
	filteredData := map[string]int{
		"LookupEvents":10,
		"ListTags":1,
		"GetEventSelectors":12,
		"BatchGetBuilds":2,
		"GetLambdaFunctionRecommendations":2343,
		"DescribeSecurityGroups":543,
		"DescribeVpcs":8,
		"ListStacks":3,
	}

	return filteredData
}

//getTestReport returns a report in the
//form of a serialised json document
func getTestReport() *Report{
	jsonData := `{
    "results": {
      "role_usage": [
        {
          "event_name": "ListApplications",
          "count": 1
        },
        {
          "event_name": "DescribeChangeSet",
          "count": 13
        },
        {
          "event_name": "GetInsightSelectors",
          "count": 3424
        },
        {
          "event_name": "GetTrailStatus",
          "count": 3436
        },
        {
          "event_name": "ListTags",
          "count": 1
        },
        {
          "event_name": "LookupEvents",
          "count": 165
        },
        {
          "event_name": "ListProjects",
          "count": 10
        }
      ]
    }
}
	`

	testStub := jsonFileStub{inputData: jsonData}
	testData := testStub.getData()
	report, _ := GenerateReport(testData)
	return report
}
