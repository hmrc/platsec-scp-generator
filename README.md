# platsec-scp-generator

The SCP generator works in conjunction with the [PlatSec AWS
Scanner](https://github.com/hmrc/platsec-aws-scanner). The output of the Scanner
Service Usage query which is in JSON format is used as an input to the SCP
generator.

The SCP generator will create a Service Control Policy (SCP) JSON file that
either can be implemented as is or used as an example policy for discussion with
teams on the MDTP Platform.

There are two types of policy it can create

- Allow - SCP with with `Allow` effect that lists all actions which count in
   given report file was equal or higher than given threshold.

- Deny - SCP with with `Deny` effect that lists all actions which count in
   given report file was lower than given threshold.

## Example

Given following service usage report:

```json
[
  {
    "account": {
      "identifier": "01234567890",
      "name": "my-aws-account"
    },
    "description": "AWS s3 service usage scan",
    "partition": {
      "year": "2021",
      "month": "03"
    },
    "results": {
      "event_source": "s3.amazonaws.com",
      "service_usage": [
        {
          "event_name": "ListBuckets",
          "count": 10
        },
        {
          "event_name": "GetObject",
          "count": 231
        },
        {
          "event_name": "GetBucketNotification",
          "count": 1
        }
      ]
    }
  }
]
```

We want to generate `Allow` type of SCP with threshold `10`:

```bash
go run main.go -file testdata/s3_usage.input.json -threshold 10 -type "Allow"
```

The output will be a policy with two actions that had the `count` field equal or
higher than `10`:

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "s3:ListBuckets",
      "s3:GetObject"
    ],
    "Resource": "*"
  }
}
```

## License

This code is open source software licensed under the [Apache 2.0
License]("http://www.apache.org/licenses/LICENSE-2.0.html").
