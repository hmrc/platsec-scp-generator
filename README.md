
# platsec-scp-generator

The SCP generator works in conjunction with the Athena Scanner solution implemented by Platsec.
The output of the Athena Scanner Service Usage query which is in JSON format is used as an input
to the SCP generator.

The SCP generator will create a SCP json file that either can be implemented as is or used
as an example policy for discussion with teams on the MDTP Platform.

The required parameters can be seen by issuing awsscp -h

-fileloc This is the path and file name of the Service Usage Query file.
-threshold Is an integer which is used to determine which permissions are included in the SCP.
-type Allow or Deny determines whether to generate an allow SCP or a deny SCP.

./awsscp -fileloc "./s3_usage.json" -threshold 10 -type "Allow"

The above is a typical example of executing the awsscp program from the command line

### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
