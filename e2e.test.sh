#!/bin/bash

set -o errexit  # Exit immediately if any command or pipeline of commands fails
set -o nounset  # Treat unset variables and parameters as an error
set -o pipefail # Exit when command before pipe fails
# set -o xtrace   # Debug mode expand everything and print it before execution

cd "$(dirname "$0")" # Always run from script location

test_run() {
    set -o errexit
    local file="$1"
    local threshold="$2"
    local type="$3"
    local golden_file="$4"
    echo -ne "test for file ${file} with threshold ${threshold} and policy type ${type}: "
    got=$(go run main.go -file "${file}" -threshold "${threshold}" -type "${type}")
    want=$(cat "${golden_file}")
    if [[ "${got}" != "${want}" ]]; then
        echo -e " Fail"
        echo -e "\n'-' program output; '+' content of golden file ${golden_file}"
        diff -u <(echo "${got}") <(echo "${want}") # will error with difference
    fi
    echo -e "OK"
}

file="testdata/s3_usage.input.json"
threshold=10
type="Deny"
golden_file="testdata/s3_usage_deny_10.golden.json"
test_run "${file}" "${threshold}" "${type}" "${golden_file}"

file="testdata/s3_usage.input.json"
threshold=10
type="Allow"
golden_file="testdata/s3_usage_allow_10.golden.json"
test_run "${file}" "${threshold}" "${type}" "${golden_file}"
