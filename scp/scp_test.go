package scp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//TestDirectorCheckTrue tests directoryCheck returns true for
//existing directory
func TestDirectoryCheckTrue(t *testing.T) {
	directory := "../scp/"
	expected := true

	actual, _ := directoryCheck(directory)

	assert.True(t, expected, actual)
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
	expected := 3

	actual, _ := getFileUsage(directory)

	assert.Equal(t, expected, len(actual))
}
