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
