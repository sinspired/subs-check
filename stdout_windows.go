//go:build windows

package main

import (
	"io"

	"github.com/mattn/go-colorable"
)

func getStdout() io.Writer {
	return colorable.NewColorableStdout()
}
