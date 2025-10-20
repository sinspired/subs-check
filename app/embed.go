package app

import "embed"

//go:embed templates/*
var configFS embed.FS

//go:embed static
var staticFS embed.FS