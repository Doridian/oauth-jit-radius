package main

import (
	"embed"
	"io/fs"
)

//go:embed web/*
var webFS embed.FS

var webHttpFs fs.FS = func() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	return sub
}()
