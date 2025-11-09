package assets

import (
	_ "embed"
)

//go:embed sub-store.bundle.js.zst
var EmbeddedSubStoreBackend []byte

//go:embed sub-store.frontend.tar.zst
var EmbeddedSubStoreFrotend []byte

//go:embed ACL4SSR_Online_Full.yaml.zst
var EmbeddedOverrideYaml []byte
