// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"path/filepath"
)

func (m *mkcert) installPlatform() {
	log.Fatalf("-install is not yet supported on Linux 😣\nYou can manually install the root certificate at %q in the meantime.", filepath.Join(m.CAROOT, rootName))
}

func (m *mkcert) uninstallPlatform() {}
