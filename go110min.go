// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build !go1.10

package main

// This file is here to give a better hint in the error message
// when this project is built with a too old version of Go.

var _ = ThisProjectRequiresGo1·10OrHigher
