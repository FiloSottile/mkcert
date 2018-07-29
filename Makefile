IMPORT_PATH := github.com/FiloSottile/mkcert

.PHONY: mkcert
mkcert: .GOPATH/.ok
	GOPATH="$(PWD)/.GOPATH" go install -v $(IMPORT_PATH)

.PHONY: clean
clean:
	rm -rf bin .GOPATH

unexport GOBIN

.GOPATH/.ok:
	mkdir -p ".GOPATH/src/$(IMPORT_PATH)"
	rmdir ".GOPATH/src/$(IMPORT_PATH)"
	ln -s ../../../.. ".GOPATH/src/$(IMPORT_PATH)"
	mkdir -p bin
	ln -s ../bin .GOPATH/bin
	touch $@
