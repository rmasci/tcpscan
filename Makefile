compilerFlag=-gcflags=-trimpath=$(shell pwd) -asmflags=-trimpath=$(shell pwd)
files=main.go
all: mac linux 

windows:$(files)
	GOOS=windows GOARCH=386  go build $(compilerFlag)  -o binaries/win32/tcpscan $(files)
	cksum binaries/win32/tcpscan > binaries/win32/tcpscan.cksum
	GOOS=windows GOARCH=amd64  go build $(compilerFlag)  -o binaries/win64/tcpscan $(files)
	cksum binaries/win64/tcpscan > binaries/win64/tcpscan.cksum

linux: $(files)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/linux32/tcpscan $(files)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/linux64/tcpscan $(files)
	cksum binaries/linux32/tcpscan > binaries/linux32/tcpscan.cksum
	cksum binaries/linux64/tcpscan > binaries/linux64/tcpscan.cksum

mac: $(files)
	GOOS=darwin GOARCH=amd64  go build $(compilerFlag) -o binaries/mac/tcpscan $(files)
	cksum binaries/mac/tcpscan > binaries/mac/tcpscan.cksum