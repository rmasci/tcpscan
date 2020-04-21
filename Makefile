compilerFlag=-gcflags=-trimpath=$(shell pwd) -asmflags=-trimpath=$(shell pwd)
goFilesU=tcpscan.go digicert.go format.go setFilesLinux.go tcpCheck.go 
goFilesW=tcpscan.go digicert.go format.go setFilesWindows.go tcpCheckw.go 
all: mac pi bsd32 bsd64 linux64 linux32 netbsd32 netbsd64 openbsd32 openbsd64 win32 win64 solaris;

linux32: tcpscan.go digicert.go format.go setFilesLinux.go
	
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/linux32/tcpscan $(goFilesU)
	cksum binaries/linux32/tcpscan > binaries/linux32/tcpscan.cksum
linux64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/linux64/tcpscan $(goFilesU)
	cksum binaries/linux64/tcpscan > binaries/linux64/tcpscan.cksum
mac: $(goFilesU)
	GOOS=darwin GOARCH=amd64  go build $(compilerFlag) -o binaries/mac/tcpscan $(goFilesU)
	cksum binaries/mac/tcpscan > binaries/mac/tcpscan.cksum

win64: $(goFilesW)
	GOOS=windows GOARCH=amd64  go build $(compilerFlag)  -o binaries/win64/tcpscan.exe $(goFilesW)
	cksum binaries/win64/tcpscan.exe > binaries/win64/tcpscan.exe.cksum

win32: $(goFilesW)
	GOOS=windows GOARCH=386  go build $(compilerFlag)  -o binaries/win32/tcpscan.exe $(goFilesW)
	cksum binaries/win32/tcpscan.exe > binaries/win32/tcpscan.exe.cksum
	
pi: $(goFilesU)
	GOOS=linux GOARCH=arm GOARM=6 go build $(compilerFlag)  -o binaries/pi/tcpscan $(goFilesU)
	cksum binaries/pi/tcpscan > binaries/pi/tcpscan.cksum

bsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/bsd32/tcpscan $(goFilesU)
	cksum binaries/bsd32/tcpscan > binaries/bsd32/tcpscan.cksum
	
bsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/bsd64/tcpscan $(goFilesU)
	cksum binaries/bsd64/tcpscan > binaries/bsd64/tcpscan.cksum

openbsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/openbsd32/tcpscan $(goFilesU)
	cksum binaries/openbsd32/tcpscan > binaries/openbsd32/tcpscan.cksum
	
openbsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/openbsd64/tcpscan $(goFilesU)
	cksum binaries/openbsd64/tcpscan > binaries/openbsd64/tcpscan.cksum

netbsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/netbsd32/tcpscan $(goFilesU)
	cksum binaries/netbsd32/tcpscan > binaries/netbsd32/tcpscan.cksum
	
netbsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/netbsd64/tcpscan $(goFilesU)
	cksum binaries/netbsd64/tcpscan > binaries/netbsd64/tcpscan.cksum

solaris: $(goFilesU)
	GOOS=solaris GOARCH=amd64  go build $(compilerFlag)  -o binaries/solaris/tcpscan $(goFilesU)
	cksum binaries/solaris/tcpscan > binaries/solaris/tcpscan.cksum