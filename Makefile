compilerFlag=-gcflags=-trimpath=$(shell pwd) -asmflags=-trimpath=$(shell pwd)
goFilesU=tcpscan.go digicert.go format.go setFilesLinux.go tcpCheck.go subnetcalc.go
goFilesW=tcpscan.go digicert.go format.go setFilesWindows.go tcpCheckw.go subnetcalc.go
all: mac pi bsd32 bsd64 linux64 linux32 netbsd32 netbsd64 openbsd32 openbsd64 win32 win64 solaris;

linux32: $(goFilesU)
	
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/tcpscan-l32 $(goFilesU)

linux64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-l64 $(goFilesU)

mac: $(goFilesU)
	GOOS=darwin GOARCH=amd64  go build $(compilerFlag) -o binaries/tcpscan-mac $(goFilesU)

win64: $(goFilesW)
	GOOS=windows GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-w64.exe $(goFilesW)

win32: $(goFilesW)
	GOOS=windows GOARCH=386  go build $(compilerFlag)  -o binaries/tcpscan-w32.exe $(goFilesW)
	
pi: $(goFilesU)
	GOOS=linux GOARCH=arm GOARM=6 go build $(compilerFlag)  -o binaries/tcpscan-pi $(goFilesU)

bsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/tcpscan-bsd32 $(goFilesU)
	
bsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-bsd64 $(goFilesU)

openbsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/tcpscan-ob32 $(goFilesU)
	
openbsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-ob64 $(goFilesU)

netbsd32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o binaries/tcpscan-b32 $(goFilesU)
	
netbsd64: $(goFilesU)
	GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-b64 $(goFilesU)

solaris: $(goFilesU)
	GOOS=solaris GOARCH=amd64  go build $(compilerFlag)  -o binaries/tcpscan-sol $(goFilesU)
