# Go Modules ON:

compilerFlag=-gcflags=-trimpath=$(shell pwd) -asmflags=-trimpath=$(shell pwd)
goFilesU=tcpscan.go digicert.go format.go setFilesLinux.go tcpCheck.go subnetcalc.go
goFilesW=tcpscan.go digicert.go format.go setFilesWindows.go tcpCheckw.go subnetcalc.go
#all: mac pi bsd32 bsd64 linux64 linux32 netbsd32 netbsd64 openbsd32 openbsd64 win32 win64 solaris;
all: mac pi bsd64 linux64 netbsd64 openbsd64 win64 solaris;

linux32: $(goFilesU)
	GOOS=linux GOARCH=386  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-l32 $(goFilesU)

linux64: $(goFilesU)

	GO111MODULE=on GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-l64 $(goFilesU)

mac: $(goFilesU)
	GO111MODULE=on GOOS=darwin GOARCH=amd64  go build $(compilerFlag) -o ../tcpscan-release/tcpscan-mac $(goFilesU)

win64: $(goFilesW)
	GO111MODULE=on GOOS=windows GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-w64.exe $(goFilesW)

win32: $(goFilesW)
	GOOS=windows GOARCH=386  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-w32.exe $(goFilesW)
	
pi: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=arm GOARM=6 go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-pi $(goFilesU)

bsd32: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=386  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-bsd32 $(goFilesU)
	
bsd64: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-bsd64 $(goFilesU)

openbsd32: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=386  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-ob32 $(goFilesU)
	
openbsd64: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-ob64 $(goFilesU)

netbsd32: $(goFilesU)
	GO111MODULE=on OOS=linux GOARCH=386  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-b32 $(goFilesU)
	
netbsd64: $(goFilesU)
	GO111MODULE=on GOOS=linux GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-b64 $(goFilesU)

solaris: $(goFilesU)
	GO111MODULE=on GOOS=solaris GOARCH=amd64  go build $(compilerFlag)  -o ../tcpscan-release/tcpscan-sol $(goFilesU)
