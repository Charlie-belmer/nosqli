env GOOS=linux GOARCH=amd64 go build -o distribution/nosqli_linux_x64_v0.5.0 .
env GOOS=linux GOARCH=386 go build -o distribution/nosqli_linux_x86_v0.5.0 .
env GOOS=windows GOARCH=amd64 go build -o distribution/nosqli_windows_v0.5.0.exe .
env GOOS=darwin GOARCH=amd64 go build  -o distribution/nosqli_macos_v0.5.0 .
