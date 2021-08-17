env GOOS=linux GOARCH=amd64 go build main.go
chmod +x main
zip -r function.zip main