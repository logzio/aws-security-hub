GOOS=linux GOARCH=amd64 go build -o main *.go
chmod +x main
zip -r function.zip main
rm main