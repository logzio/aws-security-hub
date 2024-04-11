GOOS=linux GOARCH=amd64 go build -o bootstrap *.go
chmod +x bootstrap
zip -r function.zip bootstrap
rm bootstrap