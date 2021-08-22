package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/logzio/logzio-go"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	maxBulkSizeBytes = 10 * 1024 * 1024  // 10 MB
)

var logger = log.New()

func HandleRequest(ctx context.Context, securityEvent AwsSecurityHubEvent) error {
	var sb strings.Builder
	logger.Debug("Starting to handle events")
	logzioSender, err := getLogzioSender()
	if err != nil {
		return err
	}

	logzioEvent, err := ConvertAwsEventToLogzioEvent(securityEvent)
	if err != nil {
		return err
	}

	eventBytes, err := json.Marshal(logzioEvent)
	if err != nil {
		return err
	}

	sb.Write(eventBytes)
	logger.Debugf("Current event: %s", sb.String())
	if err != nil {
		return err
	}
	logger.Debug("About to write to sender")
	logzioSender.Write(eventBytes)
	logzioSender.Drain()
	logger.Debug("DONE")
	return nil
}

func main() {
	logger.SetLevel(GetLoggerLevel())
	logger.Debug("Starting aws security hub collector")
	lambda.Start(HandleRequest)
}

func getLogzioSender() (*logzio.LogzioSender, error) {
	token, err := GetLogzioSecurityToken()
	if err != nil {
		return nil, err
	}
	listener, err := GetLogzioListener()
	if err != nil {
		return nil, err
	}

	sender, err := logzio.New(
		token,
		logzio.SetUrl(listener),
		logzio.SetInMemoryQueue(true),
		logzio.SetinMemoryCapacity(maxBulkSizeBytes),
		logzio.SetDebug(os.Stdout),
	)

	if err != nil {
		return nil, err
	}

	return sender, nil
}

