package main

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/logzio/logzio-go"
	log "github.com/sirupsen/logrus"
	"os"
)

const (
	maxBulkSizeBytes = 10 * 1024 * 1024 // 10 MB
)

var (
	logger   = log.New()
	logLevel = GetLoggerLevel()
)

func HandleRequest(ctx context.Context, securityEvent AwsSecurityHubEvent) error {
	logger.Debug("Starting to handle events")
	if logLevel == log.DebugLevel {
		logOriginalAwsEvent(securityEvent)
	}

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

	logger.Debugf("Current event: %s", string(eventBytes))
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
	var sender *logzio.LogzioSender
	token, err := GetLogzioSecurityToken()
	if err != nil {
		return nil, err
	}
	listener, err := GetLogzioListener()
	if err != nil {
		return nil, err
	}
	if logLevel == log.DebugLevel {
		sender, err = logzio.New(
			token,
			logzio.SetUrl(listener),
			logzio.SetInMemoryQueue(true),
			logzio.SetinMemoryCapacity(maxBulkSizeBytes),
			logzio.SetDebug(os.Stdout),
		)
	} else {
		sender, err = logzio.New(
			token,
			logzio.SetUrl(listener),
			logzio.SetInMemoryQueue(true),
			logzio.SetinMemoryCapacity(maxBulkSizeBytes),
		)
	}

	if err != nil {
		return nil, err
	}

	return sender, nil
}

func logOriginalAwsEvent(awsEvent AwsSecurityHubEvent) {
	awsEventBytes, err := json.Marshal(awsEvent)
	if err != nil {
		log.Warn("Could not marshal AwsSecurityHubEvent")
	}
	logger.Debugf("Event from AWS: %s", string(awsEventBytes))
}
