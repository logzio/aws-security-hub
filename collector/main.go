package main

import (
	"aws-security-hub/collector/utils"
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/logzio/logzio-go"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	detailTypeInsightResults = "Security Hub Insight Results"
	detailTypeImported = "Security Hub Findings - Imported"
	detailTypeCustom = "Security Hub Findings - Custom Action"
	detailTypeCloudTrail = "AWS API Call via CloudTrail"
	maxBulkSizeBytes = 10 * 1024 * 1024  // 10 MB
	logzioType = "aws-security-hub"
)

type AwsSecurityHubEvent struct {
	Version string `json:"version,omitempty"`
	Id string `json:"id,omitempty"`
	DetailType string `json:"detail-type,omitempty"`
	Source string `json:"source,omitempty"`
	Account string `json:"account,omitempty"`
	Time string `json:"time,omitempty"`
	Region string `json:"region,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Detail interface{} `json:"detail,omitempty"`
}

type LogzioEvent struct {
	Timestamp string `json:"@timestamp"`
	Type string `json:"type"`
	Event AwsSecurityHubEvent `json:"event"`
}

var logger = log.New()

func HandleRequest(ctx context.Context, securityEvent AwsSecurityHubEvent) error {
	var sb strings.Builder
	logger.Debug("Starting to handle events")
	logzioSender, err := getLogzioSender()
	if err != nil {
		return err
	}

	logzioEvent := convertAwsEventToLogzioEvent(securityEvent)
	eventBytes, err := json.Marshal(logzioEvent)
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
	logger.SetLevel(utils.GetLoggerLevel())
	logger.Debug("Starting aws security hub collector")
	lambda.Start(HandleRequest)
}

func getLogzioSender() (*logzio.LogzioSender, error) {
	token, err := utils.GetLogzioSecurityToken()
	if err != nil {
		return nil, err
	}
	listener, err := utils.GetLogzioListener()
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

func convertAwsEventToLogzioEvent(awsEvent AwsSecurityHubEvent) LogzioEvent {
	eventToLogzio := awsEvent
	eventToLogzio.Time = ""
	if len(eventToLogzio.Resources) == 0 {
		eventToLogzio.Resources = nil
	}

	logzioEvent := LogzioEvent{
		Timestamp: awsEvent.Time,
		Type:      logzioType,
		Event:     eventToLogzio,
	}

	return logzioEvent
}