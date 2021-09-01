package main

import "encoding/json"

func ConvertAwsEventToLogzioEvent(awsEvent AwsSecurityHubEvent) (LogzioEvent, error) {
	var logzioEvent LogzioEvent
	logzioEvent.Timestamp = awsEvent.Time
	logzioEvent.Type = LogzioType

	eventToLogzio, err := parseAwsEvent(awsEvent)
	if err != nil {
		return logzioEvent, err
	}
	eventToLogzio.Time = ""
	if len(eventToLogzio.Resources) == 0 {
		eventToLogzio.Resources = nil
	}

	logzioEvent.Event = eventToLogzio
	return logzioEvent, err
}

func parseAwsEvent(awsEvent AwsSecurityHubEvent) (AwsSecurityHubEvent, error) {
	switch awsEvent.DetailType {
	case DetailTypeImported:
		return parseImportedEvent(awsEvent)
	case DetailTypeCustom:
		return parseCustomEvent(awsEvent)
	case DetailTypeInsightResults:
		return awsEvent, nil
	case DetailTypeCloudTrail:
		return awsEvent, nil
	default:
		panic("Unknown type. Exiting.")
	}
}

func parseImportedEvent(awsEvent AwsSecurityHubEvent) (AwsSecurityHubEvent, error) {
	detailsByte, err := json.Marshal(awsEvent.Detail)
	if err != nil {
		return awsEvent, err
	}

	var details DetailFindingsArray
	err = json.Unmarshal(detailsByte, &details)
	if err != nil {
		return awsEvent, err
	}

	awsEvent.Detail = DetailImported{Findings: details.Findings[0]}

	return awsEvent, nil
}

func parseCustomEvent(awsEvent AwsSecurityHubEvent) (AwsSecurityHubEvent, error) {
	detailsByte, err := json.Marshal(awsEvent.Detail)
	if err != nil {
		return awsEvent, err
	}

	var details DetailCustomArray
	err = json.Unmarshal(detailsByte, &details)
	if err != nil {
		return awsEvent, err
	}

	awsEvent.Detail = DetailCustom{
		ActionName:        details.ActionName,
		ActionDescription: details.ActionDescription,
		Findings:          details.Findings[0],
	}

	return awsEvent, nil
}
