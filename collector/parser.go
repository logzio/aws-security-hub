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
		return parseInsightsEvent(awsEvent), nil
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

	awsEvent.Detail = parseImportedResources(DetailImported{Findings: details.Findings[0]})

	return awsEvent, nil
}

func parseImportedResources(detail DetailImported) DetailImported {
	resources := make(map[string]interface{})
	for _, resource := range detail.Findings.(map[string]interface{})["Resources"].([]interface{}) {
		id := resource.(map[string]interface{})["Id"].(string)
		for resourceKey, resourceValue := range resource.(map[string]interface{}) {
			resources[id + "." + resourceKey] = resourceValue
		}
	}

	detail.Findings.(map[string]interface{})["Resources"] = resources
	return detail
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

func parseInsightsEvent(awsEvent AwsSecurityHubEvent) AwsSecurityHubEvent {
	insights := make(map[string]float64)
	for _, insight := range awsEvent.Detail.(map[string]interface{})["insightResults"].([]interface{}) {
		for key, val := range insight.(map[string]interface{}) {
			// this loop will only iterate once
			insights[key] = val.(float64)
		}
	}

	awsEvent.Detail.(map[string]interface{})["insightResults"] = insights
	return awsEvent
}
