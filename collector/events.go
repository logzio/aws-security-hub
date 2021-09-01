package main

const (
	DetailTypeInsightResults = "Security Hub Insight Results"
	DetailTypeImported       = "Security Hub Findings - Imported"
	DetailTypeCustom         = "Security Hub Findings - Custom Action"
	DetailTypeCloudTrail     = "AWS API Call via CloudTrail"
	LogzioType               = "aws-security-hub"
)

type AwsSecurityHubEvent struct {
	Version    string      `json:"version,omitempty"`
	Id         string      `json:"id,omitempty"`
	DetailType string      `json:"detail-type,omitempty"`
	Source     string      `json:"source,omitempty"`
	Account    string      `json:"account,omitempty"`
	Time       string      `json:"time,omitempty"`
	Region     string      `json:"region,omitempty"`
	Resources  []string    `json:"resources,omitempty"`
	Detail     interface{} `json:"detail,omitempty"`
}

type LogzioEvent struct {
	Timestamp string              `json:"@timestamp"`
	Type      string              `json:"type"`
	Event     AwsSecurityHubEvent `json:"event"`
}

// DetailFindingsArray - Intermediate struct, to parse from original event
type DetailFindingsArray struct {
	Findings []interface{} `json:"findings"`
}

// DetailImported - According to https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
// Imported event contains a single finding
type DetailImported struct {
	Findings interface{} `json:"findings"`
}

type DetailCustomArray struct {
	ActionName        string        `json:"actionName"`
	ActionDescription string        `json:"actionDescription"`
	Findings          []interface{} `json:"findings"`
}

// DetailCustom - According to https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
// For custom actions, each finding is sent to EventBridge as a separate EventBridge event.
type DetailCustom struct {
	ActionName        string      `json:"actionName"`
	ActionDescription string      `json:"actionDescription"`
	Findings          interface{} `json:"findings"`
}