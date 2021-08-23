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

//type DetailInsight struct {
//	ActionName        string `json:"actionName"`
//	ActionDescription string `json:"actionDescription"`
//	InsightArn        string `json:"insightArn"`
//	InsightName       string `json:"insightName"`
//	ResultType        string `json:"resultType"`
//	NumberOfResults   string `json:"number of results"`
//	InsightResults    []map[string]int `json:"insightResults"`
//}

//type FindingsObj struct {
//	Action struct {
//		ActionType       string `json:"ActionType"`
//		AwsApiCallAction struct {
//			AffectedResources struct {
//				String string `json:"string"`
//			} `json:"AffectedResources"`
//			Api           string `json:"Api"`
//			CallerType    string `json:"CallerType"`
//			DomainDetails struct {
//				Domain string `json:"Domain"`
//			} `json:"DomainDetails"`
//			FirstSeen       string `json:"FirstSeen"`
//			LastSeen        string `json:"LastSeen"`
//			RemoteIpDetails struct {
//				City struct {
//					CityName string `json:"CityName"`
//				} `json:"City"`
//				Country struct {
//					CountryCode string `json:"CountryCode"`
//					CountryName string `json:"CountryName"`
//				} `json:"Country"`
//				IpAddressV4 string `json:"IpAddressV4"`
//				Geolocation struct {
//					Lat interface{} `json:"Lat"`
//					Lon interface{} `json:"Lon"`
//				} `json:"Geolocation"`
//				Organization struct {
//					Asn    interface{} `json:"Asn"`
//					AsnOrg string      `json:"AsnOrg"`
//					Isp    string      `json:"Isp"`
//					Org    string      `json:"Org"`
//				} `json:"Organization"`
//			} `json:"RemoteIpDetails"`
//			ServiceName string `json:"ServiceName"`
//		} `json:"AwsApiCallAction"`
//		DnsRequestAction struct {
//			Blocked  interface{} `json:"Blocked"`
//			Domain   string      `json:"Domain"`
//			Protocol string      `json:"Protocol"`
//		} `json:"DnsRequestAction"`
//		NetworkConnectionAction struct {
//			Blocked             interface{} `json:"Blocked"`
//			ConnectionDirection string      `json:"ConnectionDirection"`
//			LocalPortDetails    struct {
//				Port     interface{} `json:"Port"`
//				PortName string      `json:"PortName"`
//			} `json:"LocalPortDetails"`
//			Protocol        string `json:"Protocol"`
//			RemoteIpDetails struct {
//				City struct {
//					CityName string `json:"CityName"`
//				} `json:"City"`
//				Country struct {
//					CountryCode string `json:"CountryCode"`
//					CountryName string `json:"CountryName"`
//				} `json:"Country"`
//				IpAddressV4 string `json:"IpAddressV4"`
//				Geolocation struct {
//					Lat interface{} `json:"Lat"`
//					Lon interface{} `json:"Lon"`
//				} `json:"Geolocation"`
//				Organization struct {
//					Asn    interface{} `json:"Asn"`
//					AsnOrg string      `json:"AsnOrg"`
//					Isp    string      `json:"Isp"`
//					Org    string      `json:"Org"`
//				} `json:"Organization"`
//			} `json:"RemoteIpDetails"`
//			RemotePortDetails struct {
//				Port     interface{} `json:"Port"`
//				PortName string      `json:"PortName"`
//			} `json:"RemotePortDetails"`
//		} `json:"NetworkConnectionAction"`
//		PortProbeAction struct {
//			Blocked          interface{} `json:"Blocked"`
//			PortProbeDetails []struct {
//				LocalIpDetails struct {
//					IpAddressV4 string `json:"IpAddressV4"`
//				} `json:"LocalIpDetails"`
//				LocalPortDetails struct {
//					Port     interface{} `json:"Port"`
//					PortName string      `json:"PortName"`
//				} `json:"LocalPortDetails"`
//				RemoteIpDetails struct {
//					City struct {
//						CityName string `json:"CityName"`
//					} `json:"City"`
//					Country struct {
//						CountryCode string `json:"CountryCode"`
//						CountryName string `json:"CountryName"`
//					} `json:"Country"`
//					GeoLocation struct {
//						Lat interface{} `json:"Lat"`
//						Lon interface{} `json:"Lon"`
//					} `json:"GeoLocation"`
//					IpAddressV4  string `json:"IpAddressV4"`
//					Organization struct {
//						Asn    interface{} `json:"Asn"`
//						AsnOrg string      `json:"AsnOrg"`
//						Isp    string      `json:"Isp"`
//						Org    string      `json:"Org"`
//					} `json:"Organization"`
//				} `json:"RemoteIpDetails"`
//			} `json:"PortProbeDetails"`
//		} `json:"PortProbeAction"`
//	} `json:"Action"`
//	AwsAccountId string `json:"AwsAccountId"`
//	CompanyName  string `json:"CompanyName"`
//	Compliance   struct {
//		RelatedRequirements []string `json:"RelatedRequirements"`
//		Status              string   `json:"Status"`
//		StatusReasons       []struct {
//			Description string `json:"Description"`
//			ReasonCode  string `json:"ReasonCode"`
//		} `json:"StatusReasons"`
//	} `json:"Compliance"`
//	Confidence            interface{} `json:"Confidence"`
//	CreatedAt             string      `json:"CreatedAt"`
//	Criticality           interface{} `json:"Criticality"`
//	Description           string      `json:"Description"`
//	FindingProviderFields struct {
//		Confidence      interface{} `json:"Confidence"`
//		Criticality     interface{} `json:"Criticality"`
//		RelatedFindings []struct {
//			ProductArn string `json:"ProductArn"`
//			Id         string `json:"Id"`
//		} `json:"RelatedFindings"`
//		Severity struct {
//			Label    string `json:"Label"`
//			Original string `json:"Original"`
//		} `json:"Severity"`
//		Types []string `json:"Types"`
//	} `json:"FindingProviderFields"`
//	FirstObservedAt string `json:"FirstObservedAt"`
//	GeneratorId     string `json:"GeneratorId"`
//	Id              string `json:"Id"`
//	LastObservedAt  string `json:"LastObservedAt"`
//	Malware         []struct {
//		Name  string `json:"Name"`
//		Path  string `json:"Path"`
//		State string `json:"State"`
//		Type  string `json:"Type"`
//	} `json:"Malware"`
//	Network struct {
//		DestinationDomain string      `json:"DestinationDomain"`
//		DestinationIpV4   string      `json:"DestinationIpV4"`
//		DestinationIpV6   string      `json:"DestinationIpV6"`
//		DestinationPort   interface{} `json:"DestinationPort"`
//		Direction         string      `json:"Direction"`
//		OpenPortRange     struct {
//			Begin interface{} `json:"Begin"`
//			End   interface{} `json:"End"`
//		} `json:"OpenPortRange"`
//		Protocol     string      `json:"Protocol"`
//		SourceDomain string      `json:"SourceDomain"`
//		SourceIpV4   string      `json:"SourceIpV4"`
//		SourceIpV6   string      `json:"SourceIpV6"`
//		SourceMac    string      `json:"SourceMac"`
//		SourcePort   interface{} `json:"SourcePort"`
//	} `json:"Network"`
//	NetworkPath []struct {
//		ComponentId   string `json:"ComponentId"`
//		ComponentType string `json:"ComponentType"`
//		Egress        struct {
//			Destination struct {
//				Address    []string `json:"Address"`
//				PortRanges []struct {
//					Begin interface{} `json:"Begin"`
//					End   interface{} `json:"End"`
//				} `json:"PortRanges"`
//			} `json:"Destination"`
//			Protocol string `json:"Protocol"`
//			Source   struct {
//				Address    []string `json:"Address"`
//				PortRanges []struct {
//					Begin interface{} `json:"Begin"`
//					End   interface{} `json:"End"`
//				} `json:"PortRanges"`
//			} `json:"Source"`
//		} `json:"Egress"`
//		Ingress struct {
//			Destination struct {
//				Address    []string `json:"Address"`
//				PortRanges []struct {
//					Begin interface{} `json:"Begin"`
//					End   interface{} `json:"End"`
//				} `json:"PortRanges"`
//			} `json:"Destination"`
//			Protocol string `json:"Protocol"`
//			Source   struct {
//				Address    []string `json:"Address"`
//				PortRanges []struct {
//					Begin interface{} `json:"Begin"`
//					End   interface{} `json:"End"`
//				} `json:"PortRanges"`
//			} `json:"Source"`
//		} `json:"Ingress"`
//	} `json:"NetworkPath"`
//	Note struct {
//		Text      string `json:"Text"`
//		UpdatedAt string `json:"UpdatedAt"`
//		UpdatedBy string `json:"UpdatedBy"`
//	} `json:"Note"`
//	PatchSummary struct {
//		FailedCount            interface{} `json:"FailedCount"`
//		Id                     string      `json:"Id"`
//		InstalledCount         interface{} `json:"InstalledCount"`
//		InstalledOtherCount    interface{} `json:"InstalledOtherCount"`
//		InstalledPendingReboot interface{} `json:"InstalledPendingReboot"`
//		InstalledRejectedCount interface{} `json:"InstalledRejectedCount"`
//		MissingCount           interface{} `json:"MissingCount"`
//		Operation              string      `json:"Operation"`
//		OperationEndTime       string      `json:"OperationEndTime"`
//		OperationStartTime     string      `json:"OperationStartTime"`
//		RebootOption           string      `json:"RebootOption"`
//	} `json:"PatchSummary"`
//	Process struct {
//		LaunchedAt   string      `json:"LaunchedAt"`
//		Name         string      `json:"Name"`
//		ParentPid    interface{} `json:"ParentPid"`
//		Path         string      `json:"Path"`
//		Pid          interface{} `json:"Pid"`
//		TerminatedAt string      `json:"TerminatedAt"`
//	} `json:"Process"`
//	ProductArn    string `json:"ProductArn"`
//	ProductFields struct {
//		String string `json:"string"`
//	} `json:"ProductFields"`
//	ProductName     string `json:"ProductName"`
//	RecordState     string `json:"RecordState"`
//	Region          string `json:"Region"`
//	RelatedFindings []struct {
//		Id         string `json:"Id"`
//		ProductArn string `json:"ProductArn"`
//	} `json:"RelatedFindings"`
//	Remediation struct {
//		Recommendation struct {
//			Text string `json:"Text"`
//			Url  string `json:"Url"`
//		} `json:"Recommendation"`
//	} `json:"Remediation"`
//	Resources []struct {
//		DataClassification struct {
//			DetailedResultsLocation string `json:"DetailedResultsLocation"`
//			Result                  struct {
//				AdditionalOccurrences interface{} `json:"AdditionalOccurrences"`
//				CustomDataIdentifiers struct {
//					Detections []struct {
//						Arn         string      `json:"Arn"`
//						Count       interface{} `json:"Count"`
//						Name        string      `json:"Name"`
//						Occurrences struct {
//							Cells []struct {
//								CellReference string      `json:"CellReference"`
//								Column        interface{} `json:"Column"`
//								ColumnName    string      `json:"ColumnName"`
//								Row           interface{} `json:"Row"`
//							} `json:"Cells"`
//							LineRanges []struct {
//								End         interface{} `json:"End"`
//								Start       interface{} `json:"Start"`
//								StartColumn interface{} `json:"StartColumn"`
//							} `json:"LineRanges"`
//							OffsetRanges []struct {
//								End         interface{} `json:"End"`
//								Start       interface{} `json:"Start"`
//								StartColumn interface{} `json:"StartColumn"`
//							} `json:"OffsetRanges"`
//							Pages []struct {
//								LineRange struct {
//									End         interface{} `json:"End"`
//									Start       interface{} `json:"Start"`
//									StartColumn interface{} `json:"StartColumn"`
//								} `json:"LineRange"`
//								OffsetRange struct {
//									End         interface{} `json:"End"`
//									Start       interface{} `json:"Start"`
//									StartColumn interface{} `json:"StartColumn"`
//								} `json:"OffsetRange"`
//								PageNumber interface{} `json:"PageNumber"`
//							} `json:"Pages"`
//							Records []struct {
//								JsonPath    string      `json:"JsonPath"`
//								RecordIndex interface{} `json:"RecordIndex"`
//							} `json:"Records"`
//						} `json:"Occurrences"`
//					} `json:"Detections"`
//					TotalCount interface{} `json:"TotalCount"`
//				} `json:"CustomDataIdentifiers"`
//				MimeType      string `json:"MimeType"`
//				SensitiveData []struct {
//					Category   string `json:"Category"`
//					Detections []struct {
//						Count       interface{} `json:"Count"`
//						Occurrences struct {
//							Cells []struct {
//								CellReference string      `json:"CellReference"`
//								Column        interface{} `json:"Column"`
//								ColumnName    string      `json:"ColumnName"`
//								Row           interface{} `json:"Row"`
//							} `json:"Cells"`
//							LineRanges []struct {
//								End         interface{} `json:"End"`
//								Start       interface{} `json:"Start"`
//								StartColumn interface{} `json:"StartColumn"`
//							} `json:"LineRanges"`
//							OffsetRanges []struct {
//								End         interface{} `json:"End"`
//								Start       interface{} `json:"Start"`
//								StartColumn interface{} `json:"StartColumn"`
//							} `json:"OffsetRanges"`
//							Pages []struct {
//								LineRange struct {
//									End         interface{} `json:"End"`
//									Start       interface{} `json:"Start"`
//									StartColumn interface{} `json:"StartColumn"`
//								} `json:"LineRange"`
//								OffsetRange struct {
//									End         interface{} `json:"End"`
//									Start       interface{} `json:"Start"`
//									StartColumn interface{} `json:"StartColumn"`
//								} `json:"OffsetRange"`
//								PageNumber interface{} `json:"PageNumber"`
//							} `json:"Pages"`
//							Records []struct {
//								JsonPath    string      `json:"JsonPath"`
//								RecordIndex interface{} `json:"RecordIndex"`
//							} `json:"Records"`
//						} `json:"Occurrences"`
//						Type string `json:"Type"`
//					} `json:"Detections"`
//					TotalCount interface{} `json:"TotalCount"`
//				} `json:"SensitiveData"`
//				SizeClassified interface{} `json:"SizeClassified"`
//				Status         struct {
//					Code   string `json:"Code"`
//					Reason string `json:"Reason"`
//				} `json:"Status"`
//			} `json:"Result"`
//		} `json:"DataClassification"`
//		Details struct {
//			AwsApiGatewayRestApi struct {
//				ApiKeySource          string   `json:"ApiKeySource"`
//				BinaryMediaTypes      []string `json:"BinaryMediaTypes"`
//				CreatedDate           string   `json:"CreatedDate"`
//				Description           string   `json:"Description"`
//				EndpointConfiguration struct {
//					Types []string `json:"Types"`
//				} `json:"EndpointConfiguration"`
//				Id                     string      `json:"Id"`
//				MinimumCompressionSize interface{} `json:"MinimumCompressionSize"`
//				Name                   string      `json:"Name"`
//				Version                string      `json:"Version"`
//			} `json:"AwsApiGatewayRestApi"`
//			AwsApiGatewayStage struct {
//				AccessLogSettings struct {
//					DestinationArn string `json:"DestinationArn"`
//					Format         string `json:"Format"`
//				} `json:"AccessLogSettings"`
//				CacheClusterEnabled interface{} `json:"CacheClusterEnabled"`
//				CacheClusterSize    string      `json:"CacheClusterSize"`
//				CacheClusterStatus  string      `json:"CacheClusterStatus"`
//				CanarySettings      struct {
//					DeploymentId           string      `json:"DeploymentId"`
//					PercentTraffic         interface{} `json:"PercentTraffic"`
//					StageVariableOverrides []struct {
//						String string `json:"string"`
//					} `json:"StageVariableOverrides"`
//					UseStageCache interface{} `json:"UseStageCache"`
//				} `json:"CanarySettings"`
//				ClientCertificateId  string `json:"ClientCertificateId"`
//				CreatedDate          string `json:"CreatedDate"`
//				DeploymentId         string `json:"DeploymentId"`
//				Description          string `json:"Description"`
//				DocumentationVersion string `json:"DocumentationVersion"`
//				LastUpdatedDate      string `json:"LastUpdatedDate"`
//				MethodSettings       []struct {
//					CacheDataEncrypted                     interface{} `json:"CacheDataEncrypted"`
//					CachingEnabled                         interface{} `json:"CachingEnabled"`
//					CacheTtlInSeconds                      interface{} `json:"CacheTtlInSeconds"`
//					DataTraceEnabled                       interface{} `json:"DataTraceEnabled"`
//					HttpMethod                             string      `json:"HttpMethod"`
//					LoggingLevel                           string      `json:"LoggingLevel"`
//					MetricsEnabled                         interface{} `json:"MetricsEnabled"`
//					RequireAuthorizationForCacheControl    interface{} `json:"RequireAuthorizationForCacheControl"`
//					ResourcePath                           string      `json:"ResourcePath"`
//					ThrottlingBurstLimit                   interface{} `json:"ThrottlingBurstLimit"`
//					ThrottlingRateLimit                    interface{} `json:"ThrottlingRateLimit"`
//					UnauthorizedCacheControlHeaderStrategy string      `json:"UnauthorizedCacheControlHeaderStrategy"`
//				} `json:"MethodSettings"`
//				StageName      string      `json:"StageName"`
//				TracingEnabled interface{} `json:"TracingEnabled"`
//				Variables      struct {
//					String string `json:"string"`
//				} `json:"Variables"`
//				WebAclArn string `json:"WebAclArn"`
//			} `json:"AwsApiGatewayStage"`
//			AwsApiGatewayV2Api struct {
//				ApiEndpoint               string `json:"ApiEndpoint"`
//				ApiId                     string `json:"ApiId"`
//				ApiKeySelectionExpression string `json:"ApiKeySelectionExpression"`
//				CorsConfiguration         struct {
//					AllowCredentials interface{} `json:"AllowCredentials"`
//					AllowHeaders     []string    `json:"AllowHeaders"`
//					AllowMethods     []string    `json:"AllowMethods"`
//					AllowOrigins     []string    `json:"AllowOrigins"`
//					ExposeHeaders    []string    `json:"ExposeHeaders"`
//					MaxAge           interface{} `json:"MaxAge"`
//				} `json:"CorsConfiguration"`
//				CreatedDate              string `json:"CreatedDate"`
//				Description              string `json:"Description"`
//				Name                     string `json:"Name"`
//				ProtocolType             string `json:"ProtocolType"`
//				RouteSelectionExpression string `json:"RouteSelectionExpression"`
//				Version                  string `json:"Version"`
//			} `json:"AwsApiGatewayV2Api"`
//			AwsApiGatewayV2Stage struct {
//				AccessLogSettings struct {
//					DestinationArn string `json:"DestinationArn"`
//					Format         string `json:"Format"`
//				} `json:"AccessLogSettings"`
//				ApiGatewayManaged    interface{} `json:"ApiGatewayManaged"`
//				AutoDeploy           interface{} `json:"AutoDeploy"`
//				ClientCertificateId  string      `json:"ClientCertificateId"`
//				CreatedDate          string      `json:"CreatedDate"`
//				DefaultRouteSettings struct {
//					DataTraceEnabled       interface{} `json:"DataTraceEnabled"`
//					DetailedMetricsEnabled interface{} `json:"DetailedMetricsEnabled"`
//					LoggingLevel           string      `json:"LoggingLevel"`
//					ThrottlingBurstLimit   interface{} `json:"ThrottlingBurstLimit"`
//					ThrottlingRateLimit    interface{} `json:"ThrottlingRateLimit"`
//				} `json:"DefaultRouteSettings"`
//				DeploymentId                string `json:"DeploymentId"`
//				Description                 string `json:"Description"`
//				LastDeploymentStatusMessage string `json:"LastDeploymentStatusMessage"`
//				LastUpdatedDate             string `json:"LastUpdatedDate"`
//				RouteSettings               struct {
//					DetailedMetricsEnabled interface{} `json:"DetailedMetricsEnabled"`
//					LoggingLevel           string      `json:"LoggingLevel"`
//					DataTraceEnabled       interface{} `json:"DataTraceEnabled"`
//					ThrottlingBurstLimit   interface{} `json:"ThrottlingBurstLimit"`
//					ThrottlingRateLimit    interface{} `json:"ThrottlingRateLimit"`
//				} `json:"RouteSettings"`
//				StageName      string `json:"StageName"`
//				StageVariables []struct {
//					String string `json:"string"`
//				} `json:"StageVariables"`
//			} `json:"AwsApiGatewayV2Stage"`
//			AwsAutoScalingAutoScalingGroup struct {
//				CreatedTime             string      `json:"CreatedTime"`
//				HealthCheckGracePeriod  interface{} `json:"HealthCheckGracePeriod"`
//				HealthCheckType         string      `json:"HealthCheckType"`
//				LaunchConfigurationName string      `json:"LaunchConfigurationName"`
//				LoadBalancerNames       []string    `json:"LoadBalancerNames"`
//			} `json:"AwsAutoScalingAutoScalingGroup"`
//			AwsCertificateManagerCertificate struct {
//				CertificateAuthorityArn string `json:"CertificateAuthorityArn"`
//				CreatedAt               string `json:"CreatedAt"`
//				DomainName              string `json:"DomainName"`
//				DomainValidationOptions []struct {
//					DomainName     string `json:"DomainName"`
//					ResourceRecord struct {
//						Name  string `json:"Name"`
//						Type  string `json:"Type"`
//						Value string `json:"Value"`
//					} `json:"ResourceRecord"`
//					ValidationDomain string   `json:"ValidationDomain"`
//					ValidationEmails []string `json:"ValidationEmails"`
//					ValidationMethod string   `json:"ValidationMethod"`
//					ValidationStatus string   `json:"ValidationStatus"`
//				} `json:"DomainValidationOptions"`
//				ExtendedKeyUsages []struct {
//					Name string `json:"Name"`
//					OId  string `json:"OId"`
//				} `json:"ExtendedKeyUsages"`
//				FailureReason string   `json:"FailureReason"`
//				ImportedAt    string   `json:"ImportedAt"`
//				InUseBy       []string `json:"InUseBy"`
//				IssuedAt      string   `json:"IssuedAt"`
//				Issuer        string   `json:"Issuer"`
//				KeyAlgorithm  string   `json:"KeyAlgorithm"`
//				KeyUsages     []struct {
//					Name string `json:"Name"`
//				} `json:"KeyUsages"`
//				NotAfter  string `json:"NotAfter"`
//				NotBefore string `json:"NotBefore"`
//				Options   struct {
//					CertificateTransparencyLoggingPreference string `json:"CertificateTransparencyLoggingPreference"`
//				} `json:"Options"`
//				RenewalEligibility string `json:"RenewalEligibility"`
//				RenewalSummary     struct {
//					DomainValidationOptions []struct {
//						DomainName     string `json:"DomainName"`
//						ResourceRecord struct {
//							Name  string `json:"Name"`
//							Type  string `json:"Type"`
//							Value string `json:"Value"`
//						} `json:"ResourceRecord"`
//						ValidationDomain string   `json:"ValidationDomain"`
//						ValidationEmails []string `json:"ValidationEmails"`
//						ValidationMethod string   `json:"ValidationMethod"`
//						ValidationStatus string   `json:"ValidationStatus"`
//					} `json:"DomainValidationOptions"`
//					RenewalStatus       string `json:"RenewalStatus"`
//					RenewalStatusReason string `json:"RenewalStatusReason"`
//					UpdatedAt           string `json:"UpdatedAt"`
//				} `json:"RenewalSummary"`
//				Serial                  string   `json:"Serial"`
//				SignatureAlgorithm      string   `json:"SignatureAlgorithm"`
//				Status                  string   `json:"Status"`
//				Subject                 string   `json:"Subject"`
//				SubjectAlternativeNames []string `json:"SubjectAlternativeNames"`
//				Type                    string   `json:"Type"`
//			} `json:"AwsCertificateManagerCertificate"`
//			AwsCloudFrontDistribution struct {
//				CacheBehaviors struct {
//					Items []struct {
//						ViewerProtocolPolicy string `json:"ViewerProtocolPolicy"`
//					} `json:"Items"`
//				} `json:"CacheBehaviors"`
//				DefaultCacheBehavior struct {
//					ViewerProtocolPolicy string `json:"ViewerProtocolPolicy"`
//				} `json:"DefaultCacheBehavior"`
//				DefaultRootObject string `json:"DefaultRootObject"`
//				DomainName        string `json:"DomainName"`
//				Etag              string `json:"Etag"`
//				LastModifiedTime  string `json:"LastModifiedTime"`
//				Logging           struct {
//					Bucket         string      `json:"Bucket"`
//					Enabled        interface{} `json:"Enabled"`
//					IncludeCookies interface{} `json:"IncludeCookies"`
//					Prefix         string      `json:"Prefix"`
//				} `json:"Logging"`
//				OriginGroups struct {
//					Items []struct {
//						FailoverCriteria struct {
//							StatusCodes struct {
//								Items    []interface{} `json:"Items"`
//								Quantity interface{}   `json:"Quantity"`
//							} `json:"StatusCodes"`
//						} `json:"FailoverCriteria"`
//					} `json:"Items"`
//				} `json:"OriginGroups"`
//				Origins struct {
//					Items []struct {
//						DomainName     string `json:"DomainName"`
//						Id             string `json:"Id"`
//						OriginPath     string `json:"OriginPath"`
//						S3OriginConfig struct {
//							OriginAccessIdentity string `json:"OriginAccessIdentity"`
//						} `json:"S3OriginConfig"`
//					} `json:"Items"`
//				} `json:"Origins"`
//				Status   string `json:"Status"`
//				WebAclId string `json:"WebAclId"`
//			} `json:"AwsCloudFrontDistribution"`
//			AwsCloudTrailTrail struct {
//				CloudWatchLogsLogGroupArn  string      `json:"CloudWatchLogsLogGroupArn"`
//				CloudWatchLogsRoleArn      string      `json:"CloudWatchLogsRoleArn"`
//				HasCustomEventSelectors    interface{} `json:"HasCustomEventSelectors"`
//				HomeRegion                 string      `json:"HomeRegion"`
//				IncludeGlobalServiceEvents interface{} `json:"IncludeGlobalServiceEvents"`
//				IsMultiRegionTrail         interface{} `json:"IsMultiRegionTrail"`
//				IsOrganizationTrail        interface{} `json:"IsOrganizationTrail"`
//				KmsKeyId                   string      `json:"KmsKeyId"`
//				LogFileValidationEnabled   interface{} `json:"LogFileValidationEnabled"`
//				Name                       string      `json:"Name"`
//				S3BucketName               string      `json:"S3BucketName"`
//				S3KeyPrefix                string      `json:"S3KeyPrefix"`
//				SnsTopicArn                string      `json:"SnsTopicArn"`
//				SnsTopicName               string      `json:"SnsTopicName"`
//				TrailArn                   string      `json:"TrailArn"`
//			} `json:"AwsCloudTrailTrail"`
//			AwsCodeBuildProject struct {
//				EncryptionKey string `json:"EncryptionKey"`
//				Environment   struct {
//					Type                     string `json:"Type"`
//					Certificate              string `json:"Certificate"`
//					ImagePullCredentialsType string `json:"ImagePullCredentialsType"`
//					RegistryCredential       struct {
//						Credential         string `json:"Credential"`
//						CredentialProvider string `json:"CredentialProvider"`
//					} `json:"RegistryCredential"`
//				} `json:"Environment"`
//				Name        string `json:"Name"`
//				ServiceRole string `json:"ServiceRole"`
//				Source      struct {
//					Type          string      `json:"Type"`
//					Location      string      `json:"Location"`
//					GitCloneDepth interface{} `json:"GitCloneDepth"`
//				} `json:"Source"`
//				VpcConfig struct {
//					VpcId            string   `json:"VpcId"`
//					Subnets          []string `json:"Subnets"`
//					SecurityGroupIds []string `json:"SecurityGroupIds"`
//				} `json:"VpcConfig"`
//			} `json:"AwsCodeBuildProject"`
//			AwsDynamoDbTable struct {
//				AttributeDefinitions []struct {
//					AttributeName string `json:"AttributeName"`
//					AttributeType string `json:"AttributeType"`
//				} `json:"AttributeDefinitions"`
//				BillingModeSummary struct {
//					BillingMode                       string `json:"BillingMode"`
//					LastUpdateToPayPerRequestDateTime string `json:"LastUpdateToPayPerRequestDateTime"`
//				} `json:"BillingModeSummary"`
//				CreationDateTime       string `json:"CreationDateTime"`
//				GlobalSecondaryIndexes []struct {
//					Backfilling    interface{} `json:"Backfilling"`
//					IndexArn       string      `json:"IndexArn"`
//					IndexName      string      `json:"IndexName"`
//					IndexSizeBytes interface{} `json:"IndexSizeBytes"`
//					IndexStatus    string      `json:"IndexStatus"`
//					ItemCount      interface{} `json:"ItemCount"`
//					KeySchema      []struct {
//						AttributeName string `json:"AttributeName"`
//						KeyType       string `json:"KeyType"`
//					} `json:"KeySchema"`
//					Projection struct {
//						NonKeyAttributes []string `json:"NonKeyAttributes"`
//						ProjectionType   string   `json:"ProjectionType"`
//					} `json:"Projection"`
//					ProvisionedThroughput struct {
//						LastDecreaseDateTime   string      `json:"LastDecreaseDateTime"`
//						LastIncreaseDateTime   string      `json:"LastIncreaseDateTime"`
//						NumberOfDecreasesToday interface{} `json:"NumberOfDecreasesToday"`
//						ReadCapacityUnits      interface{} `json:"ReadCapacityUnits"`
//						WriteCapacityUnits     interface{} `json:"WriteCapacityUnits"`
//					} `json:"ProvisionedThroughput"`
//				} `json:"GlobalSecondaryIndexes"`
//				GlobalTableVersion string      `json:"GlobalTableVersion"`
//				ItemCount          interface{} `json:"ItemCount"`
//				KeySchema          []struct {
//					AttributeName string `json:"AttributeName"`
//					KeyType       string `json:"KeyType"`
//				} `json:"KeySchema"`
//				LatestStreamArn       string `json:"LatestStreamArn"`
//				LatestStreamLabel     string `json:"LatestStreamLabel"`
//				LocalSecondaryIndexes []struct {
//					IndexArn  string `json:"IndexArn"`
//					IndexName string `json:"IndexName"`
//					KeySchema []struct {
//						AttributeName string `json:"AttributeName"`
//						KeyType       string `json:"KeyType"`
//					} `json:"KeySchema"`
//					Projection struct {
//						NonKeyAttributes []string `json:"NonKeyAttributes"`
//						ProjectionType   string   `json:"ProjectionType"`
//					} `json:"Projection"`
//				} `json:"LocalSecondaryIndexes"`
//				ProvisionedThroughput struct {
//					LastDecreaseDateTime   string      `json:"LastDecreaseDateTime"`
//					LastIncreaseDateTime   string      `json:"LastIncreaseDateTime"`
//					NumberOfDecreasesToday interface{} `json:"NumberOfDecreasesToday"`
//					ReadCapacityUnits      interface{} `json:"ReadCapacityUnits"`
//					WriteCapacityUnits     interface{} `json:"WriteCapacityUnits"`
//				} `json:"ProvisionedThroughput"`
//				Replicas []struct {
//					GlobalSecondaryIndexes []struct {
//						IndexName                     string `json:"IndexName"`
//						ProvisionedThroughputOverride struct {
//							ReadCapacityUnits interface{} `json:"ReadCapacityUnits"`
//						} `json:"ProvisionedThroughputOverride"`
//					} `json:"GlobalSecondaryIndexes"`
//					KmsMasterKeyId                string `json:"KmsMasterKeyId"`
//					ProvisionedThroughputOverride struct {
//						ReadCapacityUnits interface{} `json:"ReadCapacityUnits"`
//					} `json:"ProvisionedThroughputOverride"`
//					RegionName               string `json:"RegionName"`
//					ReplicaStatus            string `json:"ReplicaStatus"`
//					ReplicaStatusDescription string `json:"ReplicaStatusDescription"`
//				} `json:"Replicas"`
//				RestoreSummary struct {
//					RestoreDateTime   string      `json:"RestoreDateTime"`
//					RestoreInProgress interface{} `json:"RestoreInProgress"`
//					SourceBackupArn   string      `json:"SourceBackupArn"`
//					SourceTableArn    string      `json:"SourceTableArn"`
//				} `json:"RestoreSummary"`
//				SseDescription struct {
//					InaccessibleEncryptionDateTime string `json:"InaccessibleEncryptionDateTime"`
//					KmsMasterKeyArn                string `json:"KmsMasterKeyArn"`
//					SseType                        string `json:"SseType"`
//					Status                         string `json:"Status"`
//				} `json:"SseDescription"`
//				StreamSpecification struct {
//					StreamEnabled  interface{} `json:"StreamEnabled"`
//					StreamViewType string      `json:"StreamViewType"`
//				} `json:"StreamSpecification"`
//				TableId        string      `json:"TableId"`
//				TableName      string      `json:"TableName"`
//				TableSizeBytes interface{} `json:"TableSizeBytes"`
//				TableStatus    string      `json:"TableStatus"`
//			} `json:"AwsDynamoDbTable"`
//			AwsEc2Eip struct {
//				AllocationId            string `json:"AllocationId"`
//				AssociationId           string `json:"AssociationId"`
//				Domain                  string `json:"Domain"`
//				InstanceId              string `json:"InstanceId"`
//				NetworkBorderGroup      string `json:"NetworkBorderGroup"`
//				NetworkInterfaceId      string `json:"NetworkInterfaceId"`
//				NetworkInterfaceOwnerId string `json:"NetworkInterfaceOwnerId"`
//				PrivateIpAddress        string `json:"PrivateIpAddress"`
//				PublicIp                string `json:"PublicIp"`
//				PublicIpv4Pool          string `json:"PublicIpv4Pool"`
//			} `json:"AwsEc2Eip"`
//			AwsEc2Instance struct {
//				IamInstanceProfileArn string   `json:"IamInstanceProfileArn"`
//				ImageId               string   `json:"ImageId"`
//				IpV4Addresses         []string `json:"IpV4Addresses"`
//				IpV6Addresses         []string `json:"IpV6Addresses"`
//				KeyName               string   `json:"KeyName"`
//				LaunchedAt            string   `json:"LaunchedAt"`
//				NetworkInterfaces     []struct {
//					NetworkInterfaceId string `json:"NetworkInterfaceId"`
//				} `json:"NetworkInterfaces"`
//				SubnetId string `json:"SubnetId"`
//				Type     string `json:"Type"`
//				VpcId    string `json:"VpcId"`
//			} `json:"AwsEc2Instance"`
//			AwsEc2NetworkAcl struct {
//				Associations []struct {
//					NetworkAclAssociationId string `json:"NetworkAclAssociationId"`
//					NetworkAclId            string `json:"NetworkAclId"`
//					SubnetId                string `json:"SubnetId"`
//				} `json:"Associations"`
//				Entries []struct {
//					CidrBlock    string      `json:"CidrBlock"`
//					Egress       interface{} `json:"Egress"`
//					IcmpTypeCode struct {
//						Code interface{} `json:"Code"`
//						Type interface{} `json:"Type"`
//					} `json:"IcmpTypeCode"`
//					Ipv6CidrBlock string `json:"Ipv6CidrBlock"`
//					PortRange     struct {
//						From interface{} `json:"From"`
//						To   interface{} `json:"To"`
//					} `json:"PortRange"`
//					Protocol   string      `json:"Protocol"`
//					RuleAction string      `json:"RuleAction"`
//					RuleNumber interface{} `json:"RuleNumber"`
//				} `json:"Entries"`
//				IsDefault    interface{} `json:"IsDefault"`
//				NetworkAclId string      `json:"NetworkAclId"`
//				OwnerId      string      `json:"OwnerId"`
//				VpcId        string      `json:"VpcId"`
//			} `json:"AwsEc2NetworkAcl"`
//			AwsEc2NetworkInterface struct {
//				Attachment struct {
//					AttachmentId        string      `json:"AttachmentId"`
//					AttachTime          string      `json:"AttachTime"`
//					DeleteOnTermination interface{} `json:"DeleteOnTermination"`
//					DeviceIndex         interface{} `json:"DeviceIndex"`
//					InstanceId          string      `json:"InstanceId"`
//					InstanceOwnerId     string      `json:"InstanceOwnerId"`
//					Status              string      `json:"Status"`
//				} `json:"Attachment"`
//				Ipv6Addresses []struct {
//					Ipv6Address string `json:"Ipv6Address"`
//				} `json:"Ipv6Addresses"`
//				NetworkInterfaceId string `json:"NetworkInterfaceId"`
//				PrivateIpAddresses []struct {
//					PrivateDnsName   string `json:"PrivateDnsName"`
//					PrivateIpAddress string `json:"PrivateIpAddress"`
//				} `json:"PrivateIpAddresses"`
//				PublicDnsName  string `json:"PublicDnsName"`
//				PublicIp       string `json:"PublicIp"`
//				SecurityGroups []struct {
//					GroupId   string `json:"GroupId"`
//					GroupName string `json:"GroupName"`
//				} `json:"SecurityGroups"`
//				SourceDestCheck interface{} `json:"SourceDestCheck"`
//			} `json:"AwsEc2NetworkInterface"`
//			AwsEc2SecurityGroup struct {
//				GroupId       string `json:"GroupId"`
//				GroupName     string `json:"GroupName"`
//				IpPermissions []struct {
//					FromPort   interface{} `json:"FromPort"`
//					IpProtocol string      `json:"IpProtocol"`
//					IpRanges   []struct {
//						CidrIp string `json:"CidrIp"`
//					} `json:"IpRanges"`
//					Ipv6Ranges []struct {
//						CidrIpv6 string `json:"CidrIpv6"`
//					} `json:"Ipv6Ranges"`
//					PrefixListIds []struct {
//						PrefixListId string `json:"PrefixListId"`
//					} `json:"PrefixListIds"`
//					ToPort           interface{} `json:"ToPort"`
//					UserIdGroupPairs []struct {
//						GroupId                string `json:"GroupId"`
//						GroupName              string `json:"GroupName"`
//						PeeringStatus          string `json:"PeeringStatus"`
//						UserId                 string `json:"UserId"`
//						VpcId                  string `json:"VpcId"`
//						VpcPeeringConnectionId string `json:"VpcPeeringConnectionId"`
//					} `json:"UserIdGroupPairs"`
//				} `json:"IpPermissions"`
//				IpPermissionsEgress []struct {
//					FromPort   interface{} `json:"FromPort"`
//					IpProtocol string      `json:"IpProtocol"`
//					IpRanges   []struct {
//						CidrIp string `json:"CidrIp"`
//					} `json:"IpRanges"`
//					Ipv6Ranges []struct {
//						CidrIpv6 string `json:"CidrIpv6"`
//					} `json:"Ipv6Ranges"`
//					PrefixListIds []struct {
//						PrefixListId string `json:"PrefixListId"`
//					} `json:"PrefixListIds"`
//					ToPort           interface{} `json:"ToPort"`
//					UserIdGroupPairs []struct {
//						GroupId                string `json:"GroupId"`
//						GroupName              string `json:"GroupName"`
//						PeeringStatus          string `json:"PeeringStatus"`
//						UserId                 string `json:"UserId"`
//						VpcId                  string `json:"VpcId"`
//						VpcPeeringConnectionId string `json:"VpcPeeringConnectionId"`
//					} `json:"UserIdGroupPairs"`
//				} `json:"IpPermissionsEgress"`
//				OwnerId string `json:"OwnerId"`
//				VpcId   string `json:"VpcId"`
//			} `json:"AwsEc2SecurityGroup"`
//			AwsEc2Subnet struct {
//				AssignIpv6AddressOnCreation interface{} `json:"AssignIpv6AddressOnCreation"`
//				AvailabilityZone            string      `json:"AvailabilityZone"`
//				AvailabilityZoneId          string      `json:"AvailabilityZoneId"`
//				AvailableIpAddressCount     interface{} `json:"AvailableIpAddressCount"`
//				CidrBlock                   string      `json:"CidrBlock"`
//				DefaultForAz                interface{} `json:"DefaultForAz"`
//				Ipv6CidrBlockAssociationSet []struct {
//					AssociationId  string `json:"AssociationId"`
//					Ipv6CidrBlock  string `json:"Ipv6CidrBlock"`
//					CidrBlockState string `json:"CidrBlockState"`
//				} `json:"Ipv6CidrBlockAssociationSet"`
//				MapPublicIpOnLaunch interface{} `json:"MapPublicIpOnLaunch"`
//				OwnerId             string      `json:"OwnerId"`
//				State               string      `json:"State"`
//				SubnetArn           string      `json:"SubnetArn"`
//				SubnetId            string      `json:"SubnetId"`
//				VpcId               string      `json:"VpcId"`
//			} `json:"AwsEc2Subnet"`
//			AwsEc2Volume struct {
//				Attachments []struct {
//					AttachTime          string      `json:"AttachTime"`
//					DeleteOnTermination interface{} `json:"DeleteOnTermination"`
//					InstanceId          string      `json:"InstanceId"`
//					Status              string      `json:"Status"`
//				} `json:"Attachments"`
//				CreateTime string      `json:"CreateTime"`
//				Encrypted  interface{} `json:"Encrypted"`
//				KmsKeyId   string      `json:"KmsKeyId"`
//				Size       interface{} `json:"Size"`
//				SnapshotId string      `json:"SnapshotId"`
//				Status     string      `json:"Status"`
//			} `json:"AwsEc2Volume"`
//			AwsEc2Vpc struct {
//				CidrBlockAssociationSet []struct {
//					AssociationId  string `json:"AssociationId"`
//					CidrBlock      string `json:"CidrBlock"`
//					CidrBlockState string `json:"CidrBlockState"`
//				} `json:"CidrBlockAssociationSet"`
//				DhcpOptionsId               string `json:"DhcpOptionsId"`
//				Ipv6CidrBlockAssociationSet []struct {
//					AssociationId  string `json:"AssociationId"`
//					CidrBlockState string `json:"CidrBlockState"`
//					Ipv6CidrBlock  string `json:"Ipv6CidrBlock"`
//				} `json:"Ipv6CidrBlockAssociationSet"`
//				State string `json:"State"`
//			} `json:"AwsEc2Vpc"`
//			AwsEcsCluster struct {
//				CapacityProviders []string `json:"CapacityProviders"`
//				ClusterSettings   []struct {
//					Name  string `json:"Name"`
//					Value string `json:"Value"`
//				} `json:"ClusterSettings"`
//				Configuration struct {
//					ExecuteCommandConfiguration struct {
//						KmsKeyId         string `json:"KmsKeyId"`
//						LogConfiguration struct {
//							CloudWatchEncryptionEnabled interface{} `json:"CloudWatchEncryptionEnabled"`
//							CloudWatchLogGroupName      string      `json:"CloudWatchLogGroupName"`
//							S3BucketName                string      `json:"S3BucketName"`
//							S3EncryptionEnabled         interface{} `json:"S3EncryptionEnabled"`
//							S3KeyPrefix                 string      `json:"S3KeyPrefix"`
//						} `json:"LogConfiguration"`
//						Logging string `json:"Logging"`
//					} `json:"ExecuteCommandConfiguration"`
//				} `json:"Configuration"`
//				DefaultCapacityProviderStrategy []struct {
//					Base             interface{} `json:"Base"`
//					CapacityProvider string      `json:"CapacityProvider"`
//					Weight           interface{} `json:"Weight"`
//				} `json:"DefaultCapacityProviderStrategy"`
//			} `json:"AwsEcsCluster"`
//			AwsEcsService struct {
//				CapacityProviderStrategy []struct {
//					Base             interface{} `json:"Base"`
//					CapacityProvider string      `json:"CapacityProvider"`
//					Weight           interface{} `json:"Weight"`
//				} `json:"CapacityProviderStrategy"`
//				Cluster                 string `json:"Cluster"`
//				DeploymentConfiguration struct {
//					DeploymentCircuitBreaker struct {
//						Enable   interface{} `json:"Enable"`
//						Rollback interface{} `json:"Rollback"`
//					} `json:"DeploymentCircuitBreaker"`
//					MaximumPercent        interface{} `json:"MaximumPercent"`
//					MinimumHealthyPercent interface{} `json:"MinimumHealthyPercent"`
//				} `json:"DeploymentConfiguration"`
//				DeploymentController struct {
//					Type string `json:"Type"`
//				} `json:"DeploymentController"`
//				DesiredCount                  interface{} `json:"DesiredCount"`
//				EnableEcsManagedTags          interface{} `json:"EnableEcsManagedTags"`
//				EnableExecuteCommand          interface{} `json:"EnableExecuteCommand"`
//				HealthCheckGracePeriodSeconds interface{} `json:"HealthCheckGracePeriodSeconds"`
//				LaunchType                    string      `json:"LaunchType"`
//				LoadBalancers                 []struct {
//					ContainerName    string      `json:"ContainerName"`
//					ContainerPort    interface{} `json:"ContainerPort"`
//					LoadBalancerName string      `json:"LoadBalancerName"`
//					TargetGroupArn   string      `json:"TargetGroupArn"`
//				} `json:"LoadBalancers"`
//				Name                 string `json:"Name"`
//				NetworkConfiguration struct {
//					AwsVpcConfiguration struct {
//						AssignPublicIp string   `json:"AssignPublicIp"`
//						SecurityGroups []string `json:"SecurityGroups"`
//						Subnets        []string `json:"Subnets"`
//					} `json:"AwsVpcConfiguration"`
//				} `json:"NetworkConfiguration"`
//				PlacementConstraints []struct {
//					Expression string `json:"Expression"`
//					Type       string `json:"Type"`
//				} `json:"PlacementConstraints"`
//				PlacementStrategies []struct {
//					Field string `json:"Field"`
//					Type  string `json:"Type"`
//				} `json:"PlacementStrategies"`
//				PlatformVersion    string `json:"PlatformVersion"`
//				PropagateTags      string `json:"PropagateTags"`
//				Role               string `json:"Role"`
//				SchedulingStrategy string `json:"SchedulingStrategy"`
//				ServiceArn         string `json:"ServiceArn"`
//				ServiceName        string `json:"ServiceName"`
//				ServiceRegistries  []struct {
//					ContainerName string      `json:"ContainerName"`
//					ContainerPort interface{} `json:"ContainerPort"`
//					Port          interface{} `json:"Port"`
//					RegistryArn   string      `json:"RegistryArn"`
//				} `json:"ServiceRegistries"`
//				TaskDefinition string `json:"TaskDefinition"`
//			} `json:"AwsEcsService"`
//			AwsEcsTaskDefinition struct {
//				ContainerDefinitions []struct {
//					Command   []string    `json:"Command"`
//					Cpu       interface{} `json:"Cpu"`
//					DependsOn []struct {
//						Condition     string `json:"Condition"`
//						ContainerName string `json:"ContainerName"`
//					} `json:"DependsOn"`
//					DisableNetworking interface{} `json:"DisableNetworking"`
//					DnsSearchDomains  []string    `json:"DnsSearchDomains"`
//					DnsServers        []string    `json:"DnsServers"`
//					DockerLabels      struct {
//						String string `json:"string"`
//					} `json:"DockerLabels"`
//					DockerSecurityOptions []string `json:"DockerSecurityOptions"`
//					EntryPoint            []string `json:"EntryPoint"`
//					Environment           []struct {
//						Name  string `json:"Name"`
//						Value string `json:"Value"`
//					} `json:"Environment"`
//					EnvironmentFiles []struct {
//						Type  string `json:"Type"`
//						Value string `json:"Value"`
//					} `json:"EnvironmentFiles"`
//					Essential  interface{} `json:"Essential"`
//					ExtraHosts []struct {
//						Hostname  string `json:"Hostname"`
//						IpAddress string `json:"IpAddress"`
//					} `json:"ExtraHosts"`
//					FirelensConfiguration struct {
//						Options struct {
//							String string `json:"string"`
//						} `json:"Options"`
//						Type string `json:"Type"`
//					} `json:"FirelensConfiguration"`
//					HealthCheck struct {
//						Command     []string    `json:"Command"`
//						Interval    interface{} `json:"Interval"`
//						Retries     interface{} `json:"Retries"`
//						StartPeriod interface{} `json:"StartPeriod"`
//						Timeout     interface{} `json:"Timeout"`
//					} `json:"HealthCheck"`
//					Hostname        string      `json:"Hostname"`
//					Image           string      `json:"Image"`
//					Interactive     interface{} `json:"Interactive"`
//					Links           []string    `json:"Links"`
//					LinuxParameters struct {
//						Capabilities struct {
//							Add  []string `json:"Add"`
//							Drop []string `json:"Drop"`
//						} `json:"Capabilities"`
//						Devices []struct {
//							ContainerPath string   `json:"ContainerPath"`
//							HostPath      string   `json:"HostPath"`
//							Permissions   []string `json:"Permissions"`
//						} `json:"Devices"`
//						InitProcessEnabled interface{} `json:"InitProcessEnabled"`
//						MaxSwap            interface{} `json:"MaxSwap"`
//						SharedMemorySize   interface{} `json:"SharedMemorySize"`
//						Swappiness         interface{} `json:"Swappiness"`
//						Tmpfs              []struct {
//							ContainerPath string      `json:"ContainerPath"`
//							MountOptions  []string    `json:"MountOptions"`
//							Size          interface{} `json:"Size"`
//						} `json:"Tmpfs"`
//					} `json:"LinuxParameters"`
//					LogConfiguration struct {
//						LogDriver string `json:"LogDriver"`
//						Options   struct {
//							String string `json:"string"`
//						} `json:"Options"`
//						SecretOptions []struct {
//							Name      string `json:"Name"`
//							ValueFrom string `json:"ValueFrom"`
//						} `json:"SecretOptions"`
//					} `json:"LogConfiguration"`
//					Memory            interface{} `json:"Memory"`
//					MemoryReservation interface{} `json:"MemoryReservation"`
//					MountPoints       []struct {
//						ContainerPath string      `json:"ContainerPath"`
//						ReadOnly      interface{} `json:"ReadOnly"`
//						SourceVolume  string      `json:"SourceVolume"`
//					} `json:"MountPoints"`
//					Name         string `json:"Name"`
//					PortMappings []struct {
//						ContainerPort interface{} `json:"ContainerPort"`
//						HostPort      interface{} `json:"HostPort"`
//						Protocol      string      `json:"Protocol"`
//					} `json:"PortMappings"`
//					Privileged             interface{} `json:"Privileged"`
//					PseudoTerminal         interface{} `json:"PseudoTerminal"`
//					ReadonlyRootFilesystem interface{} `json:"ReadonlyRootFilesystem"`
//					RepositoryCredentials  struct {
//						CredentialsParameter string `json:"CredentialsParameter"`
//					} `json:"RepositoryCredentials"`
//					ResourceRequirements []struct {
//						Type  string `json:"Type"`
//						Value string `json:"Value"`
//					} `json:"ResourceRequirements"`
//					Secrets []struct {
//						Name      string `json:"Name"`
//						ValueFrom string `json:"ValueFrom"`
//					} `json:"Secrets"`
//					StartTimeout   interface{} `json:"StartTimeout"`
//					StopTimeout    interface{} `json:"StopTimeout"`
//					SystemControls []struct {
//						Namespace string `json:"Namespace"`
//						Value     string `json:"Value"`
//					} `json:"SystemControls"`
//					Ulimits []struct {
//						HardLimit interface{} `json:"HardLimit"`
//						Name      string      `json:"Name"`
//						SoftLimit interface{} `json:"SoftLimit"`
//					} `json:"Ulimits"`
//					User        string `json:"User"`
//					VolumesFrom []struct {
//						ReadOnly        interface{} `json:"ReadOnly"`
//						SourceContainer string      `json:"SourceContainer"`
//					} `json:"VolumesFrom"`
//					WorkingDirectory string `json:"WorkingDirectory"`
//				} `json:"ContainerDefinitions"`
//				Cpu                   string `json:"Cpu"`
//				ExecutionRoleArn      string `json:"ExecutionRoleArn"`
//				Family                string `json:"Family"`
//				InferenceAccelerators []struct {
//					DeviceName string `json:"DeviceName"`
//					DeviceType string `json:"DeviceType"`
//				} `json:"InferenceAccelerators"`
//				IpcMode              string `json:"IpcMode"`
//				Memory               string `json:"Memory"`
//				NetworkMode          string `json:"NetworkMode"`
//				PidMode              string `json:"PidMode"`
//				PlacementConstraints []struct {
//					Expression string `json:"Expression"`
//					Type       string `json:"Type"`
//				} `json:"PlacementConstraints"`
//				ProxyConfiguration struct {
//					ContainerName                string `json:"ContainerName"`
//					ProxyConfigurationProperties []struct {
//						Name  string `json:"Name"`
//						Value string `json:"Value"`
//					} `json:"ProxyConfigurationProperties"`
//					Type string `json:"Type"`
//				} `json:"ProxyConfiguration"`
//				RequiresCompatibilities []string `json:"RequiresCompatibilities"`
//				TaskRoleArn             string   `json:"TaskRoleArn"`
//				Status                  string   `json:"Status"`
//				Volumes                 []struct {
//					DockerVolumeConfiguration struct {
//						Autoprovision interface{} `json:"Autoprovision"`
//						Driver        string      `json:"Driver"`
//						DriverOpts    struct {
//							String string `json:"string"`
//						} `json:"DriverOpts"`
//						Labels struct {
//							String string `json:"string"`
//						} `json:"Labels"`
//						Scope string `json:"Scope"`
//					} `json:"DockerVolumeConfiguration"`
//					EfsVolumeConfiguration struct {
//						AuthorizationConfig struct {
//							AccessPointId string `json:"AccessPointId"`
//							Iam           string `json:"Iam"`
//						} `json:"AuthorizationConfig"`
//						FilesystemId          string      `json:"FilesystemId"`
//						RootDirectory         string      `json:"RootDirectory"`
//						TransitEncryption     string      `json:"TransitEncryption"`
//						TransitEncryptionPort interface{} `json:"TransitEncryptionPort"`
//					} `json:"EfsVolumeConfiguration"`
//					Host struct {
//						SourcePath string `json:"SourcePath"`
//					} `json:"Host"`
//					Name string `json:"Name"`
//				} `json:"Volumes"`
//			} `json:"AwsEcsTaskDefinition"`
//			AwsElasticBeanstalkEnvironment struct {
//				ApplicationName  string `json:"ApplicationName"`
//				Cname            string `json:"Cname"`
//				DateCreated      string `json:"DateCreated"`
//				DateUpdated      string `json:"DateUpdated"`
//				Description      string `json:"Description"`
//				EndpointUrl      string `json:"EndpointUrl"`
//				EnvironmentArn   string `json:"EnvironmentArn"`
//				EnvironmentId    string `json:"EnvironmentId"`
//				EnvironmentLinks []struct {
//					EnvironmentName string `json:"EnvironmentName"`
//					LinkName        string `json:"LinkName"`
//				} `json:"EnvironmentLinks"`
//				EnvironmentName string `json:"EnvironmentName"`
//				OptionSettings  []struct {
//					Namespace    string `json:"Namespace"`
//					OptionName   string `json:"OptionName"`
//					ResourceName string `json:"ResourceName"`
//					Value        string `json:"Value"`
//				} `json:"OptionSettings"`
//				PlatformArn       string `json:"PlatformArn"`
//				SolutionStackName string `json:"SolutionStackName"`
//				Status            string `json:"Status"`
//				Tier              struct {
//					Name    string `json:"Name"`
//					Type    string `json:"Type"`
//					Version string `json:"Version"`
//				} `json:"Tier"`
//				VersionLabel string `json:"VersionLabel"`
//			} `json:"AwsElasticBeanstalkEnvironment"`
//			AwsElasticSearchDomain struct {
//				AccessPolicies string `json:"AccessPolicies"`
//				DomainStatus   struct {
//					DomainId   string `json:"DomainId"`
//					DomainName string `json:"DomainName"`
//					Endpoint   string `json:"Endpoint"`
//					Endpoints  struct {
//						String string `json:"string"`
//					} `json:"Endpoints"`
//				} `json:"DomainStatus"`
//				DomainEndpointOptions struct {
//					EnforceHTTPS      interface{} `json:"EnforceHTTPS"`
//					TLSSecurityPolicy string      `json:"TLSSecurityPolicy"`
//				} `json:"DomainEndpointOptions"`
//				ElasticsearchClusterConfig struct {
//					DedicatedMasterCount   interface{} `json:"DedicatedMasterCount"`
//					DedicatedMasterEnabled interface{} `json:"DedicatedMasterEnabled"`
//					DedicatedMasterType    string      `json:"DedicatedMasterType"`
//					InstanceCount          interface{} `json:"InstanceCount"`
//					InstanceType           string      `json:"InstanceType"`
//					ZoneAwarenessConfig    struct {
//						AvailabilityZoneCount interface{} `json:"AvailabilityZoneCount"`
//					} `json:"ZoneAwarenessConfig"`
//					ZoneAwarenessEnabled interface{} `json:"ZoneAwarenessEnabled"`
//				} `json:"ElasticsearchClusterConfig"`
//				ElasticsearchVersion    string `json:"ElasticsearchVersion"`
//				EncryptionAtRestOptions struct {
//					Enabled  interface{} `json:"Enabled"`
//					KmsKeyId string      `json:"KmsKeyId"`
//				} `json:"EncryptionAtRestOptions"`
//				LogPublishingOptions struct {
//					AuditLogs struct {
//						CloudWatchLogsLogGroupArn string      `json:"CloudWatchLogsLogGroupArn"`
//						Enabled                   interface{} `json:"Enabled"`
//					} `json:"AuditLogs"`
//					IndexSlowLogs struct {
//						CloudWatchLogsLogGroupArn string      `json:"CloudWatchLogsLogGroupArn"`
//						Enabled                   interface{} `json:"Enabled"`
//					} `json:"IndexSlowLogs"`
//					SearchSlowLogs struct {
//						CloudWatchLogsLogGroupArn string      `json:"CloudWatchLogsLogGroupArn"`
//						Enabled                   interface{} `json:"Enabled"`
//					} `json:"SearchSlowLogs"`
//				} `json:"LogPublishingOptions"`
//				NodeToNodeEncryptionOptions struct {
//					Enabled interface{} `json:"Enabled"`
//				} `json:"NodeToNodeEncryptionOptions"`
//				ServiceSoftwareOptions struct {
//					AutomatedUpdateDate string      `json:"AutomatedUpdateDate"`
//					Cancellable         interface{} `json:"Cancellable"`
//					CurrentVersion      string      `json:"CurrentVersion"`
//					Description         string      `json:"Description"`
//					NewVersion          string      `json:"NewVersion"`
//					UpdateAvailable     interface{} `json:"UpdateAvailable"`
//					UpdateStatus        string      `json:"UpdateStatus"`
//				} `json:"ServiceSoftwareOptions"`
//				VPCOptions struct {
//					AvailabilityZones []string `json:"AvailabilityZones"`
//					SecurityGroupIds  []string `json:"SecurityGroupIds"`
//					SubnetIds         []string `json:"SubnetIds"`
//					VPCId             string   `json:"VPCId"`
//				} `json:"VPCOptions"`
//			} `json:"AwsElasticSearchDomain"`
//			AwsElbLoadBalancer struct {
//				AvailabilityZones         []string `json:"AvailabilityZones"`
//				BackendServerDescriptions []struct {
//					InstancePort interface{} `json:"InstancePort"`
//					PolicyNames  []string    `json:"PolicyNames"`
//				} `json:"BackendServerDescriptions"`
//				CanonicalHostedZoneName   string `json:"CanonicalHostedZoneName"`
//				CanonicalHostedZoneNameID string `json:"CanonicalHostedZoneNameID"`
//				CreatedTime               string `json:"CreatedTime"`
//				DnsName                   string `json:"DnsName"`
//				HealthCheck               struct {
//					HealthyThreshold   interface{} `json:"HealthyThreshold"`
//					Interval           interface{} `json:"Interval"`
//					Target             string      `json:"Target"`
//					Timeout            interface{} `json:"Timeout"`
//					UnhealthyThreshold interface{} `json:"UnhealthyThreshold"`
//				} `json:"HealthCheck"`
//				Instances []struct {
//					InstanceId string `json:"InstanceId"`
//				} `json:"Instances"`
//				ListenerDescriptions []struct {
//					Listener struct {
//						InstancePort     interface{} `json:"InstancePort"`
//						InstanceProtocol string      `json:"InstanceProtocol"`
//						LoadBalancerPort interface{} `json:"LoadBalancerPort"`
//						Protocol         string      `json:"Protocol"`
//						SslCertificateId string      `json:"SslCertificateId"`
//					} `json:"Listener"`
//					PolicyNames []string `json:"PolicyNames"`
//				} `json:"ListenerDescriptions"`
//				LoadBalancerAttributes struct {
//					AccessLog struct {
//						EmitInterval   interface{} `json:"EmitInterval"`
//						Enabled        interface{} `json:"Enabled"`
//						S3BucketName   string      `json:"S3BucketName"`
//						S3BucketPrefix string      `json:"S3BucketPrefix"`
//					} `json:"AccessLog"`
//					ConnectionDraining struct {
//						Enabled interface{} `json:"Enabled"`
//						Timeout interface{} `json:"Timeout"`
//					} `json:"ConnectionDraining"`
//					ConnectionSettings struct {
//						IdleTimeout interface{} `json:"IdleTimeout"`
//					} `json:"ConnectionSettings"`
//					CrossZoneLoadBalancing struct {
//						Enabled interface{} `json:"Enabled"`
//					} `json:"CrossZoneLoadBalancing"`
//				} `json:"LoadBalancerAttributes"`
//				LoadBalancerName string `json:"LoadBalancerName"`
//				Policies         struct {
//					AppCookieStickinessPolicies []struct {
//						CookieName string `json:"CookieName"`
//						PolicyName string `json:"PolicyName"`
//					} `json:"AppCookieStickinessPolicies"`
//					LbCookieStickinessPolicies []struct {
//						CookieExpirationPeriod interface{} `json:"CookieExpirationPeriod"`
//						PolicyName             string      `json:"PolicyName"`
//					} `json:"LbCookieStickinessPolicies"`
//					OtherPolicies []string `json:"OtherPolicies"`
//				} `json:"Policies"`
//				Scheme              string   `json:"Scheme"`
//				SecurityGroups      []string `json:"SecurityGroups"`
//				SourceSecurityGroup struct {
//					GroupName  string `json:"GroupName"`
//					OwnerAlias string `json:"OwnerAlias"`
//				} `json:"SourceSecurityGroup"`
//				Subnets []string `json:"Subnets"`
//				VpcId   string   `json:"VpcId"`
//			} `json:"AwsElbLoadBalancer"`
//			AwsElbv2LoadBalancer struct {
//				AvailabilityZones struct {
//					SubnetId string `json:"SubnetId"`
//					ZoneName string `json:"ZoneName"`
//				} `json:"AvailabilityZones"`
//				CanonicalHostedZoneId string   `json:"CanonicalHostedZoneId"`
//				CreatedTime           string   `json:"CreatedTime"`
//				DNSName               string   `json:"DNSName"`
//				IpAddressType         string   `json:"IpAddressType"`
//				Scheme                string   `json:"Scheme"`
//				SecurityGroups        []string `json:"SecurityGroups"`
//				State                 struct {
//					Code   string `json:"Code"`
//					Reason string `json:"Reason"`
//				} `json:"State"`
//				Type  string `json:"Type"`
//				VpcId string `json:"VpcId"`
//			} `json:"AwsElbv2LoadBalancer"`
//			AwsIamAccessKey struct {
//				AccessKeyId    string `json:"AccessKeyId"`
//				AccountId      string `json:"AccountId"`
//				CreatedAt      string `json:"CreatedAt"`
//				PrincipalId    string `json:"PrincipalId"`
//				PrincipalName  string `json:"PrincipalName"`
//				PrincipalType  string `json:"PrincipalType"`
//				SessionContext struct {
//					Attributes struct {
//						CreationDate     string      `json:"CreationDate"`
//						MfaAuthenticated interface{} `json:"MfaAuthenticated"`
//					} `json:"Attributes"`
//					SessionIssuer struct {
//						AccountId   string `json:"AccountId"`
//						Arn         string `json:"Arn"`
//						PrincipalId string `json:"PrincipalId"`
//						Type        string `json:"Type"`
//						UserName    string `json:"UserName"`
//					} `json:"SessionIssuer"`
//				} `json:"SessionContext"`
//				Status string `json:"Status"`
//			} `json:"AwsIamAccessKey"`
//			AwsIamGroup struct {
//				AttachedManagedPolicies []struct {
//					PolicyArn  string `json:"PolicyArn"`
//					PolicyName string `json:"PolicyName"`
//				} `json:"AttachedManagedPolicies"`
//				CreateDate      string `json:"CreateDate"`
//				GroupId         string `json:"GroupId"`
//				GroupName       string `json:"GroupName"`
//				GroupPolicyList []struct {
//					PolicyName string `json:"PolicyName"`
//				} `json:"GroupPolicyList"`
//				Path string `json:"Path"`
//			} `json:"AwsIamGroup"`
//			AwsIamPolicy struct {
//				AttachmentCount               interface{} `json:"AttachmentCount"`
//				CreateDate                    string      `json:"CreateDate"`
//				DefaultVersionId              string      `json:"DefaultVersionId"`
//				Description                   string      `json:"Description"`
//				IsAttachable                  interface{} `json:"IsAttachable"`
//				Path                          string      `json:"Path"`
//				PermissionsBoundaryUsageCount interface{} `json:"PermissionsBoundaryUsageCount"`
//				PolicyId                      string      `json:"PolicyId"`
//				PolicyName                    string      `json:"PolicyName"`
//				PolicyVersionList             []struct {
//					CreateDate       string      `json:"CreateDate"`
//					IsDefaultVersion interface{} `json:"IsDefaultVersion"`
//					VersionId        string      `json:"VersionId"`
//				} `json:"PolicyVersionList"`
//				UpdateDate string `json:"UpdateDate"`
//			} `json:"AwsIamPolicy"`
//			AwsIamRole struct {
//				AssumeRolePolicyDocument string `json:"AssumeRolePolicyDocument"`
//				AttachedManagedPolicies  []struct {
//					PolicyArn  string `json:"PolicyArn"`
//					PolicyName string `json:"PolicyName"`
//				} `json:"AttachedManagedPolicies"`
//				CreateDate          string `json:"CreateDate"`
//				InstanceProfileList []struct {
//					Arn                 string `json:"Arn"`
//					CreateDate          string `json:"CreateDate"`
//					InstanceProfileId   string `json:"InstanceProfileId"`
//					InstanceProfileName string `json:"InstanceProfileName"`
//					Path                string `json:"Path"`
//					Roles               []struct {
//						Arn                      string `json:"Arn"`
//						AssumeRolePolicyDocument string `json:"AssumeRolePolicyDocument"`
//						CreateDate               string `json:"CreateDate"`
//						Path                     string `json:"Path"`
//						RoleId                   string `json:"RoleId"`
//						RoleName                 string `json:"RoleName"`
//					} `json:"Roles"`
//				} `json:"InstanceProfileList"`
//				MaxSessionDuration  interface{} `json:"MaxSessionDuration"`
//				Path                string      `json:"Path"`
//				PermissionsBoundary struct {
//					PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
//					PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
//				} `json:"PermissionsBoundary"`
//				RoleId         string `json:"RoleId"`
//				RoleName       string `json:"RoleName"`
//				RolePolicyList []struct {
//					PolicyName string `json:"PolicyName"`
//				} `json:"RolePolicyList"`
//			} `json:"AwsIamRole"`
//			AwsIamUser struct {
//				AttachedManagedPolicies []struct {
//					PolicyArn  string `json:"PolicyArn"`
//					PolicyName string `json:"PolicyName"`
//				} `json:"AttachedManagedPolicies"`
//				CreateDate          string   `json:"CreateDate"`
//				GroupList           []string `json:"GroupList"`
//				Path                string   `json:"Path"`
//				PermissionsBoundary struct {
//					PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
//					PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
//				} `json:"PermissionsBoundary"`
//				UserId         string `json:"UserId"`
//				UserName       string `json:"UserName"`
//				UserPolicyList []struct {
//					PolicyName string `json:"PolicyName"`
//				} `json:"UserPolicyList"`
//			} `json:"AwsIamUser"`
//			AwsKmsKey struct {
//				AWSAccountId string `json:"AWSAccountId"`
//				CreationDate string `json:"CreationDate"`
//				Description  string `json:"Description"`
//				KeyId        string `json:"KeyId"`
//				KeyManager   string `json:"KeyManager"`
//				KeyState     string `json:"KeyState"`
//				Origin       string `json:"Origin"`
//			} `json:"AwsKmsKey"`
//			AwsLambdaFunction struct {
//				Code struct {
//					S3Bucket        string `json:"S3Bucket"`
//					S3Key           string `json:"S3Key"`
//					S3ObjectVersion string `json:"S3ObjectVersion"`
//					ZipFile         string `json:"ZipFile"`
//				} `json:"Code"`
//				CodeSha256       string `json:"CodeSha256"`
//				DeadLetterConfig struct {
//					TargetArn string `json:"TargetArn"`
//				} `json:"DeadLetterConfig"`
//				Environment struct {
//					Variables struct {
//						String string `json:"string"`
//					} `json:"Variables"`
//					Error struct {
//						ErrorCode string `json:"ErrorCode"`
//						Message   string `json:"Message"`
//					} `json:"Error"`
//				} `json:"Environment"`
//				FunctionName string `json:"FunctionName"`
//				Handler      string `json:"Handler"`
//				KmsKeyArn    string `json:"KmsKeyArn"`
//				LastModified string `json:"LastModified"`
//				Layers       struct {
//					Arn      string      `json:"Arn"`
//					CodeSize interface{} `json:"CodeSize"`
//				} `json:"Layers"`
//				RevisionId    string `json:"RevisionId"`
//				Role          string `json:"Role"`
//				Runtime       string `json:"Runtime"`
//				Timeout       string `json:"Timeout"`
//				TracingConfig struct {
//					TracingConfigMode string `json:"TracingConfig.Mode"`
//				} `json:"TracingConfig"`
//				Version   string `json:"Version"`
//				VpcConfig struct {
//					SecurityGroupIds []string `json:"SecurityGroupIds"`
//					SubnetIds        []string `json:"SubnetIds"`
//				} `json:"VpcConfig"`
//				MasterArn  string      `json:"MasterArn"`
//				MemorySize interface{} `json:"MemorySize"`
//			} `json:"AwsLambdaFunction"`
//			AwsLambdaLayerVersion struct {
//				CompatibleRuntimes []string    `json:"CompatibleRuntimes"`
//				CreatedDate        string      `json:"CreatedDate"`
//				Version            interface{} `json:"Version"`
//			} `json:"AwsLambdaLayerVersion"`
//			AwsRdsDbCluster struct {
//				ActivityStreamStatus string      `json:"ActivityStreamStatus"`
//				AllocatedStorage     interface{} `json:"AllocatedStorage"`
//				AssociatedRoles      []struct {
//					RoleArn string `json:"RoleArn"`
//					Status  string `json:"Status"`
//				} `json:"AssociatedRoles"`
//				AvailabilityZones     []string    `json:"AvailabilityZones"`
//				BackupRetentionPeriod interface{} `json:"BackupRetentionPeriod"`
//				ClusterCreateTime     string      `json:"ClusterCreateTime"`
//				CopyTagsToSnapshot    interface{} `json:"CopyTagsToSnapshot"`
//				CrossAccountClone     interface{} `json:"CrossAccountClone"`
//				CustomEndpoints       []string    `json:"CustomEndpoints"`
//				DatabaseName          string      `json:"DatabaseName"`
//				DbClusterIdentifier   string      `json:"DbClusterIdentifier"`
//				DbClusterMembers      []struct {
//					DbClusterParameterGroupStatus string      `json:"DbClusterParameterGroupStatus"`
//					DbInstanceIdentifier          string      `json:"DbInstanceIdentifier"`
//					IsClusterWriter               interface{} `json:"IsClusterWriter"`
//					PromotionTier                 interface{} `json:"PromotionTier"`
//				} `json:"DbClusterMembers"`
//				DbClusterOptionGroupMemberships []struct {
//					DbClusterOptionGroupName string `json:"DbClusterOptionGroupName"`
//					Status                   string `json:"Status"`
//				} `json:"DbClusterOptionGroupMemberships"`
//				DbClusterParameterGroup string      `json:"DbClusterParameterGroup"`
//				DbClusterResourceId     string      `json:"DbClusterResourceId"`
//				DbSubnetGroup           string      `json:"DbSubnetGroup"`
//				DeletionProtection      interface{} `json:"DeletionProtection"`
//				DomainMemberships       []struct {
//					Domain      string `json:"Domain"`
//					Fqdn        string `json:"Fqdn"`
//					IamRoleName string `json:"IamRoleName"`
//					Status      string `json:"Status"`
//				} `json:"DomainMemberships"`
//				EnabledCloudwatchLogsExports     []string    `json:"EnabledCloudwatchLogsExports"`
//				Endpoint                         string      `json:"Endpoint"`
//				Engine                           string      `json:"Engine"`
//				EngineMode                       string      `json:"EngineMode"`
//				EngineVersion                    string      `json:"EngineVersion"`
//				HostedZoneId                     string      `json:"HostedZoneId"`
//				HttpEndpointEnabled              interface{} `json:"HttpEndpointEnabled"`
//				IamDatabaseAuthenticationEnabled interface{} `json:"IamDatabaseAuthenticationEnabled"`
//				KmsKeyId                         string      `json:"KmsKeyId"`
//				MasterUsername                   string      `json:"MasterUsername"`
//				MultiAz                          interface{} `json:"MultiAz"`
//				Port                             interface{} `json:"Port"`
//				PreferredBackupWindow            string      `json:"PreferredBackupWindow"`
//				PreferredMaintenanceWindow       string      `json:"PreferredMaintenanceWindow"`
//				ReaderEndpoint                   string      `json:"ReaderEndpoint"`
//				ReadReplicaIdentifiers           []string    `json:"ReadReplicaIdentifiers"`
//				Status                           string      `json:"Status"`
//				StorageEncrypted                 interface{} `json:"StorageEncrypted"`
//				VpcSecurityGroups                []struct {
//					Status             string `json:"Status"`
//					VpcSecurityGroupId string `json:"VpcSecurityGroupId"`
//				} `json:"VpcSecurityGroups"`
//			} `json:"AwsRdsDbCluster"`
//			AwsRdsDbClusterSnapshot struct {
//				AllocatedStorage                 interface{} `json:"AllocatedStorage"`
//				AvailabilityZones                []string    `json:"AvailabilityZones"`
//				ClusterCreateTime                string      `json:"ClusterCreateTime"`
//				DbClusterIdentifier              string      `json:"DbClusterIdentifier"`
//				DbClusterSnapshotIdentifier      string      `json:"DbClusterSnapshotIdentifier"`
//				Engine                           string      `json:"Engine"`
//				EngineVersion                    string      `json:"EngineVersion"`
//				IamDatabaseAuthenticationEnabled interface{} `json:"IamDatabaseAuthenticationEnabled"`
//				KmsKeyId                         string      `json:"KmsKeyId"`
//				LicenseModel                     string      `json:"LicenseModel"`
//				MasterUsername                   string      `json:"MasterUsername"`
//				PercentProgress                  interface{} `json:"PercentProgress"`
//				Port                             interface{} `json:"Port"`
//				SnapshotCreateTime               string      `json:"SnapshotCreateTime"`
//				SnapshotType                     string      `json:"SnapshotType"`
//				Status                           string      `json:"Status"`
//				StorageEncrypted                 interface{} `json:"StorageEncrypted"`
//				VpcId                            string      `json:"VpcId"`
//			} `json:"AwsRdsDbClusterSnapshot"`
//			AwsRdsDbInstance struct {
//				AllocatedStorage interface{} `json:"AllocatedStorage"`
//				AssociatedRoles  []struct {
//					RoleArn     string `json:"RoleArn"`
//					FeatureName string `json:"FeatureName"`
//					Status      string `json:"Status"`
//				} `json:"AssociatedRoles"`
//				AutoMinorVersionUpgrade interface{} `json:"AutoMinorVersionUpgrade"`
//				AvailabilityZone        string      `json:"AvailabilityZone"`
//				BackupRetentionPeriod   interface{} `json:"BackupRetentionPeriod"`
//				CACertificateIdentifier string      `json:"CACertificateIdentifier"`
//				CharacterSetName        string      `json:"CharacterSetName"`
//				CopyTagsToSnapshot      interface{} `json:"CopyTagsToSnapshot"`
//				DBClusterIdentifier     string      `json:"DBClusterIdentifier"`
//				DBInstanceClass         string      `json:"DBInstanceClass"`
//				DBInstanceIdentifier    string      `json:"DBInstanceIdentifier"`
//				DbInstancePort          interface{} `json:"DbInstancePort"`
//				DbInstanceStatus        string      `json:"DbInstanceStatus"`
//				DbiResourceId           string      `json:"DbiResourceId"`
//				DBName                  string      `json:"DBName"`
//				DbParameterGroups       []struct {
//					DbParameterGroupName string `json:"DbParameterGroupName"`
//					ParameterApplyStatus string `json:"ParameterApplyStatus"`
//				} `json:"DbParameterGroups"`
//				DbSecurityGroups []string `json:"DbSecurityGroups"`
//				DbSubnetGroup    struct {
//					DbSubnetGroupArn         string `json:"DbSubnetGroupArn"`
//					DbSubnetGroupDescription string `json:"DbSubnetGroupDescription"`
//					DbSubnetGroupName        string `json:"DbSubnetGroupName"`
//					SubnetGroupStatus        string `json:"SubnetGroupStatus"`
//					Subnets                  []struct {
//						SubnetAvailabilityZone struct {
//							Name string `json:"Name"`
//						} `json:"SubnetAvailabilityZone"`
//						SubnetIdentifier string `json:"SubnetIdentifier"`
//						SubnetStatus     string `json:"SubnetStatus"`
//					} `json:"Subnets"`
//					VpcId string `json:"VpcId"`
//				} `json:"DbSubnetGroup"`
//				DeletionProtection interface{} `json:"DeletionProtection"`
//				Endpoint           struct {
//					Address      string      `json:"Address"`
//					Port         interface{} `json:"Port"`
//					HostedZoneId string      `json:"HostedZoneId"`
//				} `json:"Endpoint"`
//				DomainMemberships []struct {
//					Domain      string `json:"Domain"`
//					Fqdn        string `json:"Fqdn"`
//					IamRoleName string `json:"IamRoleName"`
//					Status      string `json:"Status"`
//				} `json:"DomainMemberships"`
//				EnabledCloudwatchLogsExports     []string    `json:"EnabledCloudwatchLogsExports"`
//				Engine                           string      `json:"Engine"`
//				EngineVersion                    string      `json:"EngineVersion"`
//				EnhancedMonitoringResourceArn    string      `json:"EnhancedMonitoringResourceArn"`
//				IAMDatabaseAuthenticationEnabled interface{} `json:"IAMDatabaseAuthenticationEnabled"`
//				InstanceCreateTime               string      `json:"InstanceCreateTime"`
//				Iops                             interface{} `json:"Iops"`
//				KmsKeyId                         string      `json:"KmsKeyId"`
//				LatestRestorableTime             string      `json:"LatestRestorableTime"`
//				LicenseModel                     string      `json:"LicenseModel"`
//				ListenerEndpoint                 struct {
//					Address      string      `json:"Address"`
//					HostedZoneId string      `json:"HostedZoneId"`
//					Port         interface{} `json:"Port"`
//				} `json:"ListenerEndpoint"`
//				MasterUsername         string      `json:"MasterUsername"`
//				MaxAllocatedStorage    interface{} `json:"MaxAllocatedStorage"`
//				MonitoringInterval     interface{} `json:"MonitoringInterval"`
//				MonitoringRoleArn      string      `json:"MonitoringRoleArn"`
//				MultiAz                interface{} `json:"MultiAz"`
//				OptionGroupMemberships []struct {
//					OptionGroupName string `json:"OptionGroupName"`
//					Status          string `json:"Status"`
//				} `json:"OptionGroupMemberships"`
//				PendingModifiedValues struct {
//					AllocatedStorage             interface{} `json:"AllocatedStorage"`
//					BackupRetentionPeriod        interface{} `json:"BackupRetentionPeriod"`
//					CaCertificateIdentifier      string      `json:"CaCertificateIdentifier"`
//					DbInstanceClass              string      `json:"DbInstanceClass"`
//					DbInstanceIdentifier         string      `json:"DbInstanceIdentifier"`
//					DbSubnetGroupName            string      `json:"DbSubnetGroupName"`
//					EngineVersion                string      `json:"EngineVersion"`
//					Iops                         interface{} `json:"Iops"`
//					LicenseModel                 string      `json:"LicenseModel"`
//					MasterUserPassword           string      `json:"MasterUserPassword"`
//					MultiAZ                      interface{} `json:"MultiAZ"`
//					PendingCloudWatchLogsExports struct {
//						LogTypesToDisable []string `json:"LogTypesToDisable"`
//						LogTypesToEnable  []string `json:"LogTypesToEnable"`
//					} `json:"PendingCloudWatchLogsExports"`
//					Port              interface{} `json:"Port"`
//					ProcessorFeatures []struct {
//						Name  string `json:"Name"`
//						Value string `json:"Value"`
//					} `json:"ProcessorFeatures"`
//					StorageType string `json:"StorageType"`
//				} `json:"PendingModifiedValues"`
//				PerformanceInsightsEnabled         interface{} `json:"PerformanceInsightsEnabled"`
//				PerformanceInsightsKmsKeyId        string      `json:"PerformanceInsightsKmsKeyId"`
//				PerformanceInsightsRetentionPeriod interface{} `json:"PerformanceInsightsRetentionPeriod"`
//				PreferredBackupWindow              string      `json:"PreferredBackupWindow"`
//				PreferredMaintenanceWindow         string      `json:"PreferredMaintenanceWindow"`
//				ProcessorFeatures                  []struct {
//					Name  string `json:"Name"`
//					Value string `json:"Value"`
//				} `json:"ProcessorFeatures"`
//				PromotionTier                         interface{} `json:"PromotionTier"`
//				PubliclyAccessible                    interface{} `json:"PubliclyAccessible"`
//				ReadReplicaDBClusterIdentifiers       []string    `json:"ReadReplicaDBClusterIdentifiers"`
//				ReadReplicaDBInstanceIdentifiers      []string    `json:"ReadReplicaDBInstanceIdentifiers"`
//				ReadReplicaSourceDBInstanceIdentifier string      `json:"ReadReplicaSourceDBInstanceIdentifier"`
//				SecondaryAvailabilityZone             string      `json:"SecondaryAvailabilityZone"`
//				StatusInfos                           []struct {
//					Message    string      `json:"Message"`
//					Normal     interface{} `json:"Normal"`
//					Status     string      `json:"Status"`
//					StatusType string      `json:"StatusType"`
//				} `json:"StatusInfos"`
//				StorageEncrypted  interface{} `json:"StorageEncrypted"`
//				TdeCredentialArn  string      `json:"TdeCredentialArn"`
//				Timezone          string      `json:"Timezone"`
//				VpcSecurityGroups []struct {
//					VpcSecurityGroupId string `json:"VpcSecurityGroupId"`
//					Status             string `json:"Status"`
//				} `json:"VpcSecurityGroups"`
//			} `json:"AwsRdsDbInstance"`
//			AwsRdsDbSnapshot struct {
//				AllocatedStorage                 interface{}   `json:"AllocatedStorage"`
//				AvailabilityZone                 string        `json:"AvailabilityZone"`
//				DbInstanceIdentifier             string        `json:"DbInstanceIdentifier"`
//				DbiResourceId                    string        `json:"DbiResourceId"`
//				DbSnapshotIdentifier             string        `json:"DbSnapshotIdentifier"`
//				Encrypted                        interface{}   `json:"Encrypted"`
//				Engine                           string        `json:"Engine"`
//				EngineVersion                    string        `json:"EngineVersion"`
//				IamDatabaseAuthenticationEnabled interface{}   `json:"IamDatabaseAuthenticationEnabled"`
//				InstanceCreateTime               string        `json:"InstanceCreateTime"`
//				Iops                             interface{}   `json:"Iops"`
//				KmsKeyId                         string        `json:"KmsKeyId"`
//				LicenseModel                     string        `json:"LicenseModel"`
//				MasterUsername                   string        `json:"MasterUsername"`
//				OptionGroupName                  string        `json:"OptionGroupName"`
//				PercentProgress                  interface{}   `json:"PercentProgress"`
//				Port                             interface{}   `json:"Port"`
//				ProcessorFeatures                []interface{} `json:"ProcessorFeatures"`
//				SnapshotCreateTime               string        `json:"SnapshotCreateTime"`
//				SnapshotType                     string        `json:"SnapshotType"`
//				SourceDbSnapshotIdentifier       string        `json:"SourceDbSnapshotIdentifier"`
//				SourceRegion                     string        `json:"SourceRegion"`
//				Status                           string        `json:"Status"`
//				StorageType                      string        `json:"StorageType"`
//				TdeCredentialArn                 string        `json:"TdeCredentialArn"`
//				Timezone                         string        `json:"Timezone"`
//				VpcId                            string        `json:"VpcId"`
//			} `json:"AwsRdsDbSnapshot"`
//			AwsRdsEventSubscription struct {
//				CustomerAwsId            string      `json:"CustomerAwsId"`
//				CustSubscriptionId       string      `json:"CustSubscriptionId"`
//				Enabled                  interface{} `json:"Enabled"`
//				EventCategoriesList      []string    `json:"EventCategoriesList"`
//				EventSubscriptionArn     string      `json:"EventSubscriptionArn"`
//				SnsTopicArn              string      `json:"SnsTopicArn"`
//				SourceIdsList            []string    `json:"SourceIdsList"`
//				SourceType               string      `json:"SourceType"`
//				Status                   string      `json:"Status"`
//				SubscriptionCreationTime string      `json:"SubscriptionCreationTime"`
//			} `json:"AwsRdsEventSubscription"`
//			AwsRedshiftCluster struct {
//				AllowVersionUpgrade              interface{} `json:"AllowVersionUpgrade"`
//				AutomatedSnapshotRetentionPeriod interface{} `json:"AutomatedSnapshotRetentionPeriod"`
//				AvailabilityZone                 string      `json:"AvailabilityZone"`
//				ClusterAvailabilityStatus        string      `json:"ClusterAvailabilityStatus"`
//				ClusterCreateTime                string      `json:"ClusterCreateTime"`
//				ClusterIdentifier                string      `json:"ClusterIdentifier"`
//				ClusterNodes                     []struct {
//					NodeRole         string `json:"NodeRole"`
//					PrivateIPAddress string `json:"PrivateIPAddress"`
//					PublicIPAddress  string `json:"PublicIPAddress"`
//				} `json:"ClusterNodes"`
//				ClusterParameterGroups []struct {
//					ClusterParameterStatusList []struct {
//						ParameterApplyErrorDescription string `json:"ParameterApplyErrorDescription"`
//						ParameterApplyStatus           string `json:"ParameterApplyStatus"`
//						ParameterName                  string `json:"ParameterName"`
//					} `json:"ClusterParameterStatusList"`
//					ParameterApplyStatus string `json:"ParameterApplyStatus"`
//					ParameterGroupName   string `json:"ParameterGroupName"`
//				} `json:"ClusterParameterGroups"`
//				ClusterPublicKey      string `json:"ClusterPublicKey"`
//				ClusterRevisionNumber string `json:"ClusterRevisionNumber"`
//				ClusterSecurityGroups []struct {
//					ClusterSecurityGroupName string `json:"ClusterSecurityGroupName"`
//					Status                   string `json:"Status"`
//				} `json:"ClusterSecurityGroups"`
//				ClusterSnapshotCopyStatus struct {
//					DestinationRegion             string      `json:"DestinationRegion"`
//					ManualSnapshotRetentionPeriod interface{} `json:"ManualSnapshotRetentionPeriod"`
//					RetentionPeriod               interface{} `json:"RetentionPeriod"`
//					SnapshotCopyGrantName         string      `json:"SnapshotCopyGrantName"`
//				} `json:"ClusterSnapshotCopyStatus"`
//				ClusterStatus              string `json:"ClusterStatus"`
//				ClusterSubnetGroupName     string `json:"ClusterSubnetGroupName"`
//				ClusterVersion             string `json:"ClusterVersion"`
//				DBName                     string `json:"DBName"`
//				DeferredMaintenanceWindows []struct {
//					DeferMaintenanceEndTime    string `json:"DeferMaintenanceEndTime"`
//					DeferMaintenanceIdentifier string `json:"DeferMaintenanceIdentifier"`
//					DeferMaintenanceStartTime  string `json:"DeferMaintenanceStartTime"`
//				} `json:"DeferredMaintenanceWindows"`
//				ElasticIpStatus struct {
//					ElasticIp string `json:"ElasticIp"`
//					Status    string `json:"Status"`
//				} `json:"ElasticIpStatus"`
//				ElasticResizeNumberOfNodeOptions string      `json:"ElasticResizeNumberOfNodeOptions"`
//				Encrypted                        interface{} `json:"Encrypted"`
//				Endpoint                         struct {
//					Address string      `json:"Address"`
//					Port    interface{} `json:"Port"`
//				} `json:"Endpoint"`
//				EnhancedVpcRouting                     interface{} `json:"EnhancedVpcRouting"`
//				ExpectedNextSnapshotScheduleTime       string      `json:"ExpectedNextSnapshotScheduleTime"`
//				ExpectedNextSnapshotScheduleTimeStatus string      `json:"ExpectedNextSnapshotScheduleTimeStatus"`
//				HsmStatus                              struct {
//					HsmClientCertificateIdentifier string `json:"HsmClientCertificateIdentifier"`
//					HsmConfigurationIdentifier     string `json:"HsmConfigurationIdentifier"`
//					Status                         string `json:"Status"`
//				} `json:"HsmStatus"`
//				IamRoles []struct {
//					ApplyStatus string `json:"ApplyStatus"`
//					IamRoleArn  string `json:"IamRoleArn"`
//				} `json:"IamRoles"`
//				KmsKeyId                       string      `json:"KmsKeyId"`
//				MaintenanceTrackName           string      `json:"MaintenanceTrackName"`
//				ManualSnapshotRetentionPeriod  string      `json:"ManualSnapshotRetentionPeriod"`
//				MasterUsername                 string      `json:"MasterUsername"`
//				NextMaintenanceWindowStartTime string      `json:"NextMaintenanceWindowStartTime"`
//				NodeType                       string      `json:"NodeType"`
//				NumberOfNodes                  interface{} `json:"NumberOfNodes"`
//				PendingActions                 []string    `json:"PendingActions"`
//				PendingModifiedValues          struct {
//					AutomatedSnapshotRetentionPeriod interface{} `json:"AutomatedSnapshotRetentionPeriod"`
//					ClusterIdentifier                string      `json:"ClusterIdentifier"`
//					ClusterType                      string      `json:"ClusterType"`
//					ClusterVersion                   string      `json:"ClusterVersion"`
//					EncryptionType                   string      `json:"EncryptionType"`
//					EnhancedVpcRouting               interface{} `json:"EnhancedVpcRouting"`
//					MaintenanceTrackName             string      `json:"MaintenanceTrackName"`
//					MasterUserPassword               string      `json:"MasterUserPassword"`
//					NodeType                         string      `json:"NodeType"`
//					NumberOfNodes                    interface{} `json:"NumberOfNodes"`
//					PubliclyAccessible               string      `json:"PubliclyAccessible"`
//				} `json:"PendingModifiedValues"`
//				PreferredMaintenanceWindow string      `json:"PreferredMaintenanceWindow"`
//				PubliclyAccessible         interface{} `json:"PubliclyAccessible"`
//				ResizeInfo                 struct {
//					AllowCancelResize interface{} `json:"AllowCancelResize"`
//					ResizeType        string      `json:"ResizeType"`
//				} `json:"ResizeInfo"`
//				RestoreStatus struct {
//					CurrentRestoreRateInMegaBytesPerSecond interface{} `json:"CurrentRestoreRateInMegaBytesPerSecond"`
//					ElapsedTimeInSeconds                   interface{} `json:"ElapsedTimeInSeconds"`
//					EstimatedTimeToCompletionInSeconds     interface{} `json:"EstimatedTimeToCompletionInSeconds"`
//					ProgressInMegaBytes                    interface{} `json:"ProgressInMegaBytes"`
//					SnapshotSizeInMegaBytes                interface{} `json:"SnapshotSizeInMegaBytes"`
//					Status                                 string      `json:"Status"`
//				} `json:"RestoreStatus"`
//				SnapshotScheduleIdentifier string `json:"SnapshotScheduleIdentifier"`
//				SnapshotScheduleState      string `json:"SnapshotScheduleState"`
//				VpcId                      string `json:"VpcId"`
//				VpcSecurityGroups          []struct {
//					Status             string `json:"Status"`
//					VpcSecurityGroupId string `json:"VpcSecurityGroupId"`
//				} `json:"VpcSecurityGroups"`
//			} `json:"AwsRedshiftCluster"`
//			AwsS3AccountPublicAccessBlock struct {
//				BlockPublicAcls       interface{} `json:"BlockPublicAcls"`
//				BlockPublicPolicy     interface{} `json:"BlockPublicPolicy"`
//				IgnorePublicAcls      interface{} `json:"IgnorePublicAcls"`
//				RestrictPublicBuckets interface{} `json:"RestrictPublicBuckets"`
//			} `json:"AwsS3AccountPublicAccessBlock"`
//			AwsS3Bucket struct {
//				BucketLifecycleConfiguration struct {
//					Rules []struct {
//						AbortIncompleteMultipartUpload struct {
//							DaysAfterInitiation interface{} `json:"DaysAfterInitiation"`
//						} `json:"AbortIncompleteMultipartUpload"`
//						ExpirationDate            string      `json:"ExpirationDate"`
//						ExpirationInDays          interface{} `json:"ExpirationInDays"`
//						ExpiredObjectDeleteMarker interface{} `json:"ExpiredObjectDeleteMarker"`
//						Filter                    struct {
//							Predicate struct {
//								Operands []struct {
//									Prefix string `json:"Prefix,omitempty"`
//									Type   string `json:"Type"`
//									Tag    struct {
//										Key   string `json:"Key"`
//										Value string `json:"Value"`
//									} `json:"Tag,omitempty"`
//								} `json:"Operands"`
//								Type string `json:"Type"`
//							} `json:"Predicate"`
//						} `json:"Filter"`
//						Id                                string      `json:"Id"`
//						NoncurrentVersionExpirationInDays interface{} `json:"NoncurrentVersionExpirationInDays"`
//						NoncurrentVersionTransitions      []struct {
//							Days         interface{} `json:"Days"`
//							StorageClass string      `json:"StorageClass"`
//						} `json:"NoncurrentVersionTransitions"`
//						Prefix      string `json:"Prefix"`
//						Status      string `json:"Status"`
//						Transitions []struct {
//							Date         string      `json:"Date"`
//							Days         interface{} `json:"Days"`
//							StorageClass string      `json:"StorageClass"`
//						} `json:"Transitions"`
//					} `json:"Rules"`
//				} `json:"BucketLifecycleConfiguration"`
//				CreatedAt                      string `json:"CreatedAt"`
//				OwnerId                        string `json:"OwnerId"`
//				OwnerName                      string `json:"OwnerName"`
//				PublicAccessBlockConfiguration struct {
//					BlockPublicAcls       interface{} `json:"BlockPublicAcls"`
//					BlockPublicPolicy     interface{} `json:"BlockPublicPolicy"`
//					IgnorePublicAcls      interface{} `json:"IgnorePublicAcls"`
//					RestrictPublicBuckets interface{} `json:"RestrictPublicBuckets"`
//				} `json:"PublicAccessBlockConfiguration"`
//				ServerSideEncryptionConfiguration struct {
//					Rules []struct {
//						ApplyServerSideEncryptionByDefault struct {
//							KMSMasterKeyID string `json:"KMSMasterKeyID"`
//							SSEAlgorithm   string `json:"SSEAlgorithm"`
//						} `json:"ApplyServerSideEncryptionByDefault"`
//					} `json:"Rules"`
//				} `json:"ServerSideEncryptionConfiguration"`
//			} `json:"AwsS3Bucket"`
//			AwsS3Object struct {
//				ContentType          string `json:"ContentType"`
//				ETag                 string `json:"ETag"`
//				LastModified         string `json:"LastModified"`
//				ServerSideEncryption string `json:"ServerSideEncryption"`
//				SSEKMSKeyId          string `json:"SSEKMSKeyId"`
//				VersionId            string `json:"VersionId"`
//			} `json:"AwsS3Object"`
//			AwsSecretsManagerSecret struct {
//				Deleted                         interface{} `json:"Deleted"`
//				Description                     string      `json:"Description"`
//				KmsKeyId                        string      `json:"KmsKeyId"`
//				Name                            string      `json:"Name"`
//				RotationEnabled                 interface{} `json:"RotationEnabled"`
//				RotationLambdaArn               string      `json:"RotationLambdaArn"`
//				RotationOccurredWithinFrequency interface{} `json:"RotationOccurredWithinFrequency"`
//				RotationRules                   struct {
//					AutomaticallyAfterDays interface{} `json:"AutomaticallyAfterDays"`
//				} `json:"RotationRules"`
//			} `json:"AwsSecretsManagerSecret"`
//			AwsSsmPatchCompliance struct {
//				Patch struct {
//					ComplianceSummary struct {
//						ComplianceType                 string      `json:"ComplianceType"`
//						CompliantCriticalCount         interface{} `json:"CompliantCriticalCount"`
//						CompliantHighCount             interface{} `json:"CompliantHighCount"`
//						CompliantInformationalCount    interface{} `json:"CompliantInformationalCount"`
//						CompliantLowCount              interface{} `json:"CompliantLowCount"`
//						CompliantMediumCount           interface{} `json:"CompliantMediumCount"`
//						CompliantUnspecifiedCount      interface{} `json:"CompliantUnspecifiedCount"`
//						ExecutionType                  string      `json:"ExecutionType"`
//						NonCompliantCriticalCount      interface{} `json:"NonCompliantCriticalCount"`
//						NonCompliantHighCount          interface{} `json:"NonCompliantHighCount"`
//						NonCompliantInformationalCount interface{} `json:"NonCompliantInformationalCount"`
//						NonCompliantLowCount           interface{} `json:"NonCompliantLowCount"`
//						NonCompliantMediumCount        interface{} `json:"NonCompliantMediumCount"`
//						NonCompliantUnspecifiedCount   interface{} `json:"NonCompliantUnspecifiedCount"`
//						OverallSeverity                string      `json:"OverallSeverity"`
//						PatchBaselineId                string      `json:"PatchBaselineId"`
//						PatchGroup                     string      `json:"PatchGroup"`
//						Status                         string      `json:"Status"`
//					} `json:"ComplianceSummary"`
//				} `json:"Patch"`
//			} `json:"AwsSsmPatchCompliance"`
//			AwsSnsTopic struct {
//				KmsMasterKeyId string `json:"KmsMasterKeyId"`
//				Owner          string `json:"Owner"`
//				Subscription   struct {
//					Endpoint string `json:"Endpoint"`
//					Protocol string `json:"Protocol"`
//				} `json:"Subscription"`
//				TopicName string `json:"TopicName"`
//			} `json:"AwsSnsTopic"`
//			AwsSqsQueue struct {
//				DeadLetterTargetArn          string      `json:"DeadLetterTargetArn"`
//				KmsDataKeyReusePeriodSeconds interface{} `json:"KmsDataKeyReusePeriodSeconds"`
//				KmsMasterKeyId               string      `json:"KmsMasterKeyId"`
//				QueueName                    string      `json:"QueueName"`
//			} `json:"AwsSqsQueue"`
//			AwsWafWebAcl struct {
//				DefaultAction string `json:"DefaultAction"`
//				Name          string `json:"Name"`
//				Rules         []struct {
//					Action struct {
//						Type string `json:"Type"`
//					} `json:"Action"`
//					ExcludedRules []struct {
//						RuleId string `json:"RuleId"`
//					} `json:"ExcludedRules"`
//					OverrideAction struct {
//						Type string `json:"Type"`
//					} `json:"OverrideAction"`
//					Priority interface{} `json:"Priority"`
//					RuleId   string      `json:"RuleId"`
//					Type     string      `json:"Type"`
//				} `json:"Rules"`
//				WebAclId string `json:"WebAclId"`
//			} `json:"AwsWafWebAcl"`
//			Container struct {
//				ImageId    string `json:"ImageId"`
//				ImageName  string `json:"ImageName"`
//				LaunchedAt string `json:"LaunchedAt"`
//				Name       string `json:"Name"`
//			} `json:"Container"`
//			Other struct {
//				String string `json:"string"`
//			} `json:"Other"`
//		} `json:"Details"`
//		Id           string `json:"Id"`
//		Partition    string `json:"Partition"`
//		Region       string `json:"Region"`
//		ResourceRole string `json:"ResourceRole"`
//		Tags         struct {
//			String string `json:"string"`
//		} `json:"Tags"`
//		Type string `json:"Type"`
//	} `json:"Resources"`
//	SchemaVersion string `json:"SchemaVersion"`
//	Severity      struct {
//		Label      string      `json:"Label"`
//		Normalized interface{} `json:"Normalized"`
//		Original   string      `json:"Original"`
//		Product    interface{} `json:"Product"`
//	} `json:"Severity"`
//	SourceUrl             string `json:"SourceUrl"`
//	ThreatIntelIndicators []struct {
//		Category       string `json:"Category"`
//		LastObservedAt string `json:"LastObservedAt"`
//		Source         string `json:"Source"`
//		SourceUrl      string `json:"SourceUrl"`
//		Type           string `json:"Type"`
//		Value          string `json:"Value"`
//	} `json:"ThreatIntelIndicators"`
//	Title             string   `json:"Title"`
//	Types             []string `json:"Types"`
//	UpdatedAt         string   `json:"UpdatedAt"`
//	UserDefinedFields struct {
//		String string `json:"string"`
//	} `json:"UserDefinedFields"`
//	VerificationState string `json:"VerificationState"`
//	Workflow          struct {
//		Status string `json:"Status"`
//	} `json:"Workflow"`
//	WorkflowState   string `json:"WorkflowState"`
//	Vulnerabilities []struct {
//		Cvss []struct {
//			BaseScore  interface{} `json:"BaseScore"`
//			BaseVector string      `json:"BaseVector"`
//			Version    string      `json:"Version"`
//		} `json:"Cvss"`
//		Id                     string   `json:"Id"`
//		ReferenceUrls          []string `json:"ReferenceUrls"`
//		RelatedVulnerabilities []string `json:"RelatedVulnerabilities"`
//		Vendor                 struct {
//			Name            string `json:"Name"`
//			Url             string `json:"Url"`
//			VendorCreatedAt string `json:"VendorCreatedAt"`
//			VendorSeverity  string `json:"VendorSeverity"`
//			VendorUpdatedAt string `json:"VendorUpdatedAt"`
//		} `json:"Vendor"`
//		VulnerablePackages []struct {
//			Architecture string `json:"Architecture"`
//			Epoch        string `json:"Epoch"`
//			Name         string `json:"Name"`
//			Release      string `json:"Release"`
//			Version      string `json:"Version"`
//		} `json:"VulnerablePackages"`
//	} `json:"Vulnerabilities"`
//}
