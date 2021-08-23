package main_test

import (
	collector "aws-security-hub/collector"
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

var (
	mux    *http.ServeMux
	server *httptest.Server
)

const (
	testListener = "https://jsonplaceholder.typicode.com/todos/1"
	testToken    = "someLogzioToken"
)

func TestConvertAwsEventToLogzioEventImported(t *testing.T) {
	var awsEvent collector.AwsSecurityHubEvent
	awsEventBytes := []byte(getSample("imported.json"))
	err := json.Unmarshal(awsEventBytes, &awsEvent)
	assert.NoError(t, err)
	logzioEvent, err := collector.ConvertAwsEventToLogzioEvent(awsEvent)
	assert.NoError(t, err)
	assert.NotNil(t, logzioEvent)
	assert.NotEmpty(t, logzioEvent.Timestamp)
	assert.Equal(t, awsEvent.Time, logzioEvent.Timestamp)
	assert.Equal(t, collector.LogzioType, logzioEvent.Type)
	assert.NotNil(t, logzioEvent.Event)
	assert.NotNil(t, logzioEvent.Event.Detail)
	details := awsEvent.Detail.(map[string]interface{})["findings"].([]interface{})
	assert.Equal(t, details[0], logzioEvent.Event.Detail.(collector.DetailImported).Findings)
}

func TestConvertAwsEventToLogzioEventCustom(t *testing.T) {
	var awsEvent collector.AwsSecurityHubEvent
	awsEventBytes := []byte(getSample("custom.json"))
	err := json.Unmarshal(awsEventBytes, &awsEvent)
	assert.NoError(t, err)
	logzioEvent, err := collector.ConvertAwsEventToLogzioEvent(awsEvent)
	assert.NoError(t, err)
	assert.NotNil(t, logzioEvent)
	assert.NotEmpty(t, logzioEvent.Timestamp)
	assert.Equal(t, awsEvent.Time, logzioEvent.Timestamp)
	assert.Equal(t, collector.LogzioType, logzioEvent.Type)
	assert.NotNil(t, logzioEvent.Event)
	assert.NotNil(t, logzioEvent.Event.Detail)
	assert.NotNil(t, logzioEvent.Event.Detail.(collector.DetailCustom).Findings)
	assert.Equal(t, "custom-action-name", logzioEvent.Event.Detail.(collector.DetailCustom).ActionName)
	assert.Equal(t, "description of the action", logzioEvent.Event.Detail.(collector.DetailCustom).ActionDescription)
	details := awsEvent.Detail.(map[string]interface{})["findings"].([]interface{})
	assert.Equal(t, details[0], logzioEvent.Event.Detail.(collector.DetailCustom).Findings)
}

func TestConvertAwsEventToLogzioEventInsight(t *testing.T) {
	var awsEvent collector.AwsSecurityHubEvent
	awsEventBytes := []byte(getSample("insight.json"))
	err := json.Unmarshal(awsEventBytes, &awsEvent)
	assert.NoError(t, err)
	logzioEvent, err := collector.ConvertAwsEventToLogzioEvent(awsEvent)
	assert.NoError(t, err)
	assert.NotNil(t, logzioEvent)
	assert.NotEmpty(t, logzioEvent.Timestamp)
	assert.Equal(t, awsEvent.Time, logzioEvent.Timestamp)
	assert.Equal(t, collector.LogzioType, logzioEvent.Type)
	assert.NotNil(t, logzioEvent.Event)
	assert.NotNil(t, logzioEvent.Event.Detail)
	assert.Equal(t, awsEvent.Detail.(map[string]interface{})["actionName"], logzioEvent.Event.Detail.(map[string]interface{})["actionName"])
	assert.Equal(t, awsEvent.Detail.(map[string]interface{})["actionDescription"], logzioEvent.Event.Detail.(map[string]interface{})["actionDescription"])
	assert.Equal(t, awsEvent.Detail.(map[string]interface{})["insightResults"], logzioEvent.Event.Detail.(map[string]interface{})["insightResults"])
}

func TestConvertAwsEventToLogzioEventCloudTrial(t *testing.T) {
	var awsEvent collector.AwsSecurityHubEvent
	awsEventBytes := []byte(getSample("cloudtrail.json"))
	err := json.Unmarshal(awsEventBytes, &awsEvent)
	assert.NoError(t, err)
	logzioEvent, err := collector.ConvertAwsEventToLogzioEvent(awsEvent)
	assert.NoError(t, err)
	assert.NotNil(t, logzioEvent)
	assert.NotEmpty(t, logzioEvent.Timestamp)
	assert.Equal(t, awsEvent.Time, logzioEvent.Timestamp)
	assert.Equal(t, collector.LogzioType, logzioEvent.Type)
	assert.NotNil(t, logzioEvent.Event)
	assert.NotNil(t, logzioEvent.Event.Detail)
	assert.Equal(t, awsEvent.Detail, logzioEvent.Event.Detail)
}

func TestHandleRequest(t *testing.T) {
	teardown, err := setupCollectorTest()
	defer teardown()
	if assert.NoError(t, err) {
		mux.HandleFunc("/todos/1", func(w http.ResponseWriter, r *http.Request) {
			assert.NotEmpty(t, r.Body)
			jsonBytes, _ := ioutil.ReadAll(r.Body)
			var target collector.LogzioEvent
			err = json.Unmarshal(jsonBytes, &target)
			assert.NoError(t, err)
			assert.NotEmpty(t, target)
			assert.NotEmpty(t, target.Timestamp)
			assert.Equal(t, collector.LogzioType, target.Type)
			assert.NotEmpty(t, target.Event)
			assert.Equal(t, collector.DetailTypeImported, target.Event.DetailType)
			assert.NotEmpty(t, target.Event.Detail)
		})
		var awsEvent collector.AwsSecurityHubEvent
		awsEventBytes := []byte(getSample("imported.json"))
		err = json.Unmarshal(awsEventBytes, &awsEvent)
		assert.NoError(t, err)
		os.Setenv(collector.EnvLogzioListener, testListener)
		os.Setenv(collector.EnvLogzioOperationsToken, testToken)
		err = collector.HandleRequest(context.Background(), awsEvent)
		assert.NoError(t, err)
	}
}

func getSample(path string) string {
	b, err := ioutil.ReadFile("samples/" + path)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func setupCollectorTest() (func(), error) {
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	return func() {
		server.Close()
	}, nil
}
