package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
)

const (
	EnvLogzioOperationsToken = "LOGZIO_OPERATIONS_TOKEN"
	EnvLogzioListener        = "LOGZIO_LISTENER"
	EnvLogLevel              = "LOG_LEVEL"
)

func GetLogzioSecurityToken() (string, error) {
	token := os.Getenv(EnvLogzioOperationsToken)

	if len(token) == 0 {
		return "", fmt.Errorf("%s must be set", EnvLogzioOperationsToken)
	}

	return token, nil
}

func GetLogzioListener() (string, error) {
	listener := os.Getenv(EnvLogzioListener)

	if len(listener) == 0 {
		return "", fmt.Errorf("%s must be set", EnvLogzioListener)
	}

	return listener, nil
}

func GetLoggerLevel() logrus.Level {
	level := os.Getenv(EnvLogLevel)
	levelParsed, err := logrus.ParseLevel(level)
	if err != nil {
		return logrus.InfoLevel
	}

	return levelParsed
}
