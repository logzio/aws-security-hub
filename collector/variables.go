package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
)

const (
	envLogzioSecurityToken = "LOGZIO_OPERATIONS_TOKEN"
	envLogzioListener = "LOGZIO_LISTENER"
	envLogLevel = "LOG_LEVEL"
)

func GetLogzioSecurityToken() (string, error) {
	token := os.Getenv(envLogzioSecurityToken)

	if len(token) == 0 {
		return "", fmt.Errorf("%s must be set", envLogzioSecurityToken)
	}

	return token, nil
}

func GetLogzioListener() (string, error) {
	listener := os.Getenv(envLogzioListener)

	if len(listener) == 0 {
		return "", fmt.Errorf("%s must be set", envLogzioListener)
	}

	return listener, nil
}

func GetLoggerLevel() logrus.Level {
	level := os.Getenv(envLogLevel)
	levelParsed, err := logrus.ParseLevel(level)
	if err != nil {
		return logrus.InfoLevel
	}

	return levelParsed
}