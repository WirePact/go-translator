package go_translator

import "github.com/sirupsen/logrus"

func SetLogLevel(level logrus.Level) {
	logrus.SetLevel(level)
}
