package main

import (
	"context"
	"github.com/gotd/td/telegram"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer func() { _ = logger.Sync() }()
	options := telegram.Options{Logger: logger}
	client, err := telegram.ClientFromEnvironment(options)
	if err != nil {
		panic(err)
	}
	if err := client.Run(context.Background(), func(ctx context.Context) error {
		return onClientConnected(client, logger)
	}); err != nil {
		panic(err)
	}
}

func onClientConnected(client *telegram.Client, logger *zap.Logger) error {
	logger.Info("Connected")
	return nil
}
