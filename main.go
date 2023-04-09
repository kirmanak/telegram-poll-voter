package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
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
		return onClientConnected(client, logger, ctx)
	}); err != nil {
		panic(err)
	}
}

func onClientConnected(client *telegram.Client, logger *zap.Logger, ctx context.Context) error {
	logger.Info("Connected")
	if err := checkAuth(client, ctx, logger); err != nil {
		return err
	}
	if err := printSelf(client, ctx, logger); err != nil {
		return err
	}
	return nil
}

func printSelf(client *telegram.Client, ctx context.Context, logger *zap.Logger) error {
	self, err := client.Self(ctx)
	if err != nil {
		return err
	}
	logger.Sugar().Infow("Authenticated",
		"phone", self.Phone,
		"id", self.ID,
		"first_name", self.FirstName,
		"last_name", self.LastName,
		"username", self.Username,
	)
	return nil
}

func checkAuth(client *telegram.Client, ctx context.Context, logger *zap.Logger) error {
	authClient := client.Auth()
	authStatus, err := authClient.Status(ctx)
	if err != nil {
		return err
	}
	if !authStatus.Authorized {
		phone, ok := os.LookupEnv("PHONE")
		if !ok {
			return fmt.Errorf("not authorized and PHONE env var is not set")
		}
		logger.Info("Not authorized, starting auth flow with number", zap.String("phone", phone))
		flow := auth.NewFlow(
			termAuth{phone: phone},
			auth.SendCodeOptions{},
		)
		if err := flow.Run(ctx, authClient); err != nil {
			return err
		}
	} else {
		logger.Info("Already authorized")
	}
	return nil
}
