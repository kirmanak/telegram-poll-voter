package main

import (
	"context"
	"fmt"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"go.uber.org/zap"
	"os"
	"os/signal"
)

type Client struct {
	client *telegram.Client
	logger *zap.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

func NewClient() (*Client, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	options := telegram.Options{Logger: logger}
	client, err := telegram.ClientFromEnvironment(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	return &Client{
		client: client,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (c *Client) Stop() {
	_ = c.logger.Sync()
	c.cancel()
}

func (c *Client) Run() error {
	return c.client.Run(c.ctx, func(ctx context.Context) error {
		return c.onClientConnected()
	})

}

func (c *Client) onClientConnected() error {
	c.logger.Info("Connected")
	if err := c.checkAuth(); err != nil {
		return fmt.Errorf("failed to check auth: %w", err)
	}
	if err := c.printSelf(); err != nil {
		return fmt.Errorf("failed to print self: %w", err)
	}
	return nil
}

func (c *Client) printSelf() error {
	self, err := c.client.Self(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to get self: %w", err)
	}
	c.logger.Sugar().Infow("Authenticated",
		"phone", self.Phone,
		"id", self.ID,
		"first_name", self.FirstName,
		"last_name", self.LastName,
		"username", self.Username,
	)
	return nil
}

func (c *Client) checkAuth() error {
	authClient := c.client.Auth()
	authStatus, err := authClient.Status(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth status: %w", err)
	}
	if !authStatus.Authorized {
		phone, ok := os.LookupEnv("PHONE")
		if !ok {
			return fmt.Errorf("not authorized and PHONE env var is not set")
		}
		c.logger.Info("Not authorized, starting auth flow with number", zap.String("phone", phone))
		flow := auth.NewFlow(
			termAuth{phone: phone},
			auth.SendCodeOptions{},
		)
		if err := flow.Run(c.ctx, authClient); err != nil {
			return fmt.Errorf("failed to run auth flow: %w", err)
		}
	} else {
		c.logger.Info("Already authorized")
	}
	return nil
}
