package main

import (
	"context"
	"fmt"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/updates"
	updhook "github.com/gotd/td/telegram/updates/hook"
	"github.com/gotd/td/tg"
	"go.uber.org/zap"
	"os"
	"os/signal"
)

type Client struct {
	client         *telegram.Client
	log            *zap.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	updatesManager *updates.Manager
}

func NewClient() (*Client, error) {
	log, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	updatesManager := newUpdatesManager(log)
	options := telegram.Options{
		Logger:        log.Named("telegram"),
		UpdateHandler: updatesManager,
		Middlewares: []telegram.Middleware{
			updhook.UpdateHook(updatesManager.Handle),
		},
	}
	client, err := telegram.ClientFromEnvironment(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	return &Client{
		client:         client,
		log:            log.Named("client"),
		ctx:            ctx,
		cancel:         cancel,
		updatesManager: updatesManager,
	}, nil
}

func (c *Client) Stop() {
	_ = c.log.Sync()
	c.cancel()
}

func (c *Client) Run() error {
	return c.client.Run(c.ctx, func(ctx context.Context) error {
		return c.onClientConnected()
	})
}

func (c *Client) onClientConnected() error {
	c.log.Info("Connected")
	if err := c.checkAuth(); err != nil {
		return fmt.Errorf("failed to check auth: %w", err)
	}
	self, err := c.printSelf()
	if err != nil {
		return fmt.Errorf("failed to print self: %w", err)
	}
	if err := c.updatesManager.Auth(c.ctx, c.client.API(), self.ID, self.Bot, true); err != nil {
		return fmt.Errorf("failed to auth updates manager: %w", err)
	}
	defer func() {
		if err := c.updatesManager.Logout(); err != nil {
			c.log.Error("Failed to stop updates manager", zap.Error(err))
		}
	}()
	<-c.ctx.Done()
	return c.ctx.Err()
}

func (c *Client) printSelf() (*tg.User, error) {
	self, err := c.client.Self(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get self: %w", err)
	}
	c.log.Sugar().Infow("Authenticated",
		"phone", self.Phone,
		"id", self.ID,
		"first_name", self.FirstName,
		"last_name", self.LastName,
		"username", self.Username,
	)
	return self, nil
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
		c.log.Info("Not authorized, starting auth flow with number", zap.String("phone", phone))
		flow := auth.NewFlow(
			termAuth{phone: phone},
			auth.SendCodeOptions{},
		)
		if err := flow.Run(c.ctx, authClient); err != nil {
			return fmt.Errorf("failed to run auth flow: %w", err)
		}
	} else {
		c.log.Info("Already authorized")
	}
	return nil
}

func newUpdatesManager(log *zap.Logger) *updates.Manager {
	updateDispatcher := tg.NewUpdateDispatcher()
	updateDispatcher.OnNewChannelMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewChannelMessage) error {
		log.Info("New channel message", zap.Any("message", update.Message))
		return nil
	})
	return updates.New(updates.Config{
		Handler: updateDispatcher,
		Logger:  log.Named("updates"),
	})
}
