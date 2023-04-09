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
	messages_chan  chan tg.NotEmptyMessage
}

func NewClient() (*Client, error) {
	log, err := zap.NewDevelopment()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	messages_chan := make(chan tg.NotEmptyMessage)
	updatesManager := newUpdatesManager(log, messages_chan)
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
		messages_chan:  messages_chan,
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
	c.log.Debug("Connected")
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
	for {
		select {
		case <-c.ctx.Done():
			c.log.Debug("Context done")
			return c.ctx.Err()
		case message := <-c.messages_chan:
			c.onNotEmptyMessage(message)
		}
	}
}

func (c *Client) onNotEmptyMessage(message tg.NotEmptyMessage) {
	c.log.Debug("Got message", zap.Any("message", message))
	msg, ok := message.(*tg.Message)
	if !ok {
		c.log.Debug("Not a message")
		return
	}
	media, ok := msg.GetMedia()
	if !ok {
		c.log.Debug("Not a media")
		return
	}
	poll, ok := media.(*tg.MessageMediaPoll)
	if !ok {
		c.log.Debug("Not a poll")
		return
	}
	c.onPollReceived(poll.Poll, message)
}

func (c *Client) onPollReceived(poll tg.Poll, msg tg.NotEmptyMessage) {
	c.log.Debug("Got poll", zap.Any("poll", poll))
	if len(poll.GetAnswers()) != 2 {
		c.log.Debug("Not a 2 answers poll")
		return
	}
	if poll.GetClosed() {
		c.log.Debug("Poll is closed")
		return
	}
	if poll.GetMultipleChoice() {
		c.log.Debug("Poll is multiple choice")
		return
	}
	if !poll.GetPublicVoters() {
		c.log.Debug("Poll is anonymous")
		return
	}
	if poll.GetQuiz() {
		c.log.Debug("Poll is a quiz")
		return
	}
	options := [][]byte{poll.GetAnswers()[0].GetOption()}
	inputPeer, err := getInputPeer(msg.GetPeerID())
	if err != nil {
		c.log.Error("Failed to get input peer", zap.Error(err))
		return
	}
	c.log.Sugar().Debugw(
		"Sending vote",
		"input_peer", inputPeer,
		"msg_id", msg.GetID(),
		"options", options,
	)
	if _, err := c.client.API().MessagesSendVote(c.ctx, &tg.MessagesSendVoteRequest{
		Peer:    inputPeer,
		MsgID:   msg.GetID(),
		Options: options,
	}); err != nil {
		c.log.Error("Failed to send vote", zap.Error(err))
	}
}

func getInputPeer(peerClass tg.PeerClass) (tg.InputPeerClass, error) {
	var inputPeer tg.InputPeerClass
	switch peer := peerClass.(type) {
	case *tg.PeerUser:
		inputPeer = &tg.InputPeerUser{
			UserID: peer.GetUserID(),
		}
	case *tg.PeerChat:
		inputPeer = &tg.InputPeerChat{
			ChatID: peer.GetChatID(),
		}
	case *tg.PeerChannel:
		inputPeer = &tg.InputPeerChannel{
			ChannelID: peer.GetChannelID(),
		}
	default:
		return nil, fmt.Errorf("unknown peer type: %T", peerClass)
	}
	return inputPeer, nil
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
		c.log.Debug("Not authorized, starting auth flow with number", zap.String("phone", phone))
		flow := auth.NewFlow(
			termAuth{phone: phone},
			auth.SendCodeOptions{},
		)
		if err := flow.Run(c.ctx, authClient); err != nil {
			return fmt.Errorf("failed to run auth flow: %w", err)
		}
	} else {
		c.log.Debug("Already authorized")
	}
	return nil
}

func newUpdatesManager(log *zap.Logger, ch chan tg.NotEmptyMessage) *updates.Manager {
	updateDispatcher := tg.NewUpdateDispatcher()
	updateLogger := log.Named("updateListener")
	updateDispatcher.OnNewMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewMessage) error {
		updateLogger.Debug("New message", zap.Any("update.message", update.GetMessage()), zap.Any("entities", e))
		nonempty, ok := update.Message.AsNotEmpty()
		if ok {
			updateLogger.Debug("New non-empty message", zap.Any("nonEmpty", nonempty))
			ch <- nonempty
		}
		return nil
	})
	return updates.New(updates.Config{
		Handler: updateDispatcher,
		Logger:  log.Named("updates"),
	})
}
