package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/updates"
	updhook "github.com/gotd/td/telegram/updates/hook"
	"github.com/gotd/td/tg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
)

type Client struct {
	client          *telegram.Client
	log             *zap.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	updatesManager  *updates.Manager
	messages_chan   chan *NewMessage
	target_chat_ids []int64
}

func main() {
	client, err := NewClient()
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Stop()
	if err := client.Run(); err != nil {
		panic(err)
	}
}

func NewClient() (*Client, error) {
	_, is_debug := os.LookupEnv("DEBUG")
	log, err := buildLogger(is_debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	target_chat_ids, err := getTargetChatIds()
	if err != nil {
		log.Warn("failed to get target chat ids", zap.Error(err))
	}
	messages_chan := make(chan *NewMessage)
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
		client:          client,
		log:             log.Named("client"),
		ctx:             ctx,
		cancel:          cancel,
		updatesManager:  updatesManager,
		messages_chan:   messages_chan,
		target_chat_ids: target_chat_ids,
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
	if c.target_chat_ids == nil {
		return c.printAllChats()
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
			c.log.Info("Context done")
			return c.ctx.Err()
		case message := <-c.messages_chan:
			c.onNotEmptyMessage(message)
		}
	}
}

func (c *Client) printAllChats() error {
	exceptIds := make([]int64, 0)
	chats, err := c.client.API().MessagesGetAllChats(c.ctx, exceptIds)
	if err != nil {
		return fmt.Errorf("failed to get chats: %w", err)
	}
	for _, chatClass := range chats.GetChats() {
		if chat, ok := chatClass.AsNotEmpty(); ok {
			c.log.Info("Chat", zap.Any("name", chat.GetTitle()), zap.Any("id", chat.GetID()))
		}
	}
	c.log.Info("Please, specify TARGET_CHAT_IDS env variable with a list of chat ids separated by comma")
	return nil
}

func (c *Client) onNotEmptyMessage(newMessage *NewMessage) {
	c.log.Debug("Got message", zap.Any("message", newMessage))
	msg, ok := (*newMessage.Message).(*tg.Message)
	if !ok {
		c.log.Warn("Not a message")
		return
	}
	media, ok := msg.GetMedia()
	if !ok {
		c.log.Debug("No media found")
		return
	}
	poll, ok := media.(*tg.MessageMediaPoll)
	if !ok {
		c.log.Debug("No poll found")
		return
	}
	c.onPollReceived(poll.Poll, msg, newMessage)
}

func (c *Client) onPollReceived(poll tg.Poll, msg *tg.Message, newMessage *NewMessage) {
	c.log.Info("Got poll", zap.Any("poll", poll), zap.Any("msg", msg), zap.Any("newMessage", newMessage))
	if len(poll.GetAnswers()) != 2 {
		c.log.Info("Not a 2 answers poll")
		return
	}
	if poll.GetClosed() {
		c.log.Info("Poll is closed")
		return
	}
	if poll.GetMultipleChoice() {
		c.log.Info("Poll is multiple choice")
		return
	}
	if !poll.GetPublicVoters() {
		c.log.Info("Poll is anonymous")
		return
	}
	if poll.GetQuiz() {
		c.log.Info("Poll is a quiz")
		return
	}
	answer := poll.GetAnswers()[0]
	options := [][]byte{answer.GetOption()}
	inputPeer, err := c.getInputPeer(msg.GetPeerID(), newMessage)
	if err != nil {
		c.log.Warn("Failed to get input peer", zap.Error(err))
		return
	}
	c.log.Sugar().Infow(
		"Sending vote",
		"input_peer", inputPeer,
		"msg_id", msg.GetID(),
		"options", options,
		"option_text", answer.GetText(),
	)
	for i := 0; i < 5; i++ {
		if _, err := c.client.API().MessagesSendVote(c.ctx, &tg.MessagesSendVoteRequest{
			Peer:    inputPeer,
			MsgID:   msg.GetID(),
			Options: options,
		}); err != nil {
			c.log.Error("Failed to send vote", zap.Error(err))
		} else {
			break
		}
	}
}

func (c *Client) getInputPeer(peerClass tg.PeerClass, newMessage *NewMessage) (tg.InputPeerClass, error) {
	switch peer := peerClass.(type) {
	case *tg.PeerUser:
		userId := peer.GetUserID()
		if !c.isTargetChat(userId) {
			return nil, fmt.Errorf("user %d is not in target chats", userId)
		}
		user, ok := newMessage.Entities.Users[userId]
		if !ok {
			return nil, fmt.Errorf("user %d is not in the list of entities", userId)
		}
		return user.AsInputPeer(), nil
	case *tg.PeerChat:
		chatId := peer.GetChatID()
		if !c.isTargetChat(chatId) {
			return nil, fmt.Errorf("chat %d is not in target chats", chatId)
		}
		chat, ok := newMessage.Entities.Chats[chatId]
		if !ok {
			return nil, fmt.Errorf("chat %d is not in the list of entities", chatId)
		}
		return chat.AsInputPeer(), nil
	case *tg.PeerChannel:
		channelId := peer.GetChannelID()
		if !c.isTargetChat(channelId) {
			return nil, fmt.Errorf("channel %d is not in target chats", channelId)
		}
		channel, ok := newMessage.Entities.Channels[channelId]
		if !ok {
			return nil, fmt.Errorf("channel %d is not in the list of entities", channelId)
		}
		return channel.AsInputPeer(), nil
	default:
		return nil, fmt.Errorf("unsupported peer type: %T", peerClass)
	}
}

func (c *Client) isTargetChat(chatId int64) bool {
	for _, v := range c.target_chat_ids {
		if v == chatId {
			return true
		}
	}
	return false
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
		password := os.Getenv("PASSWORD")
		c.log.Info("Not authorized, starting auth flow with number", zap.String("phone", phone))
		flow := auth.NewFlow(
			termAuth{phone: phone, password: password},
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

func newUpdatesManager(log *zap.Logger, ch chan *NewMessage) *updates.Manager {
	updateDispatcher := tg.NewUpdateDispatcher()
	updateLogger := log.Named("updateListener")
	updateDispatcher.OnNewMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewMessage) error {
		updateLogger.Debug("New message", zap.Any("update", update), zap.Any("entities", e))
		ch <- &NewMessage{Message: &update.Message, Entities: &e}
		return nil
	})
	updateDispatcher.OnNewChannelMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewChannelMessage) error {
		updateLogger.Debug("New channel message", zap.Any("update", update), zap.Any("entities", e))
		ch <- &NewMessage{Message: &update.Message, Entities: &e}
		return nil
	})
	updateDispatcher.OnNewScheduledMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewScheduledMessage) error {
		updateLogger.Debug("New scheduled message", zap.Any("update", update), zap.Any("entities", e))
		ch <- &NewMessage{Message: &update.Message, Entities: &e}
		return nil
	})
	return updates.New(updates.Config{
		Handler: updateDispatcher,
		Logger:  log.Named("updates"),
	})
}

func getTargetChatIds() ([]int64, error) {
	chatIds, ok := os.LookupEnv("TARGET_CHAT_IDS")
	if !ok {
		return nil, fmt.Errorf("TARGET_CHAT_IDS is not set")
	}
	target_chat_ids := make([]int64, 0, 2)
	for _, chatId := range strings.Split(chatIds, ",") {
		target_chat_id, err := strconv.ParseInt(chatId, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chat id: %w", err)
		}
		target_chat_ids = append(target_chat_ids, target_chat_id)
	}
	if len(target_chat_ids) == 0 {
		return nil, fmt.Errorf("no chat ids specified")
	}
	return target_chat_ids, nil
}

func buildLogger(is_debug bool) (*zap.Logger, error) {
	var loggerConf zap.Config
	if is_debug {
		loggerConf = zap.NewDevelopmentConfig()
	} else {
		loggerConf = zap.NewProductionConfig()
		loggerEncoderConf := zap.NewProductionEncoderConfig()
		loggerEncoderConf.EncodeTime = zapcore.ISO8601TimeEncoder
		loggerConf.EncoderConfig = loggerEncoderConf
		loggerConf.Encoding = "console"
	}
	return loggerConf.Build()
}

// noSignUp can be embedded to prevent signing up.
type noSignUp struct{}

func (c noSignUp) SignUp(ctx context.Context) (auth.UserInfo, error) {
	return auth.UserInfo{}, fmt.Errorf("sign up is not supported")
}

func (c noSignUp) AcceptTermsOfService(ctx context.Context, tos tg.HelpTermsOfService) error {
	return &auth.SignUpRequired{TermsOfService: tos}
}

// termAuth implements authentication via terminal.
type termAuth struct {
	noSignUp

	phone    string
	password string
}

func (a termAuth) Phone(_ context.Context) (string, error) {
	return a.phone, nil
}

func (a termAuth) Password(_ context.Context) (string, error) {
	return a.password, nil
}

func (a termAuth) Code(_ context.Context, _ *tg.AuthSentCode) (string, error) {
	fmt.Print("Enter code: ")
	code, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read code: %w", err)
	}
	return strings.TrimSpace(code), nil
}

type NewMessage struct {
	Message  *tg.MessageClass
	Entities *tg.Entities
}
