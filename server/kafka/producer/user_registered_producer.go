package producer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nusiss-capstone-project/identity-mservice/server/log"
)

const UserRegisteredTopic = "user.events.registered"

// UserRegisteredEvent is the payload for user registration messages.
type UserRegisteredEvent struct {
	UserID       int       `json:"user_id"`
	RegisterTime int       `json:"register_time"`
	Channel      string    `json:"channel"`
	InviterID    int       `json:"inviter_id"`
	EventTime    time.Time `json:"event_time"`
}

// UserRegisteredProducer publishes user registration events.
type UserRegisteredProducer interface {
	PublishUserRegistered(ctx context.Context, userID int64, registerTime time.Time) error
}

type userRegisteredProducerImpl struct {
	producer KafkaProducer
	topic    string
}

var (
	userRegisteredProducerOnce sync.Once
	userRegisteredProducerInst UserRegisteredProducer
)

// GetUserRegisteredProducer returns the singleton user registered producer.
func GetUserRegisteredProducer() UserRegisteredProducer {
	userRegisteredProducerOnce.Do(func() {
		userRegisteredProducerInst = &userRegisteredProducerImpl{
			producer: GetKafkaProducer(),
			topic:    UserRegisteredTopic,
		}
	})
	return userRegisteredProducerInst
}

func (p *userRegisteredProducerImpl) PublishUserRegistered(
	ctx context.Context,
	userID int64,
	registerTime time.Time,
) error {
	if userID <= 0 {
		return errors.New("user_id must be positive")
	}
	if registerTime.IsZero() {
		return errors.New("register_time is required")
	}

	now := time.Now().UTC()
	event := UserRegisteredEvent{
		UserID:       int(userID),
		RegisterTime: int(registerTime.Unix()),
		Channel:      "",
		InviterID:    0,
		EventTime:    now,
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal user registered event: %w", err)
	}

	err = p.producer.Publish(ctx, p.topic, []byte(strconv.FormatInt(userID, 10)), payload)
	if err != nil {
		log.WithContext(ctx).Errorw("publish user registered event failed",
			"user_id", userID, "topic", p.topic, "error", err)
		return err
	}
	return nil
}
