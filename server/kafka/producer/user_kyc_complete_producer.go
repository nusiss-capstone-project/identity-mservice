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

const UserKYCCompleteTopic = "user.events.kyc_complete"

// UserKYCCompleteEvent is the payload for user KYC completion messages.
type UserKYCCompleteEvent struct {
	UserID       int       `json:"user_id"`
	KYCStatus    string    `json:"kyc_status"`
	KYCUpdatedAt time.Time `json:"kyc_updated_at"`
	EventTime    time.Time `json:"event_time"`
}

// UserKYCCompleteProducer publishes user KYC completion events.
type UserKYCCompleteProducer interface {
	PublishUserKYCComplete(ctx context.Context, userID int64, kycStatus string, kycUpdatedAt time.Time) error
}

type userKYCCompleteProducerImpl struct {
	producer KafkaProducer
	topic    string
}

var (
	userKYCCompleteProducerOnce sync.Once
	userKYCCompleteProducerInst UserKYCCompleteProducer
)

// GetUserKYCCompleteProducer returns the singleton user KYC complete producer.
func GetUserKYCCompleteProducer() UserKYCCompleteProducer {
	userKYCCompleteProducerOnce.Do(func() {
		userKYCCompleteProducerInst = &userKYCCompleteProducerImpl{
			producer: GetKafkaProducer(),
			topic:    UserKYCCompleteTopic,
		}
	})
	return userKYCCompleteProducerInst
}

func (p *userKYCCompleteProducerImpl) PublishUserKYCComplete(
	ctx context.Context,
	userID int64,
	kycStatus string,
	kycUpdatedAt time.Time,
) error {
	if userID <= 0 {
		return errors.New("user_id must be positive")
	}
	if kycStatus == "" {
		return errors.New("kyc_status is required")
	}
	if kycUpdatedAt.IsZero() {
		return errors.New("kyc_updated_at is required")
	}

	now := time.Now().UTC()
	event := UserKYCCompleteEvent{
		UserID:       int(userID),
		KYCStatus:    kycStatus,
		KYCUpdatedAt: kycUpdatedAt.UTC(),
		EventTime:    now,
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal user kyc complete event: %w", err)
	}

	err = p.producer.Publish(ctx, p.topic, []byte(strconv.FormatInt(userID, 10)), payload)
	if err != nil {
		log.WithContext(ctx).Errorw("publish user kyc complete event failed",
			"user_id", userID, "topic", p.topic, "kyc_status", kycStatus, "error", err)
		return err
	}
	return nil
}
