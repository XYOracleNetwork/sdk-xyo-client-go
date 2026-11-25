package client

import (
	"context"
	"time"

	"github.com/XYOracleNetwork/sdk-xyo-client-go/account"
	"github.com/XYOracleNetwork/sdk-xyo-client-go/payload"
)

// ObserverFunc is a function invoked by BasicWitness to produce zero or more observed payloads.
type ObserverFunc func(ctx context.Context, in ...any) ([]any, error)

// BasicWitness is a flexible Witness implementation backed by a user-supplied ObserverFunc.
type BasicWitness struct {
	account  account.Account
	observer ObserverFunc
}

// NewBasicWitness constructs a BasicWitness with an optional account and observer function.
func NewBasicWitness(acct account.Account, observer ObserverFunc) *BasicWitness {
	return &BasicWitness{
		account:  acct,
		observer: observer,
	}
}

func (w *BasicWitness) Account() account.Account {
	return w.account
}

func (w *BasicWitness) Observe(ctx context.Context, in ...any) ([]any, error) {
	if w.observer == nil {
		return nil, nil
	}
	return w.observer(ctx, in...)
}

// EventWitness observes named application events with an epoch millisecond timestamp.
type EventWitness struct {
	account account.Account
	eventFn func(ctx context.Context) (string, error)
}

// NewEventWitness creates an EventWitness whose event name is produced by eventFn.
func NewEventWitness(acct account.Account, eventFn func(ctx context.Context) (string, error)) *EventWitness {
	return &EventWitness{
		account: acct,
		eventFn: eventFn,
	}
}

func (w *EventWitness) Account() account.Account {
	return w.account
}

func (w *EventWitness) Observe(ctx context.Context, _ ...any) ([]any, error) {
	if w.eventFn == nil {
		return nil, nil
	}
	name, err := w.eventFn(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, nil
	}
	return []any{payload.NewEventPayload(name, time.Now().UnixMilli())}, nil
}

// TimestampPayload represents a "network.xyo.timestamp" witness payload.
type TimestampPayload struct {
	payload.BasePayload
	Timestamp int64 `json:"timestamp"`
}

// TimestampWitness observes the current UTC epoch milliseconds.
type TimestampWitness struct {
	account account.Account
}

// NewTimestampWitness creates a TimestampWitness.
func NewTimestampWitness(acct account.Account) *TimestampWitness {
	return &TimestampWitness{account: acct}
}

func (w *TimestampWitness) Account() account.Account {
	return w.account
}

func (w *TimestampWitness) Observe(_ context.Context, _ ...any) ([]any, error) {
	return []any{
		TimestampPayload{
			BasePayload: payload.BasePayload{Schema: "network.xyo.timestamp"},
			Timestamp:   time.Now().UnixMilli(),
		},
	}, nil
}
