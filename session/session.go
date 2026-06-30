package session

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	sessionTTL = 72 * time.Hour
	keyPrefix  = "session:"
	userPrefix = "user_sessions:"
)

type Session struct {
	UserID     string    `json:"user_id"`
	CreatedAt  time.Time `json:"created_at"`
	UserAgent  string    `json:"user_agent"`
	IP         string    `json:"ip"`
	Pending2FA bool      `json:"pending_2fa,omitempty"`
}

type SessionInfo struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
}

type Manager struct {
	rdb *redis.Client
}

func NewManager(rdb *redis.Client) *Manager {
	return &Manager{rdb: rdb}
}

func (m *Manager) Create(ctx context.Context, userID, userAgent, ip string) (string, error) {
	return m.create(ctx, Session{
		UserID:    userID,
		CreatedAt: time.Now(),
		UserAgent: userAgent,
		IP:        ip,
	})
}

func (m *Manager) CreatePending2FA(ctx context.Context, userID, userAgent, ip string) (string, error) {
	return m.create(ctx, Session{
		UserID:     userID,
		CreatedAt:  time.Now(),
		UserAgent:  userAgent,
		IP:         ip,
		Pending2FA: true,
	})
}

func (m *Manager) create(ctx context.Context, s Session) (string, error) {
	id := uuid.NewString()
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	pipe := m.rdb.Pipeline()
	pipe.Set(ctx, keyPrefix+id, data, sessionTTL)
	pipe.SAdd(ctx, userPrefix+s.UserID, id)
	pipe.Expire(ctx, userPrefix+s.UserID, sessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return id, nil
}

func (m *Manager) Get(ctx context.Context, id string) (*Session, error) {
	data, err := m.rdb.Get(ctx, keyPrefix+id).Bytes()
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (m *Manager) List(ctx context.Context, userID string) ([]SessionInfo, error) {
	ids, err := m.rdb.SMembers(ctx, userPrefix+userID).Result()
	if err != nil {
		return nil, err
	}
	var sessions []SessionInfo
	for _, id := range ids {
		s, err := m.Get(ctx, id)
		if err != nil {
			continue
		}
		sessions = append(sessions, SessionInfo{
			ID:        id,
			CreatedAt: s.CreatedAt,
			UserAgent: s.UserAgent,
			IP:        s.IP,
		})
	}
	return sessions, nil
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	s, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	pipe := m.rdb.Pipeline()
	pipe.Del(ctx, keyPrefix+id)
	pipe.SRem(ctx, userPrefix+s.UserID, id)
	_, err = pipe.Exec(ctx)
	return err
}

func (m *Manager) DeleteAll(ctx context.Context, userID string) error {
	ids, err := m.rdb.SMembers(ctx, userPrefix+userID).Result()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = keyPrefix + id
	}
	pipe := m.rdb.Pipeline()
	pipe.Del(ctx, keys...)
	pipe.Del(ctx, userPrefix+userID)
	_, err = pipe.Exec(ctx)
	return err
}

func (m *Manager) DeleteAllExcept(ctx context.Context, userID, exceptID string) error {
	ids, err := m.rdb.SMembers(ctx, userPrefix+userID).Result()
	if err != nil {
		return err
	}
	var toDelete []string
	for _, id := range ids {
		if id != exceptID {
			toDelete = append(toDelete, id)
		}
	}
	if len(toDelete) == 0 {
		return nil
	}
	keys := make([]string, len(toDelete))
	for i, id := range toDelete {
		keys[i] = keyPrefix + id
	}
	pipe := m.rdb.Pipeline()
	pipe.Del(ctx, keys...)
	for _, id := range toDelete {
		pipe.SRem(ctx, userPrefix+userID, id)
	}
	_, err = pipe.Exec(ctx)
	return err
}

func (m *Manager) Refresh(ctx context.Context, id string) error {
	return m.rdb.Expire(ctx, keyPrefix+id, sessionTTL).Err()
}
