package session

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestManager(t *testing.T) (*Manager, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewManager(rdb), mr
}

func TestCreateAndGet(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	id, err := m.Create(ctx, "user-1", "agent", "1.2.3.4")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	s, err := m.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if s.UserID != "user-1" {
		t.Errorf("expected user-1, got %q", s.UserID)
	}
	if s.Pending2FA {
		t.Error("a full session must not be marked pending 2FA")
	}
}

func TestPending2FASessionIsDistinct(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	id, err := m.CreatePending2FA(ctx, "user-2", "agent", "1.2.3.4")
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}

	s, err := m.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !s.Pending2FA {
		t.Error("expected Pending2FA = true for a pending session")
	}
}

func TestListReturnsAllUserSessions(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	if _, err := m.Create(ctx, "user-3", "device-a", "ip"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, "user-3", "device-b", "ip"); err != nil {
		t.Fatal(err)
	}

	list, err := m.List(ctx, "user-3")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(list))
	}
}

func TestDeleteRemovesSession(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	id, _ := m.Create(ctx, "user-4", "a", "ip")
	if err := m.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.Get(ctx, id); err == nil {
		t.Error("expected an error getting a deleted session")
	}
}

func TestDeleteAllExceptKeepsCurrent(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	keep, _ := m.Create(ctx, "user-5", "current", "ip")
	other, _ := m.Create(ctx, "user-5", "other", "ip")

	if err := m.DeleteAllExcept(ctx, "user-5", keep); err != nil {
		t.Fatalf("delete all except: %v", err)
	}
	if _, err := m.Get(ctx, keep); err != nil {
		t.Errorf("the kept session should survive: %v", err)
	}
	if _, err := m.Get(ctx, other); err == nil {
		t.Error("the other session should be deleted")
	}
}

func TestDeleteAllClearsEverything(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()

	a, _ := m.Create(ctx, "user-6", "a", "ip")
	b, _ := m.Create(ctx, "user-6", "b", "ip")

	if err := m.DeleteAll(ctx, "user-6"); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	for _, id := range []string{a, b} {
		if _, err := m.Get(ctx, id); err == nil {
			t.Errorf("session %q should be deleted", id)
		}
	}
	if list, _ := m.List(ctx, "user-6"); len(list) != 0 {
		t.Errorf("expected 0 sessions after DeleteAll, got %d", len(list))
	}
}

func TestSessionExpires(t *testing.T) {
	m, mr := newTestManager(t)
	ctx := context.Background()

	id, _ := m.Create(ctx, "user-7", "a", "ip")

	mr.FastForward(sessionTTL + time.Minute)

	if _, err := m.Get(ctx, id); err == nil {
		t.Error("expected the session to be gone after its TTL")
	}
}
