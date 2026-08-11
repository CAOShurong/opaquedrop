package server

import (
	"sync"
	"time"
)

const (
	failureLimit          = 12
	failureWindowDuration = time.Minute
	maxFailureBuckets     = 4096
	overflowFailureBucket = "\x00overflow"
)

type failureWindow struct {
	start time.Time
	count int
}

type failureLimiter struct {
	mu      sync.Mutex
	windows map[string]failureWindow
	now     func() time.Time
}

func newFailureLimiter() *failureLimiter {
	return &failureLimiter{windows: map[string]failureWindow{}, now: time.Now}
}

func (l *failureLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := l.bucketKey(ip, now)
	w, ok := l.windows[key]
	if !ok || expiredFailureWindow(w, now) {
		delete(l.windows, key)
		return false
	}
	return w.count >= failureLimit
}

func (l *failureLimiter) failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := l.bucketKey(ip, now)
	w, ok := l.windows[key]
	if !ok || expiredFailureWindow(w, now) {
		w = failureWindow{start: now}
	}
	w.count++
	l.windows[key] = w
}

func (l *failureLimiter) bucketKey(ip string, now time.Time) string {
	if _, ok := l.windows[ip]; ok {
		return ip
	}
	if len(l.windows) >= maxFailureBuckets-1 {
		l.removeExpired(now)
	}
	if len(l.windows) >= maxFailureBuckets-1 {
		return overflowFailureBucket
	}
	return ip
}

func (l *failureLimiter) removeExpired(now time.Time) {
	for key, window := range l.windows {
		if expiredFailureWindow(window, now) {
			delete(l.windows, key)
		}
	}
}

func expiredFailureWindow(window failureWindow, now time.Time) bool {
	return !now.Before(window.start.Add(failureWindowDuration))
}
