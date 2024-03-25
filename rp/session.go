package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

type sessiondb struct {
	sessions map[string]interface{}
	mu       sync.RWMutex
}

var sessionDb *sessiondb = &sessiondb{
	sessions: make(map[string]interface{}),
}

func (db *sessiondb) StartSession(data interface{}) string {
	db.mu.Lock()
	defer db.mu.Unlock()
	id, _ := generateSessionId(32)
	db.sessions[id] = data
	return id
}

func (db *sessiondb) GetSession(id string) (interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	session, ok := db.sessions[id]
	if !ok {
		return nil, fmt.Errorf("error getting session '%s': does not exist", id)
	}
	return session, nil
}

func (db *sessiondb) DeleteSession(id string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.sessions, id)
}

func generateSessionId(len int) (string, error) {
	randomData := make([]byte, len)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(randomData), nil
}
