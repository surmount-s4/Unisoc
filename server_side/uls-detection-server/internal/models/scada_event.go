package models

import "time"

// ScadaEvent represents a minimal normalized SCADA/ICS log entry
type ScadaEvent struct {
	// Source metadata
	ReceivedAt     time.Time `json:"received_at,omitempty"`
	Source         string    `json:"source"`
	Timestamp      string    `json:"timestamp"`
	Tag            string    `json:"tag"`
	Name           string    `json:"name"`
	Message        string    `json:"message"`
	State          string    `json:"state,omitempty"`
	Classification string    `json:"classification,omitempty"`
	Username       string    `json:"username,omitempty"`
	Userlocation   string    `json:"userlocation,omitempty"`
	RawLog         string    `json:"raw_log,omitempty"`
}
