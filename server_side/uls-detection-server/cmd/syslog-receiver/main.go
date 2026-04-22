package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"uls-detection-server/internal/models"
	"uls-detection-server/internal/queue"
	"uls-detection-server/internal/syslogreceiver"
)

type config struct {
	listenHost string
	listenPort int

	rmqHost  string
	rmqPort  int
	rmqUser  string
	rmqPass  string
	rmqQueue string

	batchSize int
	flushSec  float64
	verbose   bool
}

func main() {
	cfg := parseFlags()

	addr := fmt.Sprintf("%s:%d", cfg.listenHost, cfg.listenPort)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("failed to listen on UDP %s: %v", addr, err)
	}
	defer conn.Close()

	var pub *queue.Publisher
	publishEnabled := true
	pub, err = queue.NewPublisher(cfg.rmqHost, fmt.Sprintf("%d", cfg.rmqPort), cfg.rmqUser, cfg.rmqPass, cfg.rmqQueue)
	if err != nil {
		publishEnabled = false
		log.Printf("RabbitMQ unavailable (%v). Running in stdout-only mode.", err)
	}

	closePublisher := func() {
		if pub != nil {
			pub.Close()
			pub = nil
		}
	}
	defer closePublisher()

	connectPublisher := func() bool {
		if pub != nil {
			return true
		}
		next, connErr := queue.NewPublisher(cfg.rmqHost, fmt.Sprintf("%d", cfg.rmqPort), cfg.rmqUser, cfg.rmqPass, cfg.rmqQueue)
		if connErr != nil {
			return false
		}
		pub = next
		publishEnabled = true
		log.Printf("RabbitMQ publisher attached %s:%d queue=%s", cfg.rmqHost, cfg.rmqPort, cfg.rmqQueue)
		return true
	}

	log.Printf("Go Universal Syslog Receiver listening on udp://%s", addr)
	if publishEnabled {
		log.Printf("Publishing to RabbitMQ %s:%d queue=%s", cfg.rmqHost, cfg.rmqPort, cfg.rmqQueue)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	flushInterval := time.Duration(cfg.flushSec * float64(time.Second))
	if flushInterval <= 0 {
		flushInterval = 2 * time.Second
	}

	batch := make([]interface{}, 0, cfg.batchSize)
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	readBuf := make([]byte, 16*1024)
	recvTotal := 0
	sentTotal := 0
	dropTotal := 0

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if !publishEnabled || pub == nil {
			if !connectPublisher() {
				dropTotal += len(batch)
				log.Printf("publisher unavailable, dropped batch size=%d (total dropped=%d)", len(batch), dropTotal)
				batch = batch[:0]
				return
			}
		}
		if pub == nil {
			dropTotal += len(batch)
			batch = batch[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := pub.PublishBatch(ctx, batch)
		cancel()
		if err != nil {
			closePublisher()
			publishEnabled = false
			dropTotal += len(batch)
			log.Printf("publish batch failed (size=%d): %v", len(batch), err)
		} else {
			sentTotal += len(batch)
			log.Printf("published batch: %d (total sent=%d)", len(batch), sentTotal)
		}
		batch = batch[:0]
	}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("failed to set read deadline: %v", err)
		}

		n, raddr, err := conn.ReadFrom(readBuf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-flushTicker.C:
					flush()
				default:
				}
				select {
				case <-sigCh:
					flush()
					log.Printf("receiver stopped: received=%d sent=%d dropped=%d", recvTotal, sentTotal, dropTotal)
					return
				default:
				}
				continue
			}
			log.Printf("udp read error: %v", err)
			continue
		}

		recvTotal++
		raw := string(readBuf[:n])
		event, ok := syslogreceiver.Normalize(raw, remoteIP(raddr), time.Now().UTC())
		if !ok {
			continue
		}

		if cfg.verbose || !publishEnabled {
			log.Printf("[%s] %s -> %s:%s action=%s type=%s", event.SensorIP, event.SrcIP, event.DstIP, event.DstPort, event.Action, event.LogType)
		}

		if len(batch) >= cfg.batchSize {
			flush()
		}
		batch = append(batch, firewallEventWithSource(event))

		select {
		case <-flushTicker.C:
			flush()
		default:
		}

		select {
		case <-sigCh:
			flush()
			log.Printf("receiver stopped: received=%d sent=%d dropped=%d", recvTotal, sentTotal, dropTotal)
			return
		default:
		}
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.listenHost, "host", envOr("SYSLOG_HOST", "0.0.0.0"), "UDP bind address")
	flag.IntVar(&cfg.listenPort, "port", envIntOr("SYSLOG_PORT", 5514), "UDP syslog port")

	flag.StringVar(&cfg.rmqHost, "rmq-host", envOr("RABBITMQ_HOST", "localhost"), "RabbitMQ host")
	flag.IntVar(&cfg.rmqPort, "rmq-port", envIntOr("RABBITMQ_PORT", 5672), "RabbitMQ port")
	flag.StringVar(&cfg.rmqUser, "rmq-user", envOr("RABBITMQ_USER", "guest"), "RabbitMQ username")
	flag.StringVar(&cfg.rmqPass, "rmq-pass", envOr("RABBITMQ_PASS", "guest"), "RabbitMQ password")
	flag.StringVar(&cfg.rmqQueue, "rmq-queue", envOr("RABBITMQ_FW_QUEUE", "firewall_events"), "RabbitMQ queue")

	flag.IntVar(&cfg.batchSize, "batch-size", envIntOr("SYSLOG_BATCH_SIZE", 50), "batch size for publish")
	flag.Float64Var(&cfg.flushSec, "flush-sec", envFloatOr("SYSLOG_FLUSH_SEC", 2.0), "flush interval in seconds")
	flag.BoolVar(&cfg.verbose, "verbose", false, "verbose event logging")
	flag.Parse()

	if cfg.batchSize <= 0 {
		cfg.batchSize = 50
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out int
	if _, err := fmt.Sscanf(v, "%d", &out); err != nil {
		return fallback
	}
	return out
}

func envFloatOr(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out float64
	if _, err := fmt.Sscanf(v, "%f", &out); err != nil {
		return fallback
	}
	return out
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

func firewallEventWithSource(e models.FirewallEvent) map[string]any {
	return map[string]any{
		"source_type":      "universal_syslog",
		"received_at":      e.ReceivedAt,
		"sensor_ip":        e.SensorIP,
		"raw_log":          e.RawLog,
		"device_name":      e.DeviceName,
		"device_id":        e.DeviceID,
		"log_date":         e.LogDate,
		"log_time":         e.LogTime,
		"timezone":         e.Timezone,
		"log_id":           e.LogID,
		"log_type":         e.LogType,
		"log_component":    e.LogComponent,
		"log_subtype":      e.LogSubtype,
		"status":           e.Status,
		"priority":         e.Priority,
		"action":           e.Action,
		"src_ip":           e.SrcIP,
		"src_port":         e.SrcPort,
		"src_mac":          e.SrcMAC,
		"src_country_code": e.SrcCountry,
		"src_zone":         e.SrcZone,
		"src_zone_type":    e.SrcZoneType,
		"src_trans_ip":     e.SrcTransIP,
		"dst_ip":           e.DstIP,
		"dst_port":         e.DstPort,
		"dst_country_code": e.DstCountry,
		"dst_zone":         e.DstZone,
		"dst_zone_type":    e.DstZoneType,
		"protocol":         e.Protocol,
		"ether_type":       e.EtherType,
		"conn_event":       e.ConnEvent,
		"conn_id":          e.ConnID,
		"sent_bytes":       e.SentBytes,
		"recv_bytes":       e.RecvBytes,
		"sent_pkts":        e.SentPkts,
		"recv_pkts":        e.RecvPkts,
		"fw_rule_id":       e.FwRuleID,
		"nat_rule_id":      e.NatRuleID,
		"fw_type":          e.FwType,
		"user":             e.User,
		"user_group":       e.UserGroup,
		"app_name":         e.AppName,
		"app_risk":         e.AppRisk,
		"message":          e.Message,
		"severity":         e.Severity,
		"classification":   e.Classification,
		"url":              e.URL,
	}
}
