package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"uls-detection-server/internal/correlationengine"
	"uls-detection-server/internal/database"
	"uls-detection-server/internal/detector"
	fwdetector "uls-detection-server/internal/firewall"
	"uls-detection-server/internal/llmwatcher"
	"uls-detection-server/internal/models"
	"uls-detection-server/internal/queue"
)

// Config holds server configuration
type Config struct {
	RabbitMQHost       string
	RabbitMQPort       string
	RabbitMQUser       string
	RabbitMQPass       string
	RabbitMQQueue      string
	RabbitMQFWQueue    string // Sophos firewall events queue
	RabbitMQSCADAQueue string // SCADA events queue

	PostgresHost string
	PostgresPort string
	PostgresUser string
	PostgresPass string
	PostgresDB   string

	BatchSize  int
	BatchDelay time.Duration

	// LLM Watcher configuration
	OllamaURL      string // empty = LLM disabled (passthrough mode)
	OllamaModel    string // e.g. "mistral", "llama3"
	LLMWindowSec   int    // 5-sec poll window in seconds
	LLMPassEnabled bool   // if true, correlator reads from llm_pass_1

	// Correlation Engine v2 configuration
	CorrelationEngineV2Enabled bool
	CorrWindowMinutes          int
	CorrTickSeconds            int
	BartInProcess              bool
	BartServiceURL             string
	BartModel                  string
	BartModelID                string
	BartModelPath              string
	BartPythonBin              string
	BartRunnerPath             string
	BartTimeoutSec             int
	BartConfidenceThreshold    float64
	CorrLLMURL                 string
	CorrLLMModel               string
	CorrLLMTimeoutSec          int
}

func loadConfig() Config {
	batchSize, _ := strconv.Atoi(getEnv("BATCH_SIZE", "100"))
	batchDelay, _ := strconv.Atoi(getEnv("BATCH_DELAY_MS", "1000"))
	llmWindowSec, _ := strconv.Atoi(getEnv("LLM_WINDOW_SECONDS", "5"))
	corrWindowMinutes, _ := strconv.Atoi(getEnv("CORR_WINDOW_MINUTES", "10"))
	corrTickSeconds, _ := strconv.Atoi(getEnv("CORR_TICK_SECONDS", "60"))
	bartTimeoutSec, _ := strconv.Atoi(getEnv("BART_TIMEOUT_SECONDS", "15"))
	corrLLMTimeoutSec, _ := strconv.Atoi(getEnv("CORR_LLM_TIMEOUT_SECONDS", "90"))
	bartThreshold, err := strconv.ParseFloat(getEnv("BART_CONFIDENCE_THRESHOLD", "0.30"), 64)
	if err != nil {
		bartThreshold = 0.30
	}
	corrLLMURL := getEnv("CORR_LLM_URL", "")
	if corrLLMURL == "" {
		corrLLMURL = getEnv("OLLAMA_URL", "")
	}

	return Config{
		RabbitMQHost:       getEnv("RABBITMQ_HOST", "localhost"),
		RabbitMQPort:       getEnv("RABBITMQ_PORT", "5672"),
		RabbitMQUser:       getEnv("RABBITMQ_USER", "guest"),
		RabbitMQPass:       getEnv("RABBITMQ_PASS", "guest"),
		RabbitMQQueue:      getEnv("RABBITMQ_QUEUE", "security_events"),
		RabbitMQFWQueue:    getEnv("RABBITMQ_FW_QUEUE", "firewall_events"),
		RabbitMQSCADAQueue: getEnv("RABBITMQ_SCADA_QUEUE", "scada_logs"),
		PostgresHost:       getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:       getEnv("POSTGRES_PORT", "5432"),
		PostgresUser:       getEnv("POSTGRES_USER", "postgres"),
		PostgresPass:       getEnv("POSTGRES_PASS", "postgres"),
		PostgresDB:         getEnv("POSTGRES_DB", "security_logs"),
		BatchSize:          batchSize,
		BatchDelay:         time.Duration(batchDelay) * time.Millisecond,
		OllamaURL:          getEnv("OLLAMA_URL", ""),
		OllamaModel:        getEnv("OLLAMA_MODEL", "mistral"),
		LLMWindowSec:       llmWindowSec,
		LLMPassEnabled:     getEnv("LLM_PASS_ENABLED", "false") == "true",

		CorrelationEngineV2Enabled: getEnv("CORRELATION_ENGINE_V2_ENABLED", "true") == "true",
		CorrWindowMinutes:          corrWindowMinutes,
		CorrTickSeconds:            corrTickSeconds,
		BartInProcess:              getEnv("BART_INPROCESS", "true") == "true",
		BartServiceURL:             getEnv("BART_SERVICE_URL", ""),
		BartModel:                  getEnv("BART_MODEL", ""),
		BartModelID:                getEnv("BART_MODEL_ID", "facebook/bart-large-mnli"),
		BartModelPath:              getEnv("BART_MODEL_PATH", ""),
		BartPythonBin:              getEnv("BART_PYTHON_BIN", "python"),
		BartRunnerPath:             getEnv("BART_RUNNER_PATH", "internal/correlationengine/bart_runner.py"),
		BartTimeoutSec:             bartTimeoutSec,
		BartConfidenceThreshold:    bartThreshold,
		CorrLLMURL:                 corrLLMURL,
		CorrLLMModel:               getEnv("CORR_LLM_MODEL", getEnv("OLLAMA_MODEL", "mistral")),
		CorrLLMTimeoutSec:          corrLLMTimeoutSec,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	log.Println("Starting ULS Detection Server...")

	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Database ─────────────────────────────────────────────────────────────
	db, err := database.Connect(ctx, cfg.PostgresHost, cfg.PostgresPort,
		cfg.PostgresUser, cfg.PostgresPass, cfg.PostgresDB)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	if err := database.InitSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize Windows schema: %v", err)
	}
	if err := database.InitFirewallSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize firewall schema: %v", err)
	}

	// SCADA schema (small table for raw SCADA/ICS logs)
	if err := database.InitScadaSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize scada schema: %v", err)
	}

	// ── Detectors ────────────────────────────────────────────────────────────
	winDetector := detector.New()
	fwDet := fwdetector.New()

	// ── LLM pass_1 schema ────────────────────────────────────────────────────
	if err := database.InitLLMPassSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize llm_pass_1 schema: %v", err)
	}
	if err := correlationengine.InitSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize correlationengine schema: %v", err)
	}

	// ── LLM Watcher (5-second window, async, non-blocking) ───────────────────
	watcher := llmwatcher.New(db, llmwatcher.Config{
		OllamaURL:     cfg.OllamaURL,
		Model:         cfg.OllamaModel,
		WindowSeconds: cfg.LLMWindowSec,
		Timeout:       90 * time.Second,
	})
	watcher.Start(ctx)
	defer watcher.Stop()

	// ── Correlation engine v2 (new module) ──────────────────────────────────
	corrEngine := correlationengine.New(db, correlationengine.Config{
		Enabled:                 cfg.CorrelationEngineV2Enabled,
		WindowMinutes:           cfg.CorrWindowMinutes,
		TickSeconds:             cfg.CorrTickSeconds,
		BARTInProcess:           cfg.BartInProcess,
		BARTServiceURL:          cfg.BartServiceURL,
		BARTModel:               cfg.BartModel,
		BARTModelID:             cfg.BartModelID,
		BARTModelPath:           cfg.BartModelPath,
		BARTPythonBinary:        cfg.BartPythonBin,
		BARTRunnerPath:          cfg.BartRunnerPath,
		BARTTimeout:             time.Duration(cfg.BartTimeoutSec) * time.Second,
		BARTConfidenceThreshold: cfg.BartConfidenceThreshold,
		CorrelatorLLMURL:        cfg.CorrLLMURL,
		CorrelatorLLMModel:      cfg.CorrLLMModel,
		CorrelatorLLMTimeout:    time.Duration(cfg.CorrLLMTimeoutSec) * time.Second,
	})
	corrEngine.Start(ctx)
	defer corrEngine.Stop()

	// ── Windows event consumer ───────────────────────────────────────────────
	consumer, err := queue.NewConsumer(cfg.RabbitMQHost, cfg.RabbitMQPort,
		cfg.RabbitMQUser, cfg.RabbitMQPass, cfg.RabbitMQQueue)
	if err != nil {
		log.Fatalf("Failed to connect to Windows RabbitMQ queue: %v", err)
	}
	defer consumer.Close()

	msgs, err := consumer.Consume()
	if err != nil {
		log.Printf("Windows consume unavailable at startup: %v", err)
	}
	msgs = waitForConsume(ctx, "Windows", consumer)
	if msgs == nil {
		log.Fatalf("Failed to start Windows consumer")
	}

	// ── Sophos firewall consumer (optional) ──────────────────────────────────
	fwConsumer, fwErr := queue.NewConsumer(cfg.RabbitMQHost, cfg.RabbitMQPort,
		cfg.RabbitMQUser, cfg.RabbitMQPass, cfg.RabbitMQFWQueue)
	if fwErr != nil {
		log.Printf("Firewall queue unavailable (%v) – firewall pipeline disabled", fwErr)
	} else {
		defer fwConsumer.Close()
		log.Printf("Firewall pipeline active (queue: %s)", cfg.RabbitMQFWQueue)
		go runFirewallPipeline(ctx, db, fwDet, fwConsumer, cfg)
	}

	// ── SCADA consumer (optional) ───────────────────────────────────────────
	scadaConsumer, scadaErr := queue.NewConsumer(cfg.RabbitMQHost, cfg.RabbitMQPort,
		cfg.RabbitMQUser, cfg.RabbitMQPass, cfg.RabbitMQSCADAQueue)
	if scadaErr != nil {
		log.Printf("SCADA queue unavailable (%v) – scada pipeline disabled", scadaErr)
	} else {
		defer scadaConsumer.Close()
		log.Printf("SCADA pipeline active (queue: %s)", cfg.RabbitMQSCADAQueue)
		go runScadaPipeline(ctx, db, scadaConsumer, cfg)
	}

	// Optional internal HTTP ingest endpoint that publishes to the SCADA queue
	if pub, err := queue.NewPublisher(cfg.RabbitMQHost, cfg.RabbitMQPort, cfg.RabbitMQUser, cfg.RabbitMQPass, cfg.RabbitMQSCADAQueue); err != nil {
		log.Printf("SCADA publisher unavailable (%v) – internal HTTP ingest disabled", err)
	} else {
		defer pub.Close()
		http.HandleFunc("/ingest_scada", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}

			var entries []models.ScadaEvent
			if err := json.Unmarshal(body, &entries); err != nil {
				var single models.ScadaEvent
				if err := json.Unmarshal(body, &single); err != nil {
					http.Error(w, "invalid JSON payload", http.StatusBadRequest)
					return
				}
				entries = append(entries, single)
			}

			for i := range entries {
				e := &entries[i]
				if e.Source == "" {
					e.Source = "Unknown_SCADA"
				}
				if e.Timestamp == "" || e.Tag == "" || e.Name == "" || e.Message == "" {
					http.Error(w, "missing required fields: source,timestamp,tag,name,message", http.StatusBadRequest)
					return
				}
				if e.ReceivedAt.IsZero() {
					e.ReceivedAt = time.Now()
				}
			}

			items := make([]interface{}, len(entries))
			for i := range entries {
				items[i] = entries[i]
			}

			if err := pub.PublishBatch(context.Background(), items); err != nil {
				log.Printf("internal SCADA publish failed: %v", err)
				http.Error(w, "failed to publish", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})

		httpPort := getEnv("SCADA_HTTP_PORT", "5001")
		go func() {
			log.Printf("Internal SCADA HTTP ingest listening on :%s", httpPort)
			if err := http.ListenAndServe(":"+httpPort, nil); err != nil {
				log.Printf("SCADA HTTP server stopped: %v", err)
			}
		}()
	}

	// ── Graceful shutdown listener ───────────────────────────────────────────
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// ── Windows event batch loop ─────────────────────────────────────────────
	type winBatch struct {
		events []models.SecurityEvent
		msgs   []amqp.Delivery
	}

	batch := winBatch{
		events: make([]models.SecurityEvent, 0, cfg.BatchSize),
		msgs:   make([]amqp.Delivery, 0, cfg.BatchSize),
	}
	ticker := time.NewTicker(cfg.BatchDelay)
	defer ticker.Stop()

	log.Println("Server started, waiting for events...")

	for {
		select {
		case <-sigChan:
			log.Println("Shutdown: flushing remaining batch...")
			if len(batch.events) > 0 {
				if err := processWindowsBatch(ctx, db, winDetector, batch.events); err != nil {
					log.Printf("Failed to process Windows batch on shutdown: %v", err)
					for _, m := range batch.msgs {
						m.Nack(false, true)
					}
				} else {
					for _, m := range batch.msgs {
						m.Ack(false)
					}
				}
			}
			log.Println("Server stopped")
			return

		case msg, ok := <-msgs:
			if !ok {
				log.Println("Windows channel closed, attempting to re-subscribe...")
				msgs = waitForConsume(ctx, "Windows", consumer)
				if msgs == nil {
					log.Println("Windows re-subscribe aborted")
					return
				}
				continue
			}

			var events []models.SecurityEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				var single models.SecurityEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("Failed to parse Windows message: %v", err)
					msg.Nack(false, false)
					continue
				}
				events = []models.SecurityEvent{single}
			}

			batch.events = append(batch.events, events...)
			batch.msgs = append(batch.msgs, msg)

			if len(batch.events) >= cfg.BatchSize {
				if err := processWindowsBatch(ctx, db, winDetector, batch.events); err != nil {
					log.Printf("Failed to process Windows batch: %v", err)
					for _, m := range batch.msgs {
						m.Nack(false, true)
					}
				} else {
					for _, m := range batch.msgs {
						m.Ack(false)
					}
				}
				batch.events = batch.events[:0]
				batch.msgs = batch.msgs[:0]
			}

		case <-ticker.C:
			if len(batch.events) > 0 {
				if err := processWindowsBatch(ctx, db, winDetector, batch.events); err != nil {
					log.Printf("Failed to flush Windows batch: %v", err)
					for _, m := range batch.msgs {
						m.Nack(false, true)
					}
				} else {
					for _, m := range batch.msgs {
						m.Ack(false)
					}
				}
				batch.events = batch.events[:0]
				batch.msgs = batch.msgs[:0]
			}
		}
	}
}

func waitForConsume(ctx context.Context, pipeline string, consumer *queue.Consumer) <-chan amqp.Delivery {
	for {
		msgs, err := consumer.Consume()
		if err == nil {
			log.Printf("[%s] Consumer active", pipeline)
			return msgs
		}

		log.Printf("[%s] Consume unavailable: %v (retrying in 2s)", pipeline, err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

// processWindowsBatch detects on Windows events and bulk-inserts them.
func processWindowsBatch(ctx context.Context, db *database.DB,
	det *detector.Detector, events []models.SecurityEvent) error {

	for i := range events {
		r := det.Detect(&events[i])
		events[i].Severity = r.Severity
		events[i].MitreTechnique = r.MitreTechnique
		events[i].DetectionModule = r.DetectionModule
		events[i].EventDetails = r.EventDetails
		events[i].AdditionalContext = r.AdditionalContext
	}
	return db.InsertEvents(ctx, events)
}

// runFirewallPipeline is the dedicated goroutine for Sophos firewall events.
// It reads amqp.Delivery messages from the firewall_events RabbitMQ queue,
// parses and detects on each FirewallEvent, then bulk-inserts into the DB.
func runFirewallPipeline(ctx context.Context, db *database.DB,
	det *fwdetector.Detector, consumer *queue.Consumer, cfg Config) {

	log.Println("[Firewall] Pipeline goroutine started")
	msgs := waitForConsume(ctx, "Firewall", consumer)
	if msgs == nil {
		log.Println("[Firewall] Pipeline stopped before consume start")
		return
	}

	type fwBatch struct {
		events []models.FirewallEvent
		msgs   []amqp.Delivery
	}

	batch := fwBatch{
		events: make([]models.FirewallEvent, 0, cfg.BatchSize),
		msgs:   make([]amqp.Delivery, 0, cfg.BatchSize),
	}
	ticker := time.NewTicker(cfg.BatchDelay)
	defer ticker.Stop()

	flush := func() {
		if len(batch.events) == 0 {
			return
		}
		if err := db.InsertFirewallEvents(ctx, batch.events); err != nil {
			log.Printf("[Firewall] Batch insert error: %v", err)
			for _, m := range batch.msgs {
				m.Nack(false, true)
			}
		} else {
			for _, m := range batch.msgs {
				m.Ack(false)
			}
		}
		batch.events = batch.events[:0]
		batch.msgs = batch.msgs[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			log.Println("[Firewall] Pipeline stopped")
			return

		case msg, ok := <-msgs:
			if !ok {
				flush()
				log.Println("[Firewall] Delivery channel closed, attempting to re-subscribe...")
				msgs = waitForConsume(ctx, "Firewall", consumer)
				if msgs == nil {
					log.Println("[Firewall] Re-subscribe aborted")
					return
				}
				continue
			}

			var events []models.FirewallEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				// Try single event
				var single models.FirewallEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("[Firewall] Parse error: %v", err)
					msg.Nack(false, false)
					continue
				}
				events = []models.FirewallEvent{single}
			}

			// Apply firewall detection rules to each event
			for i := range events {
				if events[i].ReceivedAt.IsZero() {
					events[i].ReceivedAt = time.Now().UTC()
				}
				r := det.Detect(&events[i])
				events[i].ThreatLevel = r.ThreatLevel
				events[i].ThreatType = r.ThreatType
				events[i].MitreTechnique = r.MitreTechnique
				events[i].DetectionModule = r.DetectionModule
				events[i].EventDetails = r.EventDetails
			}

			batch.events = append(batch.events, events...)
			batch.msgs = append(batch.msgs, msg)

			if len(batch.events) >= cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// runScadaPipeline ingests raw SCADA/ICS logs and stores them in scada_logs.
func runScadaPipeline(ctx context.Context, db *database.DB, consumer *queue.Consumer, cfg Config) {

	log.Println("[SCADA] Pipeline goroutine started")
	msgs := waitForConsume(ctx, "SCADA", consumer)
	if msgs == nil {
		log.Println("[SCADA] Pipeline stopped before consume start")
		return
	}

	type scadaBatch struct {
		events []models.ScadaEvent
		msgs   []amqp.Delivery
	}

	batch := scadaBatch{
		events: make([]models.ScadaEvent, 0, cfg.BatchSize),
		msgs:   make([]amqp.Delivery, 0, cfg.BatchSize),
	}
	ticker := time.NewTicker(cfg.BatchDelay)
	defer ticker.Stop()

	flush := func() {
		if len(batch.events) == 0 {
			return
		}
		if err := db.InsertScadaEvents(ctx, batch.events); err != nil {
			log.Printf("[SCADA] Batch insert error: %v", err)
			for _, m := range batch.msgs {
				m.Nack(false, true)
			}
		} else {
			for _, m := range batch.msgs {
				m.Ack(false)
			}
		}
		batch.events = batch.events[:0]
		batch.msgs = batch.msgs[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			log.Println("[SCADA] Pipeline stopped")
			return

		case msg, ok := <-msgs:
			if !ok {
				flush()
				log.Println("[SCADA] Delivery channel closed, attempting to re-subscribe...")
				msgs = waitForConsume(ctx, "SCADA", consumer)
				if msgs == nil {
					log.Println("[SCADA] Re-subscribe aborted")
					return
				}
				continue
			}

			var events []models.ScadaEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				var single models.ScadaEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("[SCADA] Parse error: %v", err)
					msg.Nack(false, false)
					continue
				}
				events = []models.ScadaEvent{single}
			}

			for i := range events {
				if events[i].ReceivedAt.IsZero() {
					events[i].ReceivedAt = time.Now()
				}
				if events[i].Source == "" {
					events[i].Source = "Unknown_SCADA"
				}
			}

			batch.events = append(batch.events, events...)
			batch.msgs = append(batch.msgs, msg)

			if len(batch.events) >= cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}
