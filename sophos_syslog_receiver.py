#!/usr/bin/env python3
"""
sophos_syslog_receiver.py
─────────────────────────
Receives Sophos XG / SFOS syslog events over UDP, parses key=value (or CEF)
format, and forwards batches to RabbitMQ → firewall_events queue.

Falls back to stdout-only mode if RabbitMQ is unreachable.

Usage:
    pip install pika
    python sophos_syslog_receiver.py [--rmq-host HOST] [--rmq-port PORT] ...
"""

import socket
import json
import re
import sys
import os
import threading
import queue as queue_module
import logging
import argparse
from datetime import datetime, timezone

try:
    import pika
    PIKA_AVAILABLE = True
except ImportError:
    PIKA_AVAILABLE = False

# ─── Defaults ────────────────────────────────────────────────────────────────
LISTEN_HOST      = "0.0.0.0"
LISTEN_PORT      = 5514
BUFFER_SIZE      = 8192
RABBITMQ_HOST    = os.getenv("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT    = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER    = os.getenv("RABBITMQ_USER", "admin")
RABBITMQ_PASS    = os.getenv("RABBITMQ_PASSWORD", os.getenv("RABBITMQ_PASS", "admin"))
RABBITMQ_QUEUE   = os.getenv("RABBITMQ_FW_QUEUE", os.getenv("RABBITMQ_QUEUE", "firewall_events"))
BATCH_SIZE       = 50
FLUSH_INTERVAL   = 2.0      # seconds

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sophos")

# ─── Parsers ─────────────────────────────────────────────────────────────────
# Matches syslog priority + header: <14>2024-01-15T10:30:00+05:30 hostname
_SYSLOG_HEADER = re.compile(r"^<\d+>\S+\s+\S+\s+")
# Matches key=value or key="quoted value" (handles empty values)
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|([^\s]*))')


def _parse_kv(text: str) -> dict:
    """Parse a Sophos XG key=value log line into a flat dict."""
    stripped = _SYSLOG_HEADER.sub("", text, count=1)
    out = {}
    for m in _KV_RE.finditer(stripped):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        if val:                          # skip empty values
            out[key] = val
    return out


def _parse_cef(text: str) -> dict:
    """Parse CEF:0|... format (alternative Sophos output mode)."""
    if not text.startswith("CEF:"):
        return {}
    parts = text.split("|", 7)
    if len(parts) < 7:
        return {}
    out = {
        "cef_device_vendor":  parts[1],
        "cef_device_product": parts[2],
        "cef_device_version": parts[3],
        "cef_signature_id":   parts[4],
        "log_component":      parts[5],
        "cef_severity":       parts[6],
    }
    if len(parts) == 8:
        for m in _KV_RE.finditer(parts[7]):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3)
            if val:
                out[key] = val
    return out


def normalize(raw: str, sensor_ip: str) -> dict | None:
    """
    Convert a raw Sophos syslog line into a normalized FirewallEvent dict
    that matches the Go FirewallEvent model.
    """
    raw = raw.strip()
    if not raw:
        return None

    # Choose parser
    if "log_type=" in raw or "device=" in raw:
        f = _parse_kv(raw)
    elif raw.startswith("CEF:"):
        f = _parse_cef(raw)
    else:
        f = {"message": raw}          # unknown format – store raw

    now = datetime.now(timezone.utc).isoformat()

    return {
        # ── Source metadata ──────────────────────────────────────────────────
        "source_type": "sophos_firewall",
        "received_at": now,
        "sensor_ip":   sensor_ip,
        "raw_log":     raw,

        # ── Device ───────────────────────────────────────────────────────────
        "device_name": f.get("device_name", ""),
        "device_id":   f.get("device_id",   ""),

        # ── Timestamps ───────────────────────────────────────────────────────
        "log_date": f.get("date",     ""),
        "log_time": f.get("time",     ""),
        "timezone": f.get("timezone", ""),

        # ── Classification ───────────────────────────────────────────────────
        "log_id":        f.get("log_id",        ""),
        "log_type":      f.get("log_type",      ""),
        "log_component": f.get("log_component", ""),
        "log_subtype":   f.get("log_subtype",   ""),
        "status":        f.get("status",        ""),
        "priority":      f.get("priority",      ""),
        "action":        f.get("action",        f.get("status", "")),

        # ── Source network ───────────────────────────────────────────────────
        "src_ip":          f.get("src_ip",          ""),
        "src_port":        f.get("src_port",        ""),
        "src_mac":         f.get("src_mac",         ""),
        "src_country_code":f.get("src_country_code",""),
        "src_zone":        f.get("srczone",         ""),
        "src_zone_type":   f.get("srczonetype",     ""),
        "src_trans_ip":    f.get("src_trans_ip",    ""),

        # ── Destination network ──────────────────────────────────────────────
        "dst_ip":          f.get("dst_ip",          ""),
        "dst_port":        f.get("dst_port",        ""),
        "dst_country_code":f.get("dst_country_code",""),
        "dst_zone":        f.get("dstzone",         ""),
        "dst_zone_type":   f.get("dstzonetype",     ""),

        # ── Protocol ─────────────────────────────────────────────────────────
        "protocol":   f.get("protocol",   ""),
        "ether_type": f.get("ether_type", ""),
        "conn_event": f.get("connevent",  ""),
        "conn_id":    f.get("connid",     ""),

        # ── Traffic stats ────────────────────────────────────────────────────
        "sent_bytes": f.get("sent_bytes", "0"),
        "recv_bytes": f.get("recv_bytes", "0"),
        "sent_pkts":  f.get("sent_pkts",  "0"),
        "recv_pkts":  f.get("recv_pkts",  "0"),

        # ── Firewall policy ──────────────────────────────────────────────────
        "fw_rule_id":  f.get("fw_rule_id",  ""),
        "nat_rule_id": f.get("nat_rule_id", ""),
        "fw_type":     f.get("type",        ""),

        # ── User ─────────────────────────────────────────────────────────────
        "user":       f.get("user",       ""),
        "user_group": f.get("user_group", ""),

        # ── Application (DPI) ────────────────────────────────────────────────
        "app_name": f.get("app_name", ""),
        "app_risk":  f.get("app_risk",  ""),

        # ── Threat / IPS / ATP ───────────────────────────────────────────────
        "message":        f.get("message",        ""),
        "severity":       f.get("severity",       ""),
        "classification": f.get("classification", ""),
        "url":            f.get("url", f.get("dst_host", "")),
    }


# ─── RabbitMQ Publisher ───────────────────────────────────────────────────────

class RabbitMQPublisher:
    """Wraps a pika BlockingConnection with auto-reconnect."""

    def __init__(self, host, port, user, password, queue_name):
        self._params = pika.ConnectionParameters(
            host=host,
            port=port,
            credentials=pika.PlainCredentials(user, password),
            heartbeat=60,
            blocked_connection_timeout=300,
        )
        self._queue = queue_name
        self._conn  = None
        self._ch    = None
        self._connect()

    def _connect(self):
        self._conn = pika.BlockingConnection(self._params)
        self._ch   = self._conn.channel()
        self._ch.queue_declare(
            queue=self._queue,
            durable=True,
            arguments={"x-queue-type": "classic"},
        )
        log.info(f"RabbitMQ connected → queue '{self._queue}'")

    def publish(self, events: list) -> bool:
        body = json.dumps(events).encode("utf-8")
        props = pika.BasicProperties(delivery_mode=2, content_type="application/json")
        for attempt in range(2):
            try:
                self._ch.basic_publish(exchange="", routing_key=self._queue,
                                       body=body, properties=props)
                return True
            except Exception as exc:
                if attempt == 0:
                    log.warning(f"Publish failed ({exc}), reconnecting…")
                    try:
                        self._connect()
                    except Exception:
                        pass
                else:
                    log.error(f"Publish failed after reconnect: {exc}")
        return False

    def close(self):
        try:
            if self._conn and not self._conn.is_closed:
                self._conn.close()
        except Exception:
            pass


# ─── Batch Publisher Thread ───────────────────────────────────────────────────

class BatchPublisher(threading.Thread):
    """Collects events and flushes to RabbitMQ in batches."""

    def __init__(self, publisher: RabbitMQPublisher, batch_size: int, flush_sec: float):
        super().__init__(daemon=True, name="batch-pub")
        self._pub        = publisher
        self._batch_size = batch_size
        self._flush_sec  = flush_sec
        self._q          = queue_module.Queue(maxsize=20_000)
        self._stop       = threading.Event()
        self.sent_total  = 0
        self.drop_total  = 0

    def enqueue(self, event: dict):
        try:
            self._q.put_nowait(event)
        except queue_module.Full:
            self.drop_total += 1
            log.warning("Queue full – dropping 1 event")

    def run(self):
        import time
        batch      = []
        last_flush = time.monotonic()

        while not self._stop.is_set():
            try:
                ev = self._q.get(timeout=0.1)
                batch.append(ev)
            except queue_module.Empty:
                pass

            now    = time.monotonic()
            flush  = len(batch) >= self._batch_size
            flush |= bool(batch) and (now - last_flush) >= self._flush_sec

            if flush:
                if self._pub.publish(batch):
                    self.sent_total += len(batch)
                    log.info(f"→ RabbitMQ: {len(batch)} events (total {self.sent_total})")
                batch      = []
                last_flush = now

        # Drain remaining
        if batch:
            self._pub.publish(batch)

    def stop(self):
        self._stop.set()


# ─── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Sophos XG Syslog → RabbitMQ forwarder")
    p.add_argument("--host",           default=LISTEN_HOST,   help="UDP bind address")
    p.add_argument("--port",  type=int, default=LISTEN_PORT,   help="UDP syslog port")
    p.add_argument("--rmq-host",       default=RABBITMQ_HOST)
    p.add_argument("--rmq-port",type=int,default=RABBITMQ_PORT)
    p.add_argument("--rmq-user",       default=RABBITMQ_USER)
    p.add_argument("--rmq-pass",       default=RABBITMQ_PASS)
    p.add_argument("--rmq-queue",      default=RABBITMQ_QUEUE)
    p.add_argument("--batch-size",type=int,default=BATCH_SIZE)
    p.add_argument("--flush-sec", type=float,default=FLUSH_INTERVAL)
    p.add_argument("--verbose",   action="store_true", help="Print every parsed event")
    return p.parse_args()


def main():
    args = parse_args()

    # ── RabbitMQ setup ────────────────────────────────────────────────────────
    publisher  = None
    batch_pub  = None

    if not PIKA_AVAILABLE:
        log.warning("pika not installed – stdout only mode (run: pip install pika)")
    else:
        try:
            publisher = RabbitMQPublisher(
                args.rmq_host, args.rmq_port,
                args.rmq_user, args.rmq_pass,
                args.rmq_queue,
            )
            batch_pub = BatchPublisher(publisher, args.batch_size, args.flush_sec)
            batch_pub.start()
        except Exception as exc:
            log.warning(f"Cannot reach RabbitMQ ({exc}) – stdout only mode")
            publisher = None

    # ── UDP socket ────────────────────────────────────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))

    print(f"\n{'─'*60}")
    print(f"  Sophos Syslog Receiver  (UDP {args.host}:{args.port})")
    if publisher:
        print(f"  → RabbitMQ {args.rmq_host}:{args.rmq_port}  queue={args.rmq_queue}")
    else:
        print(f"  → stdout only (no RabbitMQ)")
    print(f"{'─'*60}\n")

    recv_total = 0
    try:
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            raw  = data.decode("utf-8", errors="ignore")
            ev   = normalize(raw, addr[0])
            recv_total += 1

            if ev is None:
                continue

            # Console output
            ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src     = ev.get("src_ip", "?")
            dst     = ev.get("dst_ip", "?")
            dport   = ev.get("dst_port", "?")
            action  = ev.get("action",  "?")
            ltype   = ev.get("log_type","?")

            if args.verbose or not publisher:
                print(f"{ts} | {addr[0]:15} | [{ltype:10}] {src} → {dst}:{dport} | {action}")

            if batch_pub:
                batch_pub.enqueue(ev)

    except KeyboardInterrupt:
        print(f"\n[STOP] Received {recv_total} messages")
    finally:
        sock.close()
        if batch_pub:
            batch_pub.stop()
            batch_pub.join(timeout=5)
            log.info(f"Sent: {batch_pub.sent_total}  Dropped: {batch_pub.drop_total}")
        if publisher:
            publisher.close()


if __name__ == "__main__":
    main()
