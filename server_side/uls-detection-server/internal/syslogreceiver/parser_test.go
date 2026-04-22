package syslogreceiver

import (
	"testing"
	"time"
)

func TestNormalizeFortiGateKV(t *testing.T) {
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	raw := `<189>date=2022-11-02 time=13:37:42 devname="FGT01" devid="FGVM010000085566" logid="0000000015" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.130.8.206 srcport=49219 srcintf="port3" srcintfrole="lan" dstip=184.51.105.193 dstport=443 dstintf="port2" dstintfrole="wan" proto=6 action="start" policyid=1 service="HTTPS" sentbyte=100 rcvdbyte=200 sentpkt=1 rcvdpkt=2 msg="Allowed"`

	ev, ok := Normalize(raw, "192.168.1.5", now)
	if !ok {
		t.Fatalf("expected parsed event")
	}
	if ev.DeviceName != "FGT01" {
		t.Fatalf("unexpected device_name: %s", ev.DeviceName)
	}
	if ev.LogType != "traffic" || ev.LogSubtype != "forward" {
		t.Fatalf("unexpected log type/subtype: %s/%s", ev.LogType, ev.LogSubtype)
	}
	if ev.SrcIP != "10.130.8.206" || ev.DstIP != "184.51.105.193" {
		t.Fatalf("unexpected src/dst: %s -> %s", ev.SrcIP, ev.DstIP)
	}
	if ev.Protocol != "TCP" {
		t.Fatalf("expected protocol TCP, got: %s", ev.Protocol)
	}
	if ev.FwRuleID != "1" {
		t.Fatalf("expected policyid mapped to fw_rule_id")
	}
	if ev.SentBytes != "100" || ev.RecvBytes != "200" {
		t.Fatalf("unexpected byte counters: %s/%s", ev.SentBytes, ev.RecvBytes)
	}
}

func TestNormalizeSophosKV(t *testing.T) {
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	raw := `<14>2024-01-15T10:30:00+05:30 fw01 log_type="Firewall" action="DROP" src_ip="10.0.0.10" dst_ip="8.8.8.8" dst_port=53 protocol="TCP" message="Denied request"`

	ev, ok := Normalize(raw, "10.0.0.1", now)
	if !ok {
		t.Fatalf("expected parsed event")
	}
	if ev.LogType != "Firewall" || ev.Action != "DROP" {
		t.Fatalf("unexpected type/action: %s/%s", ev.LogType, ev.Action)
	}
	if ev.DstPort != "53" || ev.Protocol != "TCP" {
		t.Fatalf("unexpected network fields: port=%s proto=%s", ev.DstPort, ev.Protocol)
	}
}

func TestNormalizeCEF(t *testing.T) {
	now := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	raw := `CEF:0|Fortinet|FortiGate|7.2|0001|traffic event|5|src=10.0.0.1 dst=8.8.8.8 spt=12345 dpt=443 proto=6 act=ALLOW`

	ev, ok := Normalize(raw, "10.10.10.10", now)
	if !ok {
		t.Fatalf("expected parsed event")
	}
	if ev.LogComponent == "" {
		t.Fatalf("expected log component from CEF")
	}
	if ev.SrcIP != "10.0.0.1" || ev.DstIP != "8.8.8.8" {
		t.Fatalf("unexpected src/dst: %s -> %s", ev.SrcIP, ev.DstIP)
	}
}
