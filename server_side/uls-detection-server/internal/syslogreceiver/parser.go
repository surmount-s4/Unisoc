package syslogreceiver

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"uls-detection-server/internal/models"
)

var (
	syslogHeaderRe = regexp.MustCompile(`^<\d+>\S+\s+\S+\s+`)
	kvPairRe       = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([^\s]*))`)
)

// Normalize converts a raw syslog line into the internal FirewallEvent model.
// It supports generic key=value logs, FortiGate style key=value logs, and CEF.
func Normalize(rawLine, sensorIP string, now time.Time) (models.FirewallEvent, bool) {
	raw := strings.TrimSpace(rawLine)
	if raw == "" {
		return models.FirewallEvent{}, false
	}

	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	body := stripSyslogHeader(raw)
	fields := map[string]string{}

	switch {
	case strings.HasPrefix(body, "CEF:"):
		fields = parseCEF(body)
	case strings.Contains(body, "="):
		fields = parseKV(body)
	default:
		fields["message"] = body
	}

	event := mapToFirewallEvent(fields, raw, sensorIP, now)
	if event.Message == "" && len(fields) == 0 {
		return models.FirewallEvent{}, false
	}
	return event, true
}

func stripSyslogHeader(raw string) string {
	stripped := strings.TrimSpace(syslogHeaderRe.ReplaceAllString(raw, ""))
	if stripped == "" {
		return raw
	}

	// RFC5424-like fallback: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
	if strings.HasPrefix(raw, "<") {
		if idx := strings.Index(raw, ">"); idx != -1 && idx+1 < len(raw) {
			candidate := strings.TrimSpace(raw[idx+1:])
			if strings.HasPrefix(candidate, "1 ") || strings.HasPrefix(candidate, "2 ") {
				parts := strings.SplitN(candidate, " ", 7)
				if len(parts) == 7 {
					return strings.TrimSpace(parts[6])
				}
			}
		}
	}

	return stripped
}

func parseKV(text string) map[string]string {
	out := make(map[string]string)
	for _, m := range kvPairRe.FindAllStringSubmatch(text, -1) {
		key := m[1]
		val := ""
		if len(m) > 2 && m[2] != "" {
			val = m[2]
		} else if len(m) > 3 {
			val = m[3]
		}
		if key != "" && val != "" {
			out[key] = val
		}
	}
	return out
}

func parseCEF(text string) map[string]string {
	out := make(map[string]string)
	parts := strings.SplitN(text, "|", 8)
	if len(parts) < 7 {
		return out
	}

	out["cef_device_vendor"] = strings.TrimPrefix(parts[0], "CEF:")
	out["cef_device_product"] = parts[1]
	out["cef_device_version"] = parts[2]
	out["cef_signature_id"] = parts[3]
	out["log_component"] = parts[4]
	out["cef_name"] = parts[5]
	out["cef_severity"] = parts[6]

	if len(parts) == 8 {
		for k, v := range parseKV(parts[7]) {
			out[k] = v
		}
	}
	return out
}

func mapToFirewallEvent(f map[string]string, raw, sensorIP string, now time.Time) models.FirewallEvent {
	protocol := firstNonEmpty(
		f["protocol"],
		normalizeProtocolValue(f["proto"]),
	)

	msg := firstNonEmpty(
		f["message"],
		f["msg"],
		f["cef_name"],
	)

	logType := firstNonEmpty(f["log_type"], f["type"])
	logSubtype := firstNonEmpty(f["log_subtype"], f["subtype"])

	return models.FirewallEvent{
		ReceivedAt: now,
		SensorIP:   strings.TrimSpace(sensorIP),
		RawLog:     raw,

		DeviceName: firstNonEmpty(f["device_name"], f["devname"], f["device"]),
		DeviceID:   firstNonEmpty(f["device_id"], f["devid"]),

		LogDate:  firstNonEmpty(f["log_date"], f["date"]),
		LogTime:  firstNonEmpty(f["log_time"], f["time"]),
		Timezone: firstNonEmpty(f["timezone"], f["tz"]),

		LogID:        firstNonEmpty(f["log_id"], f["logid"], f["cef_signature_id"]),
		LogType:      logType,
		LogComponent: firstNonEmpty(f["log_component"], logType),
		LogSubtype:   logSubtype,
		Status:       firstNonEmpty(f["status"]),
		Priority:     firstNonEmpty(f["priority"], f["level"], f["cef_severity"]),
		Action:       firstNonEmpty(f["action"], f["act"], f["status"]),

		SrcIP:       firstNonEmpty(f["src_ip"], f["srcip"], f["src"]),
		SrcPort:     firstNonEmpty(f["src_port"], f["srcport"], f["spt"]),
		SrcMAC:      firstNonEmpty(f["src_mac"], f["srcmac"]),
		SrcCountry:  firstNonEmpty(f["src_country_code"], f["srccountry"]),
		SrcZone:     firstNonEmpty(f["src_zone"], f["srcintf"], f["srcinterface"], f["srczone"]),
		SrcZoneType: firstNonEmpty(f["src_zone_type"], f["srcintfrole"], f["srczonetype"]),
		SrcTransIP:  firstNonEmpty(f["src_trans_ip"], f["transip"]),

		DstIP:       firstNonEmpty(f["dst_ip"], f["dstip"], f["dst"], f["dstaddr"]),
		DstPort:     firstNonEmpty(f["dst_port"], f["dstport"], f["dpt"]),
		DstCountry:  firstNonEmpty(f["dst_country_code"], f["dstcountry"]),
		DstZone:     firstNonEmpty(f["dst_zone"], f["dstintf"], f["dstinterface"], f["dstzone"]),
		DstZoneType: firstNonEmpty(f["dst_zone_type"], f["dstintfrole"], f["dstzonetype"]),

		Protocol:  protocol,
		EtherType: firstNonEmpty(f["ether_type"]),
		ConnEvent: firstNonEmpty(f["conn_event"], f["event"], f["action"]),
		ConnID:    firstNonEmpty(f["conn_id"], f["connid"], f["sessionid"], f["session_id"]),

		SentBytes: firstNonEmpty(f["sent_bytes"], f["sentbyte"], f["bytes_sent"], "0"),
		RecvBytes: firstNonEmpty(f["recv_bytes"], f["rcvdbyte"], f["bytes_received"], "0"),
		SentPkts:  firstNonEmpty(f["sent_pkts"], f["sentpkt"], "0"),
		RecvPkts:  firstNonEmpty(f["recv_pkts"], f["rcvdpkt"], "0"),

		FwRuleID:  firstNonEmpty(f["fw_rule_id"], f["policyid"], f["ruleid"]),
		NatRuleID: firstNonEmpty(f["nat_rule_id"]),
		FwType:    firstNonEmpty(f["fw_type"], f["type"]),

		User:      firstNonEmpty(f["user"], f["usr"], f["dstuser"], f["srcuser"]),
		UserGroup: firstNonEmpty(f["user_group"], f["group"]),

		AppName: firstNonEmpty(f["app_name"], f["service"], f["app"], f["appid"]),
		AppRisk: firstNonEmpty(f["app_risk"], f["apprisk"], f["appcat"]),

		Message:        msg,
		Severity:       firstNonEmpty(f["severity"], f["level"], f["cef_severity"]),
		Classification: firstNonEmpty(f["classification"], f["appcat"], f["subtype"]),
		URL:            firstNonEmpty(f["url"], f["hostname"], f["dsthost"]),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func normalizeProtocolValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	switch strings.ToLower(v) {
	case "6", "tcp":
		return "TCP"
	case "17", "udp":
		return "UDP"
	case "1", "icmp":
		return "ICMP"
	}

	if n, err := strconv.Atoi(v); err == nil {
		return strconv.Itoa(n)
	}
	return strings.ToUpper(v)
}
