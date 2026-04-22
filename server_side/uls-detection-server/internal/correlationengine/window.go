package correlationengine

import "time"

// LastClosedWindow returns the most recently closed tumbling window in UTC.
func LastClosedWindow(now time.Time, windowMinutes int) (time.Time, time.Time) {
	if windowMinutes <= 0 {
		windowMinutes = 10
	}

	nowUTC := now.UTC()
	window := time.Duration(windowMinutes) * time.Minute
	end := nowUTC.Truncate(window)
	start := end.Add(-window)
	return start, end
}
