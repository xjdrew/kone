package logstore

import (
	"context"
	"log/slog"
)

type handler struct {
	store  *Store
	next   slog.Handler
	source string
	attrs  []boundAttr
	groups []string
	hidden bool
}
type boundAttr struct {
	attr   slog.Attr
	groups []string
}

func (s *Store) Handler(next slog.Handler, source string) slog.Handler {
	return &handler{store: s, next: next, source: source}
}
func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next == nil || h.next.Enabled(ctx, level)
}
func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	attrs := map[string]any{}
	sanitizer := sanitizer{remaining: 128}
	add := func(attr slog.Attr, groups []string) {
		if len(attrs) >= 32 {
			return
		}
		key := attr.Key
		for i := len(groups) - 1; i >= 0; i-- {
			key = groups[i] + "." + key
		}
		outKey := bounded(RedactText(key), 128)
		if secretKey(key) || h.hidden {
			attrs[outKey] = "[redacted]"
		} else {
			attrs[outKey] = sanitizer.slogValue(attr.Value, 0)
		}
	}
	for _, attr := range h.attrs {
		add(attr.attr, attr.groups)
	}
	record.Attrs(func(attr slog.Attr) bool { add(attr, h.groups); return len(attrs) < 32 })
	h.store.Append(Record{Time: record.Time, Level: record.Level.String(), Message: record.Message, Attrs: attrs, Source: h.source})
	if h.next != nil {
		safe := slog.NewRecord(record.Time, record.Level, RedactText(record.Message), record.PC)
		for key, value := range attrs {
			safe.AddAttrs(slog.Any(key, value))
		}
		return h.next.Handle(ctx, safe)
	}
	return nil
}
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := *h
	copy.attrs = append([]boundAttr(nil), h.attrs...)
	sanitizer := sanitizer{remaining: 128}
	for _, attr := range attrs {
		if len(copy.attrs) >= 32 {
			break
		}
		value := any("[redacted]")
		if !secretKey(attr.Key) && !h.hidden {
			value = sanitizer.slogValue(attr.Value, 0)
		}
		attr = slog.Any(bounded(RedactText(attr.Key), 128), value)
		copy.attrs = append(copy.attrs, boundAttr{attr, append([]string(nil), h.groups...)})
	}
	return &copy
}
func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	copy := *h
	if len(h.groups) >= 8 {
		copy.hidden = true
		return &copy
	}
	copy.groups = append(append([]string(nil), h.groups...), name)
	return &copy
}
