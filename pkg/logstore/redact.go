package logstore

import (
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var userInfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^\s/]+@`)
var authLine = regexp.MustCompile(`(?im)\b(authorization|proxy-authorization|cookie|set-cookie)(["']?\s*[:=]\s*)[^\r\n]+`)
var authValue = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[a-z0-9._~+/=-]+`)
var secretValue = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:password|passwd|token|api[_-]?key|secret|credential)[a-z0-9_.-]*)(["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s&,;#}]+)`)

func bounded(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	value = value[:max(0, limit-3)]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value + "…"
}
func RedactText(value string) string {
	if len(value) > 8192 {
		return "[log text exceeded limit]"
	}
	value = userInfo.ReplaceAllString(value, "${1}[redacted]@")
	value = authLine.ReplaceAllString(value, "${1}${2}[redacted]")
	value = authValue.ReplaceAllString(value, "${1} [redacted]")
	value = secretValue.ReplaceAllString(value, "${1}${2}[redacted]")
	return bounded(value, 2048)
}
func secretKey(key string) bool {
	if len(key) > 128 {
		return true
	}
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
	for _, secret := range []string{"password", "passwd", "token", "secret", "credential", "authorization", "cookie", "apikey", "privatekey"} {
		if strings.Contains(key, secret) {
			return true
		}
	}
	return key == "config" || key == "configuration" || key == "username" || key == "userinfo"
}
func sanitizeRecord(record Record) Record {
	record.ID = 0
	if record.Time.IsZero() || record.Time.Year() < 0 || record.Time.Year() > 9999 {
		record.Time = time.Now()
	}
	record.Time = record.Time.UTC()
	record.Source = bounded(RedactText(record.Source), 64)
	record.Message = RedactText(record.Message)
	var level slog.Level
	if level.UnmarshalText([]byte(record.Level)) != nil {
		level = slog.LevelInfo
	}
	record.Level = level.String()
	attrs := map[string]any{}
	sanitizer := sanitizer{remaining: 128}
	count := 0
	for key, value := range record.Attrs {
		if count >= 32 {
			attrs["truncated"] = true
			break
		}
		count++
		outKey := bounded(RedactText(key), 128)
		if secretKey(key) {
			attrs[outKey] = "[redacted]"
		} else {
			attrs[outKey] = sanitizer.value(reflect.ValueOf(value), 0)
		}
	}
	record.Attrs = attrs
	return record
}

type sanitizer struct{ remaining int }

func (s *sanitizer) value(value reflect.Value, depth int) (result any) {
	defer func() {
		if recover() != nil {
			result = "[unavailable log value]"
		}
	}()
	if !value.IsValid() {
		return nil
	}
	if depth > 4 || s.remaining <= 0 {
		return "[truncated]"
	}
	s.remaining--
	if value.CanInterface() {
		switch v := value.Interface().(type) {
		case time.Time:
			return v.UTC().Format(time.RFC3339Nano)
		case error:
			return bounded(RedactText(v.Error()), 512)
		case slog.Value:
			return s.slogValue(v, depth+1)
		}
	}
	switch value.Kind() {
	case reflect.String:
		return bounded(RedactText(value.String()), 512)
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		v := value.Float()
		if v != v || v > 1.7976931348623157e308 || v < -1.7976931348623157e308 {
			return "[non-finite]"
		}
		return v
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return s.value(value.Elem(), depth+1)
	case reflect.Map:
		result := map[string]any{}
		if value.Type().Key().Kind() != reflect.String {
			return "[unsupported map]"
		}
		iterator := value.MapRange()
		count := 0
		for iterator.Next() {
			if count >= 16 {
				result["truncated"] = true
				break
			}
			count++
			key := iterator.Key().String()
			outKey := bounded(RedactText(key), 128)
			if secretKey(key) {
				result[outKey] = "[redacted]"
			} else {
				result[outKey] = s.value(iterator.Value(), depth+1)
			}
		}
		return result
	case reflect.Slice, reflect.Array:
		result := []any{}
		for i := 0; i < min(value.Len(), 16); i++ {
			result = append(result, s.value(value.Index(i), depth+1))
		}
		if value.Len() > 16 {
			result = append(result, "[truncated]")
		}
		return result
	case reflect.Struct:
		result := map[string]any{}
		count := 0
		for i := 0; i < value.NumField() && count < 16; i++ {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			count++
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if key == "-" {
				continue
			}
			if key == "" {
				key = field.Name
			}
			outKey := bounded(RedactText(key), 128)
			if secretKey(key) {
				result[outKey] = "[redacted]"
			} else {
				result[outKey] = s.value(value.Field(i), depth+1)
			}
		}
		return result
	default:
		return "[" + value.Kind().String() + "]"
	}
}
func (s *sanitizer) slogValue(value slog.Value, depth int) any {
	if depth > 4 || s.remaining <= 0 {
		return "[truncated]"
	}
	s.remaining--
	value = value.Resolve()
	if value.Kind() == slog.KindGroup {
		attrs := map[string]any{}
		for i, attr := range value.Group() {
			if i >= 16 {
				attrs["truncated"] = true
				break
			}
			key := attr.Key
			outKey := bounded(RedactText(key), 128)
			if secretKey(key) {
				attrs[outKey] = "[redacted]"
			} else {
				attrs[outKey] = s.slogValue(attr.Value, depth+1)
			}
		}
		return attrs
	}
	if value.Kind() == slog.KindDuration {
		return value.Duration().String()
	}
	if value.Kind() == slog.KindTime {
		return value.Time().UTC().Format(time.RFC3339Nano)
	}
	if value.Kind() == slog.KindAny {
		return s.value(reflect.ValueOf(value.Any()), depth+1)
	}
	return s.value(reflect.ValueOf(value.Any()), depth+1)
}
