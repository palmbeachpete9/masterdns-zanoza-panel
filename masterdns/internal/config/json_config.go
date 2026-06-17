package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

type configSourceFormat uint8

const (
	configSourceTOML configSourceFormat = iota
	configSourceJSON
)

const maxConfigBytes = 8 << 20

var ignoredConfigKeys = map[string]struct{}{
	"CONFIG_VERSION": {},
}

func readConfigFileLimited(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("config %s exceeds the %d-byte size limit", path, maxConfigBytes)
	}
	return raw, nil
}

func decodeConfigJSONInto(dst any, raw []byte) (map[string]bool, error) {
	if dst == nil {
		return nil, fmt.Errorf("config target is nil")
	}

	doc, err := decodeUniqueJSONObject(raw)
	if err != nil {
		return nil, err
	}

	value := reflect.ValueOf(dst)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, fmt.Errorf("config target must be a non-nil pointer")
	}
	value = value.Elem()
	if value.Kind() != reflect.Struct {
		return nil, fmt.Errorf("config target must point to a struct")
	}

	valueType := value.Type()
	defined := make(map[string]bool, len(doc))
	known := make(map[string]struct{}, valueType.NumField()+len(ignoredConfigKeys))
	for key := range ignoredConfigKeys {
		known[key] = struct{}{}
	}

	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		known[tag] = struct{}{}

		rawValue, ok := doc[tag]
		if !ok {
			continue
		}
		target := value.Field(i)
		if !target.CanSet() {
			continue
		}

		if err := decodeJSONFieldInto(target, rawValue); err != nil {
			return nil, fmt.Errorf("invalid JSON config value for %s: %w", tag, err)
		}
		defined[field.Name] = true
	}
	for key := range doc {
		if _, ok := known[key]; !ok {
			return nil, fmt.Errorf("unknown JSON config key %q", key)
		}
	}

	return defined, nil
}

func decodeUniqueJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, fmt.Errorf("config root must be a JSON object")
	}
	doc := make(map[string]json.RawMessage)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("object key is not a string")
		}
		if _, duplicate := doc[key]; duplicate {
			return nil, fmt.Errorf("duplicate JSON config key %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		doc[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON")
		}
		return nil, err
	}
	return doc, nil
}

func rejectUnknownTOML(meta toml.MetaData) error {
	for _, key := range meta.Undecoded() {
		if _, ok := ignoredConfigKeys[key.String()]; !ok {
			return fmt.Errorf("unknown TOML config key %q", key.String())
		}
	}
	return nil
}

func decodeJSONFieldInto(target reflect.Value, raw json.RawMessage) error {
	switch target.Kind() {
	case reflect.String:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		target.SetString(value)
		return nil
	case reflect.Bool:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		target.SetBool(value)
		return nil
	case reflect.Int:
		var value int
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		target.SetInt(int64(value))
		return nil
	case reflect.Float64:
		var value float64
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		target.SetFloat(value)
		return nil
	case reflect.Slice:
		switch target.Type().Elem().Kind() {
		case reflect.String:
			var value []string
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			target.Set(reflect.ValueOf(value))
			return nil
		case reflect.Int:
			var value []int
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			target.Set(reflect.ValueOf(value))
			return nil
		default:
			return fmt.Errorf("unsupported slice type %s", target.Type())
		}
	default:
		return fmt.Errorf("unsupported kind %s", target.Kind())
	}
}

func decodeBase64ConfigJSON(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, fmt.Errorf("empty JSON base64 payload")
	}
	if base64.StdEncoding.DecodedLen(len(trimmed)) > maxConfigBytes {
		return nil, fmt.Errorf("decoded JSON config exceeds the %d-byte size limit", maxConfigBytes)
	}
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("decoded JSON config exceeds the %d-byte size limit", maxConfigBytes)
	}
	return raw, nil
}

func resolveConfigPathWithJSONFallback(filename string) (string, configSourceFormat, error) {
	path, err := filepath.Abs(filename)
	if err != nil {
		return "", configSourceTOML, err
	}

	if _, err := os.Stat(path); err == nil {
		if strings.EqualFold(filepath.Ext(path), ".json") {
			return path, configSourceJSON, nil
		}
		return path, configSourceTOML, nil
	}

	var jsonPath string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		jsonPath = strings.TrimSuffix(path, filepath.Ext(path)) + ".json"
	case ".json":
		jsonPath = path
	default:
		jsonPath = path + ".json"
	}

	if _, err := os.Stat(jsonPath); err == nil {
		return jsonPath, configSourceJSON, nil
	}

	return "", configSourceTOML, fmt.Errorf("config file not found: %s", path)
}

func currentWorkingConfigDir() string {
	wd, err := os.Getwd()
	if err != nil || strings.TrimSpace(wd) == "" {
		return "."
	}
	return wd
}
