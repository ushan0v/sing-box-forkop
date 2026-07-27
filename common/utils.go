package common

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

func StringToType[T any](str string) T {
	var value T
	v := reflect.ValueOf(&value).Elem()
	switch any(value).(type) {
	case badoption.Duration:
		d, err := time.ParseDuration(str)
		if err != nil {
			v.SetInt(StringToType[int64](str))
		} else {
			v.SetInt(int64(d))
		}
		return value
	case badoption.HTTPHeader:
		headers := badoption.HTTPHeader{}
		reg := regexp.MustCompile(`^[ \t]*?(\S+?):[ \t]*?(\S+?)[ \t]*?$`)
		for _, header := range strings.Split(str, "\n") {
			result := reg.FindStringSubmatch(header)
			if result != nil {
				key := result[1]
				headers[key] = strings.Split(result[2], ",")
			}
		}
		v.Set(reflect.ValueOf(headers))
		return value
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, _ := strconv.ParseInt(str, 10, 64)
		v.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, _ := strconv.ParseUint(str, 10, 64)
		v.SetUint(i)
	case reflect.Float32, reflect.Float64:
		f, _ := strconv.ParseFloat(str, 64)
		v.SetFloat(f)
	case reflect.Bool:
		b, _ := strconv.ParseBool(str)
		v.SetBool(b)
	default:
		panic("unsupported type")
	}
	return value
}

func DecodeBase64URLSafe(content string) (string, error) {
	s := strings.ReplaceAll(content, " ", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "=", "")
	result, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return content, nil
	}
	return string(result), nil
}

func ParseXHTTPRange(value string) (badoption.Range[int], error) {
	result := badoption.Range[int]{}
	encoded, err := json.Marshal(value)
	if err != nil {
		return result, err
	}
	return result, result.UnmarshalJSON(encoded)
}
