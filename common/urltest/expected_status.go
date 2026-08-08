package urltest

import (
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ranges"
)

type ExpectedStatus []ranges.Range[uint16]

func ParseExpectedStatus(value string) (ExpectedStatus, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" {
		return nil, nil
	}

	parts := strings.Split(strings.ReplaceAll(value, ",", "/"), "/")
	if len(parts) > 28 {
		return nil, E.New("too many expected status ranges")
	}

	result := make(ExpectedStatus, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, E.New("invalid expected status range: ", part)
		}
		start, err := strconv.ParseUint(strings.Trim(bounds[0], "[ ]"), 10, 16)
		if err != nil {
			return nil, E.New("invalid expected status range: ", part)
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.ParseUint(strings.Trim(bounds[1], "[ ]"), 10, 16)
			if err != nil {
				return nil, E.New("invalid expected status range: ", part)
			}
		}
		if start > end {
			start, end = end, start
		}
		result = append(result, ranges.New(uint16(start), uint16(end)))
	}
	return result, nil
}

func (s ExpectedStatus) Contains(value uint16) bool {
	if len(s) == 0 {
		return true
	}
	for _, item := range s {
		if value >= item.Start && value <= item.End {
			return true
		}
	}
	return false
}
