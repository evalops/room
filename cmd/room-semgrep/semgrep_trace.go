package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

type semgrepTraceRange struct {
	Path       string
	Start, End int
}

func semgrepTraceRanges(data []byte) ([]semgrepTraceRange, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("dataflow trace must contain one JSON value")
	}
	trace, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("dataflow trace must be an object")
	}
	source, hasSource := trace["taint_source"]
	sink, hasSink := trace["taint_sink"]
	if !hasSource || !hasSink {
		return nil, errors.New("dataflow trace must contain source and sink")
	}
	ranges := make([]semgrepTraceRange, 0, 3)
	if err := collectSemgrepCallTrace(source, &ranges); err != nil {
		return nil, err
	}
	if intermediate, present := trace["intermediate_vars"]; present {
		values, ok := intermediate.([]any)
		if !ok {
			return nil, errors.New("dataflow trace intermediates must be an array")
		}
		for _, value := range values {
			if err := collectSemgrepIntermediate(value, &ranges); err != nil {
				return nil, err
			}
		}
	}
	if err := collectSemgrepCallTrace(sink, &ranges); err != nil {
		return nil, err
	}
	return ranges, nil
}

func collectSemgrepCallTrace(value any, ranges *[]semgrepTraceRange) error {
	variant, ok := value.([]any)
	if !ok || len(variant) != 2 {
		return errors.New("invalid dataflow call trace")
	}
	kind, ok := variant[0].(string)
	if !ok {
		return errors.New("invalid dataflow call trace kind")
	}
	switch kind {
	case "CliLoc":
		return collectSemgrepLocAndContent(variant[1], ranges)
	case "CliCall":
		call, ok := variant[1].([]any)
		if !ok || len(call) != 3 {
			return errors.New("invalid dataflow call")
		}
		if err := collectSemgrepLocAndContent(call[0], ranges); err != nil {
			return err
		}
		intermediates, ok := call[1].([]any)
		if !ok {
			return errors.New("invalid call intermediates")
		}
		for _, intermediate := range intermediates {
			if err := collectSemgrepIntermediate(intermediate, ranges); err != nil {
				return err
			}
		}
		return collectSemgrepCallTrace(call[2], ranges)
	default:
		return errors.New("unknown dataflow call trace kind")
	}
}

func collectSemgrepLocAndContent(value any, ranges *[]semgrepTraceRange) error {
	locationAndContent, ok := value.([]any)
	if !ok || len(locationAndContent) != 2 {
		return errors.New("invalid dataflow location and content")
	}
	if _, ok := locationAndContent[1].(string); !ok {
		return errors.New("invalid dataflow location content")
	}
	return collectSemgrepLocation(locationAndContent[0], ranges)
}

func collectSemgrepIntermediate(value any, ranges *[]semgrepTraceRange) error {
	intermediate, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid dataflow intermediate")
	}
	if _, ok := intermediate["content"].(string); !ok {
		return errors.New("invalid dataflow intermediate content")
	}
	return collectSemgrepLocation(intermediate["location"], ranges)
}

func collectSemgrepLocation(value any, ranges *[]semgrepTraceRange) error {
	location, ok := value.(map[string]any)
	if !ok {
		return errors.New("invalid dataflow location")
	}
	path, pathOK := location["path"].(string)
	start, startOK := semgrepTraceLine(location["start"])
	end, endOK := semgrepTraceLine(location["end"])
	if !pathOK || !startOK || !endOK || path == "" || start < 1 || end < start {
		return errors.New("invalid dataflow trace location")
	}
	*ranges = append(*ranges, semgrepTraceRange{Path: path, Start: start, End: end})
	return nil
}

func semgrepTraceLine(value any) (int, bool) {
	position, ok := value.(map[string]any)
	if !ok {
		return 0, false
	}
	line, ok := position["line"].(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(string(line))
	return parsed, err == nil
}
