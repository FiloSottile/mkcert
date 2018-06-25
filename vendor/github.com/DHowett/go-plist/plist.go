package plist

import (
	"reflect"
)

// Property list format constants
const (
	// Used by Decoder to represent an invalid property list.
	InvalidFormat int = 0

	// Used to indicate total abandon with regards to Encoder's output format.
	AutomaticFormat = 0

	XMLFormat      = 1
	BinaryFormat   = 2
	OpenStepFormat = 3
	GNUStepFormat  = 4
)

var FormatNames = map[int]string{
	InvalidFormat:  "unknown/invalid",
	XMLFormat:      "XML",
	BinaryFormat:   "Binary",
	OpenStepFormat: "OpenStep",
	GNUStepFormat:  "GNUStep",
}

type unknownTypeError struct {
	typ reflect.Type
}

func (u *unknownTypeError) Error() string {
	return "plist: can't marshal value of type " + u.typ.String()
}

type invalidPlistError struct {
	format string
	err    error
}

func (e invalidPlistError) Error() string {
	s := "plist: invalid " + e.format + " property list"
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

type plistParseError struct {
	format string
	err    error
}

func (e plistParseError) Error() string {
	s := "plist: error parsing " + e.format + " property list"
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

// A UID represents a unique object identifier. UIDs are serialized in a manner distinct from
// that of integers.
//
// UIDs cannot be serialized in OpenStepFormat or GNUStepFormat property lists.
type UID uint64

// Marshaler is the interface implemented by types that can marshal themselves into valid
// property list objects. The returned value is marshaled in place of the original value
// implementing Marshaler
//
// If an error is returned by MarshalPlist, marshaling stops and the error is returned.
type Marshaler interface {
	MarshalPlist() (interface{}, error)
}

// Unmarshaler is the interface implemented by types that can unmarshal themselves from
// property list objects. The UnmarshalPlist method receives a function that may
// be called to unmarshal the original property list value into a field or variable.
//
// It is safe to call the unmarshal function more than once.
type Unmarshaler interface {
	UnmarshalPlist(unmarshal func(interface{}) error) error
}
