package plist

import (
	"encoding"
	"fmt"
	"reflect"
	"runtime"
	"time"
)

type incompatibleDecodeTypeError struct {
	dest reflect.Type
	src  string // type name (from cfValue)
}

func (u *incompatibleDecodeTypeError) Error() string {
	return fmt.Sprintf("plist: type mismatch: tried to decode plist type `%v' into value of type `%v'", u.src, u.dest)
}

var (
	plistUnmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()
	textUnmarshalerType  = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	uidType              = reflect.TypeOf(UID(0))
)

func isEmptyInterface(v reflect.Value) bool {
	return v.Kind() == reflect.Interface && v.NumMethod() == 0
}

func (p *Decoder) unmarshalPlistInterface(pval cfValue, unmarshalable Unmarshaler) {
	err := unmarshalable.UnmarshalPlist(func(i interface{}) (err error) {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(runtime.Error); ok {
					panic(r)
				}
				err = r.(error)
			}
		}()
		p.unmarshal(pval, reflect.ValueOf(i))
		return
	})

	if err != nil {
		panic(err)
	}
}

func (p *Decoder) unmarshalTextInterface(pval cfString, unmarshalable encoding.TextUnmarshaler) {
	err := unmarshalable.UnmarshalText([]byte(pval))
	if err != nil {
		panic(err)
	}
}

func (p *Decoder) unmarshalTime(pval cfDate, val reflect.Value) {
	val.Set(reflect.ValueOf(time.Time(pval)))
}

func (p *Decoder) unmarshalLaxString(s string, val reflect.Value) {
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := mustParseInt(s, 10, 64)
		val.SetInt(i)
		return
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		i := mustParseUint(s, 10, 64)
		val.SetUint(i)
		return
	case reflect.Float32, reflect.Float64:
		f := mustParseFloat(s, 64)
		val.SetFloat(f)
		return
	case reflect.Bool:
		b := mustParseBool(s)
		val.SetBool(b)
		return
	case reflect.Struct:
		if val.Type() == timeType {
			t, err := time.Parse(textPlistTimeLayout, s)
			if err != nil {
				panic(err)
			}
			val.Set(reflect.ValueOf(t.In(time.UTC)))
			return
		}
		fallthrough
	default:
		panic(&incompatibleDecodeTypeError{val.Type(), "string"})
	}
}

func (p *Decoder) unmarshal(pval cfValue, val reflect.Value) {
	if pval == nil {
		return
	}

	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		val = val.Elem()
	}

	if isEmptyInterface(val) {
		v := p.valueInterface(pval)
		val.Set(reflect.ValueOf(v))
		return
	}

	incompatibleTypeError := &incompatibleDecodeTypeError{val.Type(), pval.typeName()}

	// time.Time implements TextMarshaler, but we need to parse it as RFC3339
	if date, ok := pval.(cfDate); ok {
		if val.Type() == timeType {
			p.unmarshalTime(date, val)
			return
		}
		panic(incompatibleTypeError)
	}

	if receiver, can := implementsInterface(val, plistUnmarshalerType); can {
		p.unmarshalPlistInterface(pval, receiver.(Unmarshaler))
		return
	}

	if val.Type() != timeType {
		if receiver, can := implementsInterface(val, textUnmarshalerType); can {
			if str, ok := pval.(cfString); ok {
				p.unmarshalTextInterface(str, receiver.(encoding.TextUnmarshaler))
			} else {
				panic(incompatibleTypeError)
			}
			return
		}
	}

	typ := val.Type()

	switch pval := pval.(type) {
	case cfString:
		if val.Kind() == reflect.String {
			val.SetString(string(pval))
			return
		}
		if p.lax {
			p.unmarshalLaxString(string(pval), val)
			return
		}

		panic(incompatibleTypeError)
	case *cfNumber:
		switch val.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			val.SetInt(int64(pval.value))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			val.SetUint(pval.value)
		default:
			panic(incompatibleTypeError)
		}
	case *cfReal:
		if val.Kind() == reflect.Float32 || val.Kind() == reflect.Float64 {
			// TODO: Consider warning on a downcast (storing a 64-bit value in a 32-bit reflect)
			val.SetFloat(pval.value)
		} else {
			panic(incompatibleTypeError)
		}
	case cfBoolean:
		if val.Kind() == reflect.Bool {
			val.SetBool(bool(pval))
		} else {
			panic(incompatibleTypeError)
		}
	case cfData:
		if val.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			val.SetBytes([]byte(pval))
		} else {
			panic(incompatibleTypeError)
		}
	case cfUID:
		if val.Type() == uidType {
			val.SetUint(uint64(pval))
		} else {
			switch val.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				val.SetInt(int64(pval))
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				val.SetUint(uint64(pval))
			default:
				panic(incompatibleTypeError)
			}
		}
	case *cfArray:
		p.unmarshalArray(pval, val)
	case *cfDictionary:
		p.unmarshalDictionary(pval, val)
	}
}

func (p *Decoder) unmarshalArray(a *cfArray, val reflect.Value) {
	var n int
	if val.Kind() == reflect.Slice {
		// Slice of element values.
		// Grow slice.
		cnt := len(a.values) + val.Len()
		if cnt >= val.Cap() {
			ncap := 2 * cnt
			if ncap < 4 {
				ncap = 4
			}
			new := reflect.MakeSlice(val.Type(), val.Len(), ncap)
			reflect.Copy(new, val)
			val.Set(new)
		}
		n = val.Len()
		val.SetLen(cnt)
	} else if val.Kind() == reflect.Array {
		if len(a.values) > val.Cap() {
			panic(fmt.Errorf("plist: attempted to unmarshal %d values into an array of size %d", len(a.values), val.Cap()))
		}
	} else {
		panic(&incompatibleDecodeTypeError{val.Type(), a.typeName()})
	}

	// Recur to read element into slice.
	for _, sval := range a.values {
		p.unmarshal(sval, val.Index(n))
		n++
	}
	return
}

func (p *Decoder) unmarshalDictionary(dict *cfDictionary, val reflect.Value) {
	typ := val.Type()
	switch val.Kind() {
	case reflect.Struct:
		tinfo, err := getTypeInfo(typ)
		if err != nil {
			panic(err)
		}

		entries := make(map[string]cfValue, len(dict.keys))
		for i, k := range dict.keys {
			sval := dict.values[i]
			entries[k] = sval
		}

		for _, finfo := range tinfo.fields {
			p.unmarshal(entries[finfo.name], finfo.value(val))
		}
	case reflect.Map:
		if val.IsNil() {
			val.Set(reflect.MakeMap(typ))
		}

		for i, k := range dict.keys {
			sval := dict.values[i]

			keyv := reflect.ValueOf(k).Convert(typ.Key())
			mapElem := reflect.New(typ.Elem()).Elem()

			p.unmarshal(sval, mapElem)
			val.SetMapIndex(keyv, mapElem)
		}
	default:
		panic(&incompatibleDecodeTypeError{typ, dict.typeName()})
	}
}

/* *Interface is modelled after encoding/json */
func (p *Decoder) valueInterface(pval cfValue) interface{} {
	switch pval := pval.(type) {
	case cfString:
		return string(pval)
	case *cfNumber:
		if pval.signed {
			return int64(pval.value)
		}
		return pval.value
	case *cfReal:
		if pval.wide {
			return pval.value
		} else {
			return float32(pval.value)
		}
	case cfBoolean:
		return bool(pval)
	case *cfArray:
		return p.arrayInterface(pval)
	case *cfDictionary:
		return p.dictionaryInterface(pval)
	case cfData:
		return []byte(pval)
	case cfDate:
		return time.Time(pval)
	case cfUID:
		return UID(pval)
	}
	return nil
}

func (p *Decoder) arrayInterface(a *cfArray) []interface{} {
	out := make([]interface{}, len(a.values))
	for i, subv := range a.values {
		out[i] = p.valueInterface(subv)
	}
	return out
}

func (p *Decoder) dictionaryInterface(dict *cfDictionary) map[string]interface{} {
	out := make(map[string]interface{})
	for i, k := range dict.keys {
		subv := dict.values[i]
		out[k] = p.valueInterface(subv)
	}
	return out
}
