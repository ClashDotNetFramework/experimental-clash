package structure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	decoder         = NewDecoder(Option{TagName: "test"})
	weakTypeDecoder = NewDecoder(Option{TagName: "test", WeaklyTypedInput: true})
)

type Baz struct {
	Foo int    `test:"foo"`
	Bar string `test:"bar"`
}

type BazSlice struct {
	Foo int      `test:"foo"`
	Bar []string `test:"bar"`
}

type BazOptional struct {
	Foo int    `test:"foo,omitempty"`
	Bar string `test:"bar,omitempty"`
}

func TestStructure_Basic(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo":   1,
		"bar":   "test",
		"extra": false,
	}

	goal := &Baz{
		Foo: 1,
		Bar: "test",
	}

	s := &Baz{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Slice(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": 1,
		"bar": []string{"one", "two"},
	}

	goal := &BazSlice{
		Foo: 1,
		Bar: []string{"one", "two"},
	}

	s := &BazSlice{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Optional(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": 1,
	}

	goal := &BazOptional{
		Foo: 1,
	}

	s := &BazOptional{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_MissingKey(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": 1,
	}

	s := &Baz{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_ParamError(t *testing.T) {
	rawMap := map[string]interface{}{}
	s := Baz{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_SliceTypeError(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": 1,
		"bar": []int{1, 2},
	}

	s := &BazSlice{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_WeakType(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": "1",
		"bar": []int{1},
	}

	goal := &BazSlice{
		Foo: 1,
		Bar: []string{"1"},
	}

	s := &BazSlice{}
	err := weakTypeDecoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Nest(t *testing.T) {
	rawMap := map[string]interface{}{
		"foo": 1,
	}

	goal := BazOptional{
		Foo: 1,
	}

	s := &struct {
		BazOptional
	}{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, s.BazOptional, goal)
}
