// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	"github.com/petergtz/pegomock"
	"reflect"
)

func AnySliceOfByte() []byte {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*([]byte))(nil)).Elem()))
	var nullValue []byte
	return nullValue
}

func EqSliceOfByte(value []byte) []byte {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue []byte
	return nullValue
}
