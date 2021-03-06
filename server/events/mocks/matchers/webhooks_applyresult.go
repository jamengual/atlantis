// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	"github.com/petergtz/pegomock"
	webhooks "github.com/runatlantis/atlantis/server/events/webhooks"
	"reflect"
)

func AnyWebhooksApplyResult() webhooks.ApplyResult {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*(webhooks.ApplyResult))(nil)).Elem()))
	var nullValue webhooks.ApplyResult
	return nullValue
}

func EqWebhooksApplyResult(value webhooks.ApplyResult) webhooks.ApplyResult {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue webhooks.ApplyResult
	return nullValue
}
