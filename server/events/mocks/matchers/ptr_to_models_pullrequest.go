// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	"github.com/petergtz/pegomock"
	models "github.com/runatlantis/atlantis/server/events/models"
	"reflect"
)

func AnyPtrToModelsPullRequest() *models.PullRequest {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*(*models.PullRequest))(nil)).Elem()))
	var nullValue *models.PullRequest
	return nullValue
}

func EqPtrToModelsPullRequest(value *models.PullRequest) *models.PullRequest {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue *models.PullRequest
	return nullValue
}
