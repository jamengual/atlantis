// Automatically generated by pegomock. DO NOT EDIT!
// Source: github.com/runatlantis/atlantis/server/events/runtime (interfaces: PullApprovedChecker)

package mocks

import (
	"reflect"

	models "github.com/cloudposse/atlantis/server/events/models"
	pegomock "github.com/petergtz/pegomock"
)

type MockPullApprovedChecker struct {
	fail func(message string, callerSkip ...int)
}

func NewMockPullApprovedChecker() *MockPullApprovedChecker {
	return &MockPullApprovedChecker{fail: pegomock.GlobalFailHandler}
}

func (mock *MockPullApprovedChecker) PullIsApproved(baseRepo models.Repo, pull models.PullRequest) (bool, error) {
	params := []pegomock.Param{baseRepo, pull}
	result := pegomock.GetGenericMockFrom(mock).Invoke("PullIsApproved", params, []reflect.Type{reflect.TypeOf((*bool)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var ret0 bool
	var ret1 error
	if len(result) != 0 {
		if result[0] != nil {
			ret0 = result[0].(bool)
		}
		if result[1] != nil {
			ret1 = result[1].(error)
		}
	}
	return ret0, ret1
}

func (mock *MockPullApprovedChecker) VerifyWasCalledOnce() *VerifierPullApprovedChecker {
	return &VerifierPullApprovedChecker{mock, pegomock.Times(1), nil}
}

func (mock *MockPullApprovedChecker) VerifyWasCalled(invocationCountMatcher pegomock.Matcher) *VerifierPullApprovedChecker {
	return &VerifierPullApprovedChecker{mock, invocationCountMatcher, nil}
}

func (mock *MockPullApprovedChecker) VerifyWasCalledInOrder(invocationCountMatcher pegomock.Matcher, inOrderContext *pegomock.InOrderContext) *VerifierPullApprovedChecker {
	return &VerifierPullApprovedChecker{mock, invocationCountMatcher, inOrderContext}
}

type VerifierPullApprovedChecker struct {
	mock                   *MockPullApprovedChecker
	invocationCountMatcher pegomock.Matcher
	inOrderContext         *pegomock.InOrderContext
}

func (verifier *VerifierPullApprovedChecker) PullIsApproved(baseRepo models.Repo, pull models.PullRequest) *PullApprovedChecker_PullIsApproved_OngoingVerification {
	params := []pegomock.Param{baseRepo, pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "PullIsApproved", params)
	return &PullApprovedChecker_PullIsApproved_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type PullApprovedChecker_PullIsApproved_OngoingVerification struct {
	mock              *MockPullApprovedChecker
	methodInvocations []pegomock.MethodInvocation
}

func (c *PullApprovedChecker_PullIsApproved_OngoingVerification) GetCapturedArguments() (models.Repo, models.PullRequest) {
	baseRepo, pull := c.GetAllCapturedArguments()
	return baseRepo[len(baseRepo)-1], pull[len(pull)-1]
}

func (c *PullApprovedChecker_PullIsApproved_OngoingVerification) GetAllCapturedArguments() (_param0 []models.Repo, _param1 []models.PullRequest) {
	params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(params) > 0 {
		_param0 = make([]models.Repo, len(params[0]))
		for u, param := range params[0] {
			_param0[u] = param.(models.Repo)
		}
		_param1 = make([]models.PullRequest, len(params[1]))
		for u, param := range params[1] {
			_param1[u] = param.(models.PullRequest)
		}
	}
	return
}
