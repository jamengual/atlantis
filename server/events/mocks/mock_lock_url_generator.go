// Code generated by pegomock. DO NOT EDIT.
// Source: github.com/runatlantis/atlantis/server/events (interfaces: LockURLGenerator)

package mocks

import (
	pegomock "github.com/petergtz/pegomock"
	"reflect"
	"time"
)

type MockLockURLGenerator struct {
	fail func(message string, callerSkip ...int)
}

func NewMockLockURLGenerator(options ...pegomock.Option) *MockLockURLGenerator {
	mock := &MockLockURLGenerator{}
	for _, option := range options {
		option.Apply(mock)
	}
	return mock
}

func (mock *MockLockURLGenerator) SetFailHandler(fh pegomock.FailHandler) { mock.fail = fh }
func (mock *MockLockURLGenerator) FailHandler() pegomock.FailHandler      { return mock.fail }

func (mock *MockLockURLGenerator) GenerateLockURL(lockID string) string {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockLockURLGenerator().")
	}
	params := []pegomock.Param{lockID}
	result := pegomock.GetGenericMockFrom(mock).Invoke("GenerateLockURL", params, []reflect.Type{reflect.TypeOf((*string)(nil)).Elem()})
	var ret0 string
	if len(result) != 0 {
		if result[0] != nil {
			ret0 = result[0].(string)
		}
	}
	return ret0
}

func (mock *MockLockURLGenerator) VerifyWasCalledOnce() *VerifierLockURLGenerator {
	return &VerifierLockURLGenerator{
		mock:                   mock,
		invocationCountMatcher: pegomock.Times(1),
	}
}

func (mock *MockLockURLGenerator) VerifyWasCalled(invocationCountMatcher pegomock.Matcher) *VerifierLockURLGenerator {
	return &VerifierLockURLGenerator{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
	}
}

func (mock *MockLockURLGenerator) VerifyWasCalledInOrder(invocationCountMatcher pegomock.Matcher, inOrderContext *pegomock.InOrderContext) *VerifierLockURLGenerator {
	return &VerifierLockURLGenerator{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		inOrderContext:         inOrderContext,
	}
}

func (mock *MockLockURLGenerator) VerifyWasCalledEventually(invocationCountMatcher pegomock.Matcher, timeout time.Duration) *VerifierLockURLGenerator {
	return &VerifierLockURLGenerator{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		timeout:                timeout,
	}
}

type VerifierLockURLGenerator struct {
	mock                   *MockLockURLGenerator
	invocationCountMatcher pegomock.Matcher
	inOrderContext         *pegomock.InOrderContext
	timeout                time.Duration
}

func (verifier *VerifierLockURLGenerator) GenerateLockURL(lockID string) *LockURLGenerator_GenerateLockURL_OngoingVerification {
	params := []pegomock.Param{lockID}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GenerateLockURL", params, verifier.timeout)
	return &LockURLGenerator_GenerateLockURL_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type LockURLGenerator_GenerateLockURL_OngoingVerification struct {
	mock              *MockLockURLGenerator
	methodInvocations []pegomock.MethodInvocation
}

func (c *LockURLGenerator_GenerateLockURL_OngoingVerification) GetCapturedArguments() string {
	lockID := c.GetAllCapturedArguments()
	return lockID[len(lockID)-1]
}

func (c *LockURLGenerator_GenerateLockURL_OngoingVerification) GetAllCapturedArguments() (_param0 []string) {
	params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(params) > 0 {
		_param0 = make([]string, len(params[0]))
		for u, param := range params[0] {
			_param0[u] = param.(string)
		}
	}
	return
}
