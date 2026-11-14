// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webauth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/webauth"
	. "github.com/runatlantis/atlantis/testing"
)

const (
	secretA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secretB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseRole(t *testing.T) {
	for in, want := range map[string]webauth.Role{"": webauth.RoleNone, "none": webauth.RoleNone, "Viewer": webauth.RoleViewer, " operator ": webauth.RoleOperator, "ADMIN": webauth.RoleAdmin} {
		got, err := webauth.ParseRole(in)
		Ok(t, err)
		Equals(t, want, got)
	}
	_, err := webauth.ParseRole("root")
	ErrContains(t, "unknown role", err)
}

func TestPrincipalCan(t *testing.T) {
	op := &webauth.Principal{Role: webauth.RoleOperator}
	Assert(t, op.Can(webauth.RoleViewer), "operator can view")
	Assert(t, op.Can(webauth.RoleOperator), "operator can operate")
	Assert(t, !op.Can(webauth.RoleAdmin), "operator is not admin")
	var nobody *webauth.Principal
	Assert(t, !nobody.Can(webauth.RoleViewer), "nil principal can do nothing")

	ctx := webauth.WithPrincipal(context.Background(), op)
	Equals(t, op, webauth.FromContext(ctx))
	Assert(t, webauth.FromContext(context.Background()) == nil, "empty context has no principal")
}

func TestRoleMapper(t *testing.T) {
	m := webauth.RoleMapper{
		Admins:    []string{"group:platform-admins", "email:boss@acme.com"},
		Operators: []string{"sre", "domain:ops.acme.com"},
		Viewers:   []string{"*"},
	}
	Ok(t, m.Validate())
	cases := []struct {
		name string
		id   webauth.Identity
		want webauth.Role
	}{
		{"group admin", webauth.Identity{Groups: []string{"Platform-Admins"}}, webauth.RoleAdmin},
		{"email admin", webauth.Identity{Email: "BOSS@acme.com", EmailVerified: true}, webauth.RoleAdmin},
		{"unverified email is ignored", webauth.Identity{Email: "boss@acme.com"}, webauth.RoleViewer},
		{"bare name is a group", webauth.Identity{Groups: []string{"sre"}}, webauth.RoleOperator},
		{"domain operator", webauth.Identity{Email: "a@ops.acme.com", EmailVerified: true}, webauth.RoleOperator},
		{"subdomain does not match", webauth.Identity{Email: "a@x.ops.acme.com", EmailVerified: true}, webauth.RoleViewer},
		{"highest role wins", webauth.Identity{Groups: []string{"sre", "platform-admins"}}, webauth.RoleAdmin},
		{"wildcard viewer", webauth.Identity{Subject: "anyone"}, webauth.RoleViewer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { Equals(t, c.want, m.Resolve(c.id)) })
	}

	strict := webauth.RoleMapper{Operators: []string{"sre"}}
	Equals(t, webauth.RoleNone, strict.Resolve(webauth.Identity{Groups: []string{"dev"}}))
	strict.Default = webauth.RoleViewer
	Equals(t, webauth.RoleViewer, strict.Resolve(webauth.Identity{Groups: []string{"dev"}}))
}

func TestRoleMapperValidate(t *testing.T) {
	ErrContains(t, "unknown kind", webauth.RoleMapper{Admins: []string{"team:x"}}.Validate())
	ErrContains(t, "has no value", webauth.RoleMapper{Viewers: []string{"email:"}}.Validate())
}

func TestKeyring(t *testing.T) {
	now := time.Now()
	ring, err := webauth.NewKeyring([]string{secretA})
	Ok(t, err)

	type payload struct{ Name string }
	tok, err := ring.Seal("session", payload{"alice"}, now.Add(time.Hour))
	Ok(t, err)

	var got payload
	Ok(t, ring.Open("session", tok, now, &got))
	Equals(t, "alice", got.Name)

	Equals(t, webauth.ErrInvalidToken, ring.Open("login", tok, now, &got))
	Equals(t, webauth.ErrInvalidToken, ring.Open("session", tok, now.Add(2*time.Hour), &got))
	Equals(t, webauth.ErrInvalidToken, ring.Open("session", "not-a-token", now, &got))

	tampered := []byte(tok)
	tampered[len(tampered)/2] ^= 1
	Equals(t, webauth.ErrInvalidToken, ring.Open("session", string(tampered), now, &got))

	// Rotation: a new key in front still opens values sealed with the old one.
	rotated, err := webauth.NewKeyring([]string{secretB, secretA})
	Ok(t, err)
	Ok(t, rotated.Open("session", tok, now, &got))
	newTok, err := rotated.Seal("session", payload{"bob"}, now.Add(time.Hour))
	Ok(t, err)
	Equals(t, webauth.ErrInvalidToken, ring.Open("session", newTok, now, &got))
}

func TestKeyringRejectsWeakSecrets(t *testing.T) {
	_, err := webauth.NewKeyring(nil)
	ErrContains(t, "at least one", err)
	_, err = webauth.NewKeyring([]string{"short"})
	ErrContains(t, "at least 32", err)
	Assert(t, !strings.Contains(err.Error(), "short"), "error must not echo the secret")
}
