// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// PlanAction is what a plan does to one resource instance.
type PlanAction string

const (
	PlanCreate  PlanAction = "create"
	PlanUpdate  PlanAction = "update"
	PlanDelete  PlanAction = "delete"
	PlanReplace PlanAction = "replace"
	PlanRead    PlanAction = "read"
	PlanForget  PlanAction = "forget"
	// PlanImport is an import that changes nothing else.
	PlanImport PlanAction = "import"
	// PlanMove is a moved block that changes nothing else.
	PlanMove PlanAction = "move"
)

// PlanLimits bounds how much of a plan is kept for display. Counts always
// cover the whole plan.
type PlanLimits struct {
	// Resources is the most resource changes kept.
	Resources int
	// AttributesPerResource is the most attribute changes kept per resource.
	AttributesPerResource int
	// Attributes is the most attribute changes kept across the plan.
	Attributes int
	// ValueLength is the longest rendered value, in characters.
	ValueLength int
}

// DefaultPlanLimits keeps pages for large plans to a few megabytes.
var DefaultPlanLimits = PlanLimits{Resources: 500, AttributesPerResource: 100, Attributes: 10000, ValueLength: 2000}

// ParsedPlan is the resource-level content of a Terraform plan.
type ParsedPlan struct {
	TerraformVersion string
	// Changes counts the plan the way Terraform's "Plan:" line does.
	Changes Changes
	// Resources lists the resource changes, data source reads included, up
	// to the resource limit. No-op changes are left out unless the resource
	// is imported or moved.
	Resources []ResourceChange
	// TotalResources is the number of resource changes before the limit.
	TotalResources int
	// AttributesOmitted is true when the plan-wide attribute limit dropped
	// attribute details from some resources.
	AttributesOmitted bool
}

// ResourceChange is one resource instance in a plan.
type ResourceChange struct {
	Address         string
	PreviousAddress string
	Module          string
	Type            string
	Name            string
	Provider        string
	Action          PlanAction
	// ImportID is set when the plan imports the resource.
	ImportID  string
	Importing bool
	// Deposed is set when the change is to a deposed object.
	Deposed string
	// Reason explains why Terraform chose the action, when it says.
	Reason     string
	Attributes []AttributeChange
	// Unchanged is how many attributes of an update or replace stay the same
	// and are not listed.
	Unchanged int
	// Omitted is how many changed attributes were dropped by the limits.
	Omitted int
}

// AttributeChange is one attribute of a resource change. Sensitive values are
// never kept: Before or After is empty when the matching flag is set.
type AttributeChange struct {
	Path            string
	Before          string
	After           string
	BeforeAbsent    bool
	AfterAbsent     bool
	BeforeSensitive bool
	AfterSensitive  bool
	// AfterUnknown means the value is known only after apply.
	AfterUnknown      bool
	ForcesReplacement bool
}

type rawPlan struct {
	FormatVersion    string        `json:"format_version"`
	TerraformVersion string        `json:"terraform_version"`
	ResourceChanges  []rawResource `json:"resource_changes"`
}

type rawResource struct {
	Address         string    `json:"address"`
	PreviousAddress string    `json:"previous_address"`
	ModuleAddress   string    `json:"module_address"`
	Mode            string    `json:"mode"`
	Type            string    `json:"type"`
	Name            string    `json:"name"`
	ProviderName    string    `json:"provider_name"`
	Deposed         string    `json:"deposed"`
	ActionReason    string    `json:"action_reason"`
	Change          rawChange `json:"change"`
}

type rawChange struct {
	Actions         []string `json:"actions"`
	Before          any      `json:"before"`
	After           any      `json:"after"`
	AfterUnknown    any      `json:"after_unknown"`
	BeforeSensitive any      `json:"before_sensitive"`
	AfterSensitive  any      `json:"after_sensitive"`
	ReplacePaths    [][]any  `json:"replace_paths"`
	Importing       *struct {
		ID string `json:"id"`
	} `json:"importing"`
}

// errNotPlanJSON means the file is JSON but not a Terraform plan.
var errNotPlanJSON = errors.New("not terraform plan json")

func decodePlan(r io.Reader) (rawPlan, error) {
	var p rawPlan
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("decoding plan json: %w", err)
	}
	if p.FormatVersion == "" {
		return p, errNotPlanJSON
	}
	return p, nil
}

// ParsePlanJSON reads the output of terraform show -json for a saved plan.
func ParsePlanJSON(r io.Reader, limits PlanLimits) (ParsedPlan, error) {
	raw, err := decodePlan(r)
	if err != nil {
		return ParsedPlan{}, err
	}
	out := ParsedPlan{TerraformVersion: raw.TerraformVersion, Changes: countChanges(raw)}
	budget := limits.Attributes
	for _, rc := range raw.ResourceChanges {
		action, ok := classify(rc)
		if !ok {
			continue
		}
		out.TotalResources++
		if len(out.Resources) >= limits.Resources {
			continue
		}
		res := ResourceChange{
			Address:  rc.Address,
			Module:   rc.ModuleAddress,
			Type:     rc.Type,
			Name:     rc.Name,
			Provider: shortProvider(rc.ProviderName),
			Action:   action,
			Deposed:  rc.Deposed,
			Reason:   actionReason(rc.ActionReason),
		}
		if rc.PreviousAddress != rc.Address {
			res.PreviousAddress = rc.PreviousAddress
		}
		if rc.Change.Importing != nil {
			res.Importing = true
			res.ImportID = rc.Change.Importing.ID
		}
		attrs, unchanged := diffAttributes(rc.Change, action, limits.ValueLength)
		res.Unchanged = unchanged
		keep := min(len(attrs), limits.AttributesPerResource)
		if budget < keep {
			keep = max(budget, 0)
			out.AttributesOmitted = true
		}
		res.Attributes = attrs[:keep]
		res.Omitted = len(attrs) - keep
		budget -= keep
		out.Resources = append(out.Resources, res)
	}
	return out, nil
}

// CountPlanChanges reads only the change counts from plan JSON.
func CountPlanChanges(r io.Reader) (Changes, error) {
	raw, err := decodePlan(r)
	if err != nil {
		return Changes{}, err
	}
	return countChanges(raw), nil
}

// countChanges follows Terraform's plan summary: replacements count as an
// add and a destroy, imports are counted on their own as well as by action,
// and data source reads are not counted.
func countChanges(raw rawPlan) Changes {
	c := Changes{Known: true}
	for _, rc := range raw.ResourceChanges {
		if rc.Mode == "data" {
			continue
		}
		if rc.Change.Importing != nil {
			c.Import++
		}
		acts := rc.Change.Actions
		switch {
		case slices.Equal(acts, []string{"create"}):
			c.Add++
		case slices.Equal(acts, []string{"update"}):
			c.Change++
		case slices.Equal(acts, []string{"delete"}):
			c.Destroy++
		case slices.Equal(acts, []string{"forget"}):
			c.Forget++
		case slices.Contains(acts, "create") && slices.Contains(acts, "delete"):
			c.Add++
			c.Destroy++
		case slices.Contains(acts, "create") && slices.Contains(acts, "forget"):
			c.Add++
			c.Forget++
		}
	}
	return c
}

// classify picks the action shown for a resource change. It returns false
// for changes that do nothing worth listing.
func classify(rc rawResource) (PlanAction, bool) {
	acts := rc.Change.Actions
	switch {
	case slices.Equal(acts, []string{"create"}):
		return PlanCreate, true
	case slices.Equal(acts, []string{"update"}):
		return PlanUpdate, true
	case slices.Equal(acts, []string{"delete"}):
		return PlanDelete, true
	case slices.Equal(acts, []string{"read"}):
		return PlanRead, true
	case slices.Equal(acts, []string{"forget"}):
		return PlanForget, true
	case slices.Contains(acts, "create") && (slices.Contains(acts, "delete") || slices.Contains(acts, "forget")):
		return PlanReplace, true
	case rc.Change.Importing != nil:
		return PlanImport, true
	case rc.PreviousAddress != "" && rc.PreviousAddress != rc.Address:
		return PlanMove, true
	}
	return "", false
}

var actionReasons = map[string]string{
	"replace_because_tainted":                 "the object is tainted",
	"replace_because_cannot_update":           "a change forces replacement",
	"replace_by_request":                      "replacement was requested",
	"replace_by_triggers":                     "replace_triggered_by changed",
	"delete_because_no_resource_config":       "its configuration was removed",
	"delete_because_no_module":                "its module was removed",
	"delete_because_wrong_repetition":         "count or for_each changed form",
	"delete_because_count_index":              "its count index is out of range",
	"delete_because_each_key":                 "its for_each key was removed",
	"delete_because_no_move_target":           "its moved target doesn't exist",
	"read_because_config_unknown":             "its configuration depends on values known after apply",
	"read_because_dependency_pending":         "a dependency has pending changes",
	"read_because_check_nested":               "a check block reads it",
	"replace_because_create_before_destroy":   "create_before_destroy is set",
	"delete_because_resource_was_removed":     "a removed block removes it",
	"delete_because_resource_was_not_managed": "it is no longer managed",
}

func actionReason(code string) string {
	if code == "" {
		return ""
	}
	if r, ok := actionReasons[code]; ok {
		return r
	}
	return strings.ReplaceAll(code, "_", " ")
}

// shortProvider turns registry.terraform.io/hashicorp/aws into hashicorp/aws.
func shortProvider(p string) string {
	for _, prefix := range []string{"registry.terraform.io/", "registry.opentofu.org/"} {
		if rest, ok := strings.CutPrefix(p, prefix); ok {
			return rest
		}
	}
	return p
}

// absent marks a side of a diff that has no value, as opposed to null.
type absentValue struct{}

var absent = absentValue{}

type attrWalker struct {
	action    PlanAction
	maxLen    int
	replace   []string
	out       []AttributeChange
	unchanged int
}

// diffAttributes lists attribute changes. Creates list every non-null
// attribute, deletes every non-null prior attribute, and updates and
// replacements only the attributes that change.
func diffAttributes(c rawChange, action PlanAction, maxLen int) ([]AttributeChange, int) {
	w := &attrWalker{action: action, maxLen: maxLen}
	for _, p := range c.ReplacePaths {
		w.replace = append(w.replace, formatPath(p))
	}
	before, after := c.Before, c.After
	if action == PlanCreate || action == PlanRead {
		before = absent
	}
	if action == PlanDelete || action == PlanForget {
		after = absent
	}
	bm, bok := before.(map[string]any)
	am, aok := after.(map[string]any)
	if !bok && !aok {
		return nil, 0
	}
	um, _ := c.AfterUnknown.(map[string]any)
	for _, k := range unionKeys(bm, am, um) {
		w.walk(attrKey("", k), lookup(before, k), lookup(after, k),
			child(c.BeforeSensitive, k), child(c.AfterSensitive, k), child(c.AfterUnknown, k))
	}
	return w.out, w.unchanged
}

func (w *attrWalker) walk(path string, before, after, bs, as, au any) {
	sensitive := isTrue(bs) || isTrue(as)
	unknown := isTrue(au)
	if !sensitive && !unknown {
		bm, bIsMap := before.(map[string]any)
		am, aIsMap := after.(map[string]any)
		if (bIsMap || isEmpty(before)) && (aIsMap || isEmpty(after)) && (bIsMap || aIsMap) {
			um, _ := au.(map[string]any)
			for _, k := range unionKeys(bm, am, um) {
				w.walk(attrKey(path, k), lookup(before, k), lookup(after, k), child(bs, k), child(as, k), child(au, k))
			}
			return
		}
		bl, bIsList := before.([]any)
		al, aIsList := after.([]any)
		if (bIsList || isEmpty(before)) && (aIsList || isEmpty(after)) && (hasObject(bl) || hasObject(al)) {
			for i := range max(len(bl), len(al)) {
				w.walk(path+"["+strconv.Itoa(i)+"]", index(before, i), index(after, i), child(bs, i), child(as, i), child(au, i))
			}
			return
		}
	}
	w.leaf(path, before, after, isTrue(bs), isTrue(as), unknown)
}

func (w *attrWalker) leaf(path string, before, after any, bSens, aSens, unknown bool) {
	bAbsent := isEmpty(before)
	aAbsent := isEmpty(after) && !unknown
	if bAbsent && aAbsent {
		return
	}
	if !unknown && reflect.DeepEqual(before, after) {
		w.unchanged++
		return
	}
	a := AttributeChange{
		Path:            path,
		BeforeAbsent:    bAbsent,
		AfterAbsent:     aAbsent,
		BeforeSensitive: bSens && !bAbsent,
		AfterSensitive:  aSens && !aAbsent && !unknown,
		AfterUnknown:    unknown,
	}
	if !bAbsent && !a.BeforeSensitive {
		a.Before = renderValue(before, w.maxLen)
	}
	if !aAbsent && !unknown && !a.AfterSensitive {
		a.After = renderValue(after, w.maxLen)
	}
	for _, rp := range w.replace {
		if path == rp || strings.HasPrefix(path, rp+".") || strings.HasPrefix(path, rp+"[") {
			a.ForcesReplacement = true
		}
	}
	w.out = append(w.out, a)
}

// isEmpty reports whether a value is missing or null.
func isEmpty(v any) bool {
	return v == nil || v == absent
}

func isTrue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func hasObject(l []any) bool {
	for _, v := range l {
		if _, ok := v.(map[string]any); ok {
			return true
		}
	}
	return false
}

// unionKeys returns the keys of every map, sorted. The after_unknown map is
// included because Terraform leaves unknown attributes out of after.
func unionKeys(maps ...map[string]any) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range maps {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	return keys
}

// lookup returns m[k], or absent when v is not a map or has no such key.
func lookup(v any, k string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return absent
	}
	if x, ok := m[k]; ok {
		return x
	}
	return absent
}

func index(v any, i int) any {
	l, ok := v.([]any)
	if !ok || i >= len(l) {
		return absent
	}
	return l[i]
}

// child returns the sensitivity or unknown mark for a key or index. A mark of
// true on a parent covers its children.
func child(mark any, key any) any {
	switch m := mark.(type) {
	case bool:
		return m
	case map[string]any:
		if k, ok := key.(string); ok {
			return m[k]
		}
	case []any:
		if i, ok := key.(int); ok && i < len(m) {
			return m[i]
		}
	}
	return nil
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

func attrKey(path, k string) string {
	if !identifier.MatchString(k) {
		return path + "[" + strconv.Quote(k) + "]"
	}
	if path == "" {
		return k
	}
	return path + "." + k
}

// formatPath renders a replace_paths entry the way walk names attributes.
func formatPath(steps []any) string {
	path := ""
	for _, s := range steps {
		switch v := s.(type) {
		case string:
			path = attrKey(path, v)
		case json.Number:
			path += "[" + v.String() + "]"
		case float64:
			path += "[" + strconv.FormatFloat(v, 'f', -1, 64) + "]"
		}
	}
	return path
}

func renderValue(v any, maxLen int) string {
	var s string
	switch x := v.(type) {
	case json.Number:
		s = x.String()
	case bool:
		s = strconv.FormatBool(x)
	default:
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			s = fmt.Sprint(x)
		} else {
			s = strings.TrimSuffix(b.String(), "\n")
		}
	}
	return truncate(s, maxLen)
}

func truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}
