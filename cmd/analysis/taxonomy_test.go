package main

import (
	"testing"
)

func TestEveryRuleCategoryHasMITREMapping(t *testing.T) {
	for _, rule := range DefaultRules.CommandRules {
		if !IsKnownCategory(rule.Category) {
			t.Errorf("command rule %q category %q has no ATT&CK mapping", rule.Pattern.String(), rule.Category)
		}
	}
	for _, rule := range DefaultRules.FileRules {
		if !IsKnownCategory(rule.Category) {
			t.Errorf("file rule %q category %q has no ATT&CK mapping", rule.Pattern.String(), rule.Category)
		}
	}
	for _, rule := range DefaultRules.NetworkRules {
		if !IsKnownCategory(rule.Category) {
			t.Errorf("network rule on port %d category %q has no ATT&CK mapping", rule.Port, rule.Category)
		}
	}
}

func TestEveryChainRuleHasMITREMapping(t *testing.T) {
	for _, rule := range defaultChainRules {
		if !IsKnownCategory(rule.name) {
			t.Errorf("chain rule %q has no ATT&CK mapping", rule.name)
		}
	}
}

func TestDefaultCategoriesAreMapped(t *testing.T) {
	for _, category := range []string{CategoryCommand, CategoryFileAccess, CategoryNetwork, CategoryUnknown, CategoryBenign} {
		if !IsKnownCategory(category) {
			t.Errorf("default category %q is not mapped", category)
		}
	}
}

func TestTacticChoiceSetsWithinLimit(t *testing.T) {
	for _, spec := range TacticSpecs {
		if len(spec.Options) > MaxChoiceOptions {
			t.Errorf("tactic %s has %d options, limit is %d", spec.Tactic, len(spec.Options), MaxChoiceOptions)
		}
		if len(spec.Description) == 0 {
			t.Errorf("tactic %s has no description", spec.Tactic)
		}
	}
}

func TestTacticOptionsWithinLimit(t *testing.T) {
	if got := len(TacticOptions()); got > MaxChoiceOptions {
		t.Errorf("stage 1 has %d options, limit is %d", got, MaxChoiceOptions)
	}
}

func TestCategoryOptionsBelongToTheirTactic(t *testing.T) {
	for _, spec := range TacticSpecs {
		if spec.Tactic == TacticBenign {
			if len(spec.Options) != 0 {
				t.Errorf("benign tactic should not offer categories, got %v", spec.Options)
			}
			continue
		}

		options := CategoryOptions(spec.Tactic)
		if len(options) == 0 {
			t.Errorf("tactic %s resolved to no category options", spec.Tactic)
		}
		if len(options) > MaxChoiceOptions {
			t.Errorf("tactic %s has %d category options, limit is %d", spec.Tactic, len(options), MaxChoiceOptions)
		}

		for _, category := range spec.Options {
			entry, ok := LookupCategory(category)
			if !ok {
				t.Errorf("tactic %s references unmapped category %q", spec.Tactic, category)
				continue
			}
			if entry.Tactic != spec.Tactic {
				t.Errorf("category %q is listed under tactic %s but mapped to %s", category, spec.Tactic, entry.Tactic)
			}
			if entry.Description == "" {
				t.Errorf("category %q has no description for the Laya criteria", category)
			}
		}
	}
}

func TestAttackCategoriesHaveConsistentTechniqueAndTactic(t *testing.T) {
	for category, entry := range CategoryMITREMap {
		if entry.Category != category {
			t.Errorf("category %q is keyed as %q", entry.Category, category)
		}
		if entry.Description == "" {
			t.Errorf("category %q has no description", category)
		}
		if entry.Tactic != "" && entry.Tactic != TacticBenign && entry.TechniqueID == "" {
			t.Errorf("category %q has tactic %s but no technique", category, entry.Tactic)
		}
		if entry.Tactic != "" {
			if _, ok := LookupTactic(entry.Tactic); !ok {
				t.Errorf("category %q references unknown tactic %q", category, entry.Tactic)
			}
		}
	}
}

func TestApplyAttackTaxonomyResolvesCategory(t *testing.T) {
	event := Event{EventType: EventTypeExecve}
	applyAttackTaxonomy(&event, "curl_pipe", 0.9, CategorySourceRules)

	if event.Category != "curl_pipe" {
		t.Errorf("category = %q, want curl_pipe", event.Category)
	}
	if event.TechniqueID != "T1059.004" {
		t.Errorf("technique = %q, want T1059.004", event.TechniqueID)
	}
	if event.Tactic != TacticExecution {
		t.Errorf("tactic = %q, want %s", event.Tactic, TacticExecution)
	}
	if event.CategorySource != CategorySourceRules {
		t.Errorf("source = %q, want %q", event.CategorySource, CategorySourceRules)
	}
	if event.CategoryConfidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9", event.CategoryConfidence)
	}
}

func TestApplyAttackTaxonomyFallsBackForUnknownCategory(t *testing.T) {
	event := Event{EventType: EventTypeOpen, FilePath: "/tmp/x"}
	applyAttackTaxonomy(&event, "no_such_rule", 0.4, CategorySourceRules)

	if event.Category != CategoryUnknown {
		t.Errorf("category = %q, want %q", event.Category, CategoryUnknown)
	}
	if event.Tactic != "" || event.TechniqueID != "" {
		t.Errorf("unknown category should carry no technique mapping, got %s/%s", event.Tactic, event.TechniqueID)
	}
}

func TestApplyAttackTaxonomyDefaultsPerEventType(t *testing.T) {
	cases := []struct {
		eventType string
		want      string
	}{
		{EventTypeExecve, CategoryCommand},
		{EventTypeExecveat, CategoryCommand},
		{EventTypeOpen, CategoryFileAccess},
		{EventTypeOpenat, CategoryFileAccess},
		{EventTypeNetwork, CategoryNetwork},
		{EventTypeConnect, CategoryNetwork},
		{EventTypeProcess, CategoryUnknown},
	}

	for _, tc := range cases {
		event := Event{EventType: tc.eventType}
		applyAttackTaxonomy(&event, "", 0, CategorySourceRules)
		if event.Category != tc.want {
			t.Errorf("event type %s defaulted to %q, want %q", tc.eventType, event.Category, tc.want)
		}
	}
}

func TestNeedsClassification(t *testing.T) {
	if needsClassification(Event{Category: "curl_pipe"}) {
		t.Error("specific rule category should not be reclassified")
	}
	if needsClassification(Event{Category: "reverse_shell"}) {
		t.Error("specific laya category should not be reclassified")
	}
	for _, category := range []string{"", CategoryCommand, CategoryFileAccess, CategoryNetwork, CategoryUnknown} {
		if !needsClassification(Event{Category: category}) {
			t.Errorf("category %q should be a classification candidate", category)
		}
	}
}

func TestBenignCategoryMapsToBenignTactic(t *testing.T) {
	event := Event{EventType: EventTypeExecve}
	applyAttackTaxonomy(&event, CategoryBenign, 0.7, CategorySourceLaya)

	if event.Tactic != TacticBenign {
		t.Errorf("tactic = %q, want %s", event.Tactic, TacticBenign)
	}
	if event.TechniqueID != "" {
		t.Errorf("benign should not carry a technique, got %q", event.TechniqueID)
	}
}
