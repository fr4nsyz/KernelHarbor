package main

import (
	"context"
	"fmt"
	"log"
)

const (
	tacticQuestionID   = "tactic"
	categoryQuestionID = "category"

	tacticInstructions = "Which MITRE ATT&CK tactic best describes the security intent of this system event? " +
		"Choose benign when the activity is routine administration with no attack behaviour."

	categoryInstructions = "The event was placed in the %s tactic. " +
		"Which specific behaviour best describes it?"
)

type Classifier struct {
	laya          *LayaClient
	minConfidence float64
	sem           chan struct{}
	enabled       bool
}

func NewClassifier(laya *LayaClient, minConfidence float64, concurrency int) *Classifier {
	if concurrency <= 0 {
		concurrency = 1
	}
	if minConfidence < 0 {
		minConfidence = 0
	}

	return &Classifier{
		laya:          laya,
		minConfidence: minConfidence,
		sem:           make(chan struct{}, concurrency),
		enabled:       laya != nil,
	}
}

func (c *Classifier) Enabled() bool {
	return c != nil && c.enabled
}

// Classify refines events that no heuristic rule could categorise. Events that already
// carry a specific rule category are left untouched.
func (c *Classifier) Classify(ctx context.Context, event *Event) {
	if !c.Enabled() || event == nil || !needsClassification(*event) {
		return
	}

	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	c.classify(ctx, event)
}

func (c *Classifier) classify(ctx context.Context, event *Event) {
	state := buildEventState(*event)

	tacticAnswer, err := c.laya.Choose(ctx, state, tacticQuestionID, tacticInstructions, TacticOptions())
	if err != nil {
		log.Printf("Laya tactic classification failed for %s: %v", event.EventID, err)
		return
	}

	tactic, ok := LookupTactic(tacticAnswer.Choice)
	if !ok || tacticAnswer.Confidence < c.minConfidence {
		log.Printf("Keeping rule category %q for %s: tactic confidence %.2f below %.2f",
			event.Category, event.EventID, tacticAnswer.Confidence, c.minConfidence)
		return
	}

	if tactic.Tactic == TacticBenign {
		applyAttackTaxonomy(event, CategoryBenign, tacticAnswer.Confidence, CategorySourceLaya)
		log.Printf("Laya classified %s as benign (confidence %.2f)", event.EventID, tacticAnswer.Confidence)
		return
	}

	options := CategoryOptions(tactic.Tactic)
	if len(options) == 0 {
		return
	}

	categoryAnswer, err := c.laya.Choose(ctx, state, categoryQuestionID, fmt.Sprintf(categoryInstructions, tactic.Description), options)
	if err != nil {
		log.Printf("Laya category classification failed for %s: %v", event.EventID, err)
		return
	}

	if categoryAnswer.Confidence < c.minConfidence {
		log.Printf("Keeping rule category %q for %s: %s category confidence %.2f below %.2f",
			event.Category, event.EventID, tactic.Tactic, categoryAnswer.Confidence, c.minConfidence)
		return
	}

	applyAttackTaxonomy(event, categoryAnswer.Choice, categoryAnswer.Confidence, CategorySourceLaya)

	log.Printf("Laya classified %s as %s/%s (confidence %.2f)",
		event.EventID, tactic.Tactic, categoryAnswer.Choice, categoryAnswer.Confidence)
}

func buildEventState(event Event) map[string]any {
	process := map[string]any{
		"image":   event.ImagePath,
		"binary":  extractBinaryName(event.ImagePath),
		"command": event.CommandLine,
		"cwd":     event.WorkingDir,
		"guid":    event.ProcessGUID,
		"pid":     event.ProcessID,
		"ppid":    event.ParentPID,
	}
	if event.ParentGUID != "" {
		process["parent_guid"] = event.ParentGUID
	}

	state := map[string]any{
		"event_type": event.EventType,
		"host":       event.HostName,
		"user":       event.User,
		"process":    process,
	}

	if event.Category != "" {
		state["rule_category"] = event.Category
	}
	if event.FilePath != "" {
		state["file"] = map[string]any{
			"path":  event.FilePath,
			"name":  baseName(event.FilePath),
			"dir":   extractDir(event.FilePath),
			"type":  extractFileType(event.FilePath),
			"flags": event.FileFlags,
			"mode":  event.FileMode,
		}
	}
	if event.RemoteAddr != "" || event.RemotePort != 0 || event.LocalPort != 0 {
		state["network"] = map[string]any{
			"remote_addr": event.RemoteAddr,
			"remote_port": event.RemotePort,
			"local_addr":  event.LocalAddr,
			"local_port":  event.LocalPort,
			"socket_info": event.SocketInfo,
		}
	}

	return state
}
