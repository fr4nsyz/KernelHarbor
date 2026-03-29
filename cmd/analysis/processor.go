package main

import (
	"context"
	"log"
	"sync"
	"time"
)

type BatchProcessorConfig struct {
	Workers         int
	BatchSize       int
	BatchTimeout    time.Duration
	MinBatchTimeout time.Duration
}

type Batch struct {
	HostName   string
	Events     []Event
	ReceivedAt time.Time
}

type BatchProcessor struct {
	cfg     BatchProcessorConfig
	inputCh chan Event
	workers []worker
	mu      sync.Mutex
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

type worker struct {
	id      int
	inputCh chan Batch
}

func NewBatchProcessor(cfg BatchProcessorConfig) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	return &BatchProcessor{
		cfg:     cfg,
		inputCh: make(chan Event, cfg.BatchSize*2),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (bp *BatchProcessor) Start() {
	for i := 0; i < bp.cfg.Workers; i++ {
		w := worker{
			id:      i,
			inputCh: make(chan Batch, 10),
		}
		bp.workers = append(bp.workers, w)
		bp.wg.Add(1)
		go bp.runWorker(w)
	}

	bp.wg.Add(1)
	go bp.batchAccumulator()
	log.Printf("Started batch processor with %d workers", bp.cfg.Workers)
}

func (bp *BatchProcessor) Stop() {
	bp.cancel()
	close(bp.inputCh)
	bp.wg.Wait()
	log.Println("Batch processor stopped")
}

func (bp *BatchProcessor) Submit(event Event) {
	select {
	case bp.inputCh <- event:
	case <-bp.ctx.Done():
		log.Printf("Dropping event %s: processor stopped", event.EventID)
	}
}

func (bp *BatchProcessor) batchAccumulator() {
	defer bp.wg.Done()

	hostBatches := make(map[string][]Event)
	var timer *time.Timer

	flushBatches := func(force bool) {
		if timer != nil {
			timer.Stop()
			timer = nil
		}

		for host, events := range hostBatches {
			if force || len(events) > 0 {
				workerID := hashHost(host) % len(bp.workers)
				select {
				case bp.workers[workerID].inputCh <- Batch{
					HostName:   host,
					Events:     events,
					ReceivedAt: time.Now(),
				}:
				case <-bp.ctx.Done():
					return
				}
			}
			delete(hostBatches, host)
		}
	}

	resetTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(bp.cfg.BatchTimeout, func() {
			bp.mu.Lock()
			flushBatches(true)
			bp.mu.Unlock()
		})
	}

	for {
		select {
		case event, ok := <-bp.inputCh:
			if !ok {
				bp.mu.Lock()
				flushBatches(true)
				bp.mu.Unlock()
				for _, w := range bp.workers {
					close(w.inputCh)
				}
				return
			}

			bp.mu.Lock()
			hostBatches[event.HostName] = append(hostBatches[event.HostName], event)

			totalSize := 0
			for _, events := range hostBatches {
				totalSize += len(events)
			}

			if totalSize >= bp.cfg.BatchSize {
				flushBatches(false)
				resetTimer()
			} else if timer == nil {
				resetTimer()
			}
			bp.mu.Unlock()

		case <-bp.ctx.Done():
			bp.mu.Lock()
			if timer != nil {
				timer.Stop()
			}
			bp.mu.Unlock()
			for _, w := range bp.workers {
				close(w.inputCh)
			}
			return
		}
	}
}

func (bp *BatchProcessor) runWorker(w worker) {
	defer bp.wg.Done()

	log.Printf("Worker %d started", w.id)

	for {
		select {
		case batch, ok := <-w.inputCh:
			if !ok {
				log.Printf("Worker %d stopped", w.id)
				return
			}
			bp.analyzeBatch(batch)

		case <-bp.ctx.Done():
			log.Printf("Worker %d stopped", w.id)
			return
		}
	}
}

func (bp *BatchProcessor) analyzeBatch(batch Batch) {
	ctx, cancel := context.WithTimeout(bp.ctx, 2*time.Minute)
	defer cancel()

	if len(batch.Events) == 0 {
		return
	}

	log.Printf("Analyzing batch for host %s with %d events", batch.HostName, len(batch.Events))

	// 1. Get embeddings for batch events
	searchTexts := make([]string, 0, len(batch.Events))
	for _, e := range batch.Events {
		searchTexts = append(searchTexts, e.ToBehaviorSummary())
	}

	// 2. Retrieve similar past events for context
	var similarEvents []Event
	if ollamaClient != nil && esClientInstance != nil {
		for i, text := range searchTexts {
			if text == "" {
				continue
			}
			emb, err := ollamaClient.GetEmbedding(ctx, text)
			if err != nil {
				log.Printf("Failed to get embedding for event %d: %v", i, err)
				continue
			}

			similar, err := esClientInstance.VectorSearch(ctx, batch.HostName, "", emb, 5)
			if err != nil {
				log.Printf("Failed to search similar events: %v", err)
				continue
			}
			similarEvents = append(similarEvents, similar...)
		}
	}

	// 3. Build analysis prompt
	prompt := buildAnalysisPrompt(batch.Events, similarEvents)

	// 4. Run AI analysis
	if ollamaClient != nil {
		response, err := ollamaClient.Generate(ctx, prompt)
		if err != nil {
			log.Printf("AI analysis failed: %v", err)
			return
		}

		verdict, confidence, evidence, summary, err := parseAnalysisResponse(response)
		if err != nil {
			log.Printf("Failed to parse AI response: %v", err)
			verdict = "unknown"
			confidence = 0.0
			evidence = []string{response}
			summary = "Failed to parse AI response"
		}

		// 5. Store analysis result
		if esClientInstance != nil {
			result := AnalysisResult{
				EventID:     "batch-" + batch.Events[0].EventID,
				Timestamp:   time.Now(),
				HostName:    batch.HostName,
				Verdict:     verdict,
				Confidence:  confidence,
				Evidence:    evidence,
				Summary:     summary,
				RawResponse: response,
			}
			if err := esClientInstance.IndexAnalysisResult(ctx, result); err != nil {
				log.Printf("Failed to index analysis result: %v", err)
			}
		}

		log.Printf("Analysis result for host %s: %s (%.2f) - %s",
			batch.HostName, verdict, confidence, summary)
	} else {
		log.Printf("No Ollama client configured, skipping AI analysis")
		log.Printf("Would analyze %d events for host %s", len(batch.Events), batch.HostName)
	}
}

func hashHost(host string) int {
	h := 0
	for _, c := range host {
		h = h*31 + int(c)
	}
	return h
}
