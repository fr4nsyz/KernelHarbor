package main

import (
	"context"
	"log"
	"sync"
	"time"

	"KernelHarbor/cmd/analysis/internal/incidents"
	"KernelHarbor/cmd/analysis/internal/interestingness"
	"KernelHarbor/cmd/analysis/internal/llm"
)

type BatchProcessorConfig struct {
	Workers         int
	BatchSize       int
	BatchTimeout    time.Duration
	MinBatchTimeout time.Duration
	LLMThreshold    float64
}

type Batch struct {
	HostName   string
	Events     []Event
	ReceivedAt time.Time
}

type Embedder interface {
	BatchEmbed(ctx context.Context, texts []string) ([][]float32, error)
}

type BatchProcessor struct {
	cfg             BatchProcessorConfig
	inputCh         chan Event
	workers         []worker
	mu              sync.Mutex
	wg              sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	interestingness *interestingness.Scorer
	llmBackend      llm.Backend
	embedder        Embedder
	incidentStore   *incidents.Store
	knownBinaries   map[string]bool
	alertStore      *AlertStore
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

func (bp *BatchProcessor) SetInterestingness(s *interestingness.Scorer) {
	bp.interestingness = s
}

func (bp *BatchProcessor) SetLLMBackend(b llm.Backend) {
	bp.llmBackend = b
}

func (bp *BatchProcessor) SetEmbedder(e Embedder) {
	bp.embedder = e
}

func (bp *BatchProcessor) SetIncidentStore(s *incidents.Store) {
	bp.incidentStore = s
}

func (bp *BatchProcessor) SetAlertStore(s *AlertStore) {
	bp.alertStore = s
}

func (bp *BatchProcessor) SetKnownBinaries(m map[string]bool) {
	bp.knownBinaries = m
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
	log.Printf("Started batch processor with %d workers (LLM threshold=%.2f)", bp.cfg.Workers, bp.cfg.LLMThreshold)
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
	default:
		log.Printf("Dropping event %s: processor busy", event.EventID)
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

type eventLikeWrapper struct {
	event Event
}

func (w eventLikeWrapper) GetEventType() string   { return w.event.EventType }
func (w eventLikeWrapper) GetCommandLine() string { return w.event.CommandLine }
func (w eventLikeWrapper) GetImagePath() string   { return w.event.ImagePath }
func (w eventLikeWrapper) GetRemoteAddr() string  { return w.event.RemoteAddr }
func (w eventLikeWrapper) GetRemotePort() uint16  { return w.event.RemotePort }
func (w eventLikeWrapper) GetFilePath() string    { return w.event.FilePath }
func (w eventLikeWrapper) GetProcessID() uint32   { return w.event.ProcessID }
func (w eventLikeWrapper) GetParentGUID() string  { return w.event.ParentGUID }
func (w eventLikeWrapper) GetHostName() string    { return w.event.HostName }

func (bp *BatchProcessor) analyzeBatch(batch Batch) {
	ctx, cancel := context.WithTimeout(bp.ctx, 5*time.Minute)
	defer cancel()

	if len(batch.Events) == 0 {
		return
	}

	log.Printf("Analyzing batch for host %s with %d events", batch.HostName, len(batch.Events))

	// Step 1: Compute interestingness score
	if bp.interestingness == nil || bp.llmBackend == nil {
		log.Printf("Skipping LLM analysis (interestingness=%v, backend=%v)", bp.interestingness, bp.llmBackend)
		return
	}

	likes := make([]interestingness.EventLike, len(batch.Events))
	for i, e := range batch.Events {
		likes[i] = eventLikeWrapper{e}
	}

	binaries := bp.knownBinaries
	if binaries == nil {
		binaries = interestingness.DefaultKnownBinaries()
	}

	score := bp.interestingness.Score(interestingness.BatchInfo{
		Events:   likes,
		HostName: batch.HostName,
	}, binaries)

	if score < bp.cfg.LLMThreshold {
		log.Printf("Batch for %s score=%.2f < threshold=%.2f, skipping LLM",
			batch.HostName, score, bp.cfg.LLMThreshold)
		return
	}

	log.Printf("Batch for %s score=%.2f >= threshold=%.2f, invoking LLM",
		batch.HostName, score, bp.cfg.LLMThreshold)

	// Step 2: Get embeddings and search for similar incidents
	var similarIncidents []llm.IncidentRef
	if bp.incidentStore != nil {
		embeddings, err := bp.embeddingsForBatch(ctx, batch.Events)
		if err != nil {
			log.Printf("Failed to get embeddings: %v", err)
		} else if len(embeddings) > 0 {
			refs := bp.incidentStore.SearchSimilar(embeddings[0], 5)
			for _, r := range refs {
				similarIncidents = append(similarIncidents, llm.IncidentRef{
					ID:       r.ID,
					Verdict:  r.Verdict,
					Verified: r.Verified,
					Summary:  r.Summary,
				})
			}
		}
	}

	// Step 3: Fetch process ancestry chains (from in-memory cache or ES)
	processChains := make(map[string][]llm.EventLike)
	if esClientInstance != nil {
		seenGUIDs := make(map[string]bool)
		for _, e := range batch.Events {
			if e.ParentGUID == "" || seenGUIDs[e.ParentGUID] {
				continue
			}
			seenGUIDs[e.ParentGUID] = true
			chain, err := esClientInstance.SearchProcessTree(ctx, batch.HostName, e.ParentGUID, 3)
			if err != nil {
				log.Printf("Failed to fetch process tree for parent %s: %v", e.ParentGUID, err)
				continue
			}
			if len(chain) > 0 {
				chainLikes := make([]llm.EventLike, len(chain))
				for i, c := range chain {
					chainLikes[i] = eventLikeWrapper{c}
				}
				processChains[e.ParentGUID] = chainLikes
			}
		}
	}

	// Step 4: Run LLM analysis
	llmLikes := toLLMEventLikes(batch.Events)
	req := llm.AnalysisRequest{
		Events:           llmLikes,
		ProcessChains:    processChains,
		SimilarIncidents: similarIncidents,
		Interestingness:  score,
		HostName:         batch.HostName,
	}

	result, err := bp.llmBackend.Analyze(req)
	if err != nil {
		log.Printf("LLM analysis failed: %v", err)
		return
	}

	log.Printf("LLM verdict for %s: %s (%.2f) - %s [model=%s]",
		batch.HostName, result.Verdict, result.Confidence, result.Summary, result.ModelUsed)

	// Step 5: Store alert — NO actions generated
	if bp.alertStore != nil && (result.Verdict == "suspicious" || result.Verdict == "malicious") {
		alert := Alert{
			ID:         generateEventID(),
			Timestamp:  time.Now(),
			HostName:   batch.HostName,
			Verdict:    result.Verdict,
			Confidence: result.Confidence,
			Evidence:   result.Evidence,
			Summary:    result.Summary,
			ModelUsed:  result.ModelUsed,
			Events:     batch.Events,
			Source:     "llm",
		}
		bp.alertStore.Add(alert)
		if esClientInstance != nil {
			if err := esClientInstance.IndexAlert(ctx, alert); err != nil {
				log.Printf("Failed to index LLM alert to ES: %v", err)
			}
		}
		log.Printf("Alert generated: %s (%s, %.2f)", alert.ID, alert.Verdict, alert.Confidence)

		// If incident store available, store as unverified incident for future RAG
		if bp.incidentStore != nil {
			incidentLikes := make([]incidents.EventLike, len(batch.Events))
			for i, e := range batch.Events {
				incidentLikes[i] = eventLikeWrapper{e}
			}

			var embedding []float32
			embeds, err := bp.embeddingsForBatch(ctx, batch.Events)
			if err == nil && len(embeds) > 0 {
				embedding = embeds[0]
			}

			bp.incidentStore.Add(&incidents.Incident{
				ID:         alert.ID,
				CreatedAt:  time.Now(),
				Events:     incidentLikes,
				Embedding:  embedding,
				Verdict:    result.Verdict,
				IsVerified: false,
				Summary:    result.Summary,
			})
		}
	}
}

func (bp *BatchProcessor) embeddingsForBatch(ctx context.Context, events []Event) ([][]float32, error) {
	if bp.embedder == nil {
		return nil, nil
	}

	var texts []string
	for _, e := range events {
		texts = append(texts, e.ToBehaviorSummary())
	}

	return bp.embedder.BatchEmbed(ctx, texts)
}

func hashHost(host string) int {
	h := 0
	for _, c := range host {
		h = h*31 + int(c)
	}
	return h
}

func toLLMEventLikes(events []Event) []llm.EventLike {
	likes := make([]llm.EventLike, len(events))
	for i, e := range events {
		likes[i] = eventLikeWrapper{e}
	}
	return likes
}

func toLLMChainLikes(events []Event) []llm.EventLike {
	likes := make([]llm.EventLike, len(events))
	for i, e := range events {
		likes[i] = eventLikeWrapper{e}
	}
	return likes
}
