package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/elastic/go-elasticsearch/v9/esapi"
)

const (
	EventsIndex   = "kb-events"
	AnalysisIndex = "kb-analysis"
	VectorDim     = 768
	VectorField   = "embedding"
	VectorModel   = "nomic-embed-text"
)

type ESConfig struct {
	Addresses []string
	Username  string
	Password  string
	Index     string
}

type ESClient struct {
	client  *elasticsearch.Client
	index   string
	vectors int
}

var esClientInstance *ESClient

func NewESClient(cfg ESConfig) (*ESClient, error) {
	escfg := elasticsearch.Config{
		Addresses: cfg.Addresses,
	}

	if cfg.Username != "" && cfg.Password != "" {
		escfg.Username = cfg.Username
		escfg.Password = cfg.Password
	}

	client, err := elasticsearch.NewClient(escfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
	}

	esClientInstance = &ESClient{
		client:  client,
		index:   cfg.Index,
		vectors: VectorDim,
	}

	if err := esClientInstance.ensureIndex(context.Background()); err != nil {
		return nil, err
	}

	return esClientInstance, nil
}

func (e *ESClient) ensureIndex(ctx context.Context) error {
	res, err := e.client.Indices.Exists([]string{e.index})
	if err != nil {
		return fmt.Errorf("failed to check index existence: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 200 {
		log.Printf("Index %s already exists", e.index)
		return nil
	}

	mapping := e.buildMapping()
	res, err = e.client.Indices.Create(
		e.index,
		e.client.Indices.Create.WithBody(bytes.NewReader(mapping)),
		e.client.Indices.Create.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("index creation error: %s", res.String())
	}

	log.Printf("Created index %s", e.index)
	return nil
}

func (e *ESClient) buildMapping() []byte {
	mapping := map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
			"index": map[string]any{
				"max_mapped_value_length": 32766,
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"@timestamp": map[string]any{
					"type": "date",
				},
				"host.name": map[string]any{
					"type": "keyword",
				},
				"event.type": map[string]any{
					"type": "keyword",
				},
				"event.id": map[string]any{
					"type": "keyword",
				},
				"process.guid": map[string]any{
					"type": "keyword",
				},
				"parent.guid": map[string]any{
					"type": "keyword",
				},
				"process.pid": map[string]any{
					"type": "integer",
				},
				"parent.pid": map[string]any{
					"type": "integer",
				},
				"image.path": map[string]any{
					"type": "text",
					"fields": map[string]any{
						"keyword": map[string]any{
							"type":         "keyword",
							"ignore_above": 256,
						},
					},
				},
				"command.line": map[string]any{
					"type": "text",
				},
				"working.directory": map[string]any{
					"type": "keyword",
				},
				"user.name": map[string]any{
					"type": "keyword",
				},
				"file.path": map[string]any{
					"type": "text",
					"fields": map[string]any{
						"keyword": map[string]any{
							"type":         "keyword",
							"ignore_above": 256,
						},
					},
				},
				"file.flags": map[string]any{
					"type": "keyword",
				},
				"socket.info": map[string]any{
					"type": "keyword",
				},
				"remote.address": map[string]any{
					"type": "ip",
				},
				"remote.port": map[string]any{
					"type": "integer",
				},
				"embedding": map[string]any{
					"type":               "dense_vector",
					"dims":               e.vectors,
					"index":              true,
					"similarity":         "cosine",
					"indexing_threshold": 500,
				},
				"metadata": map[string]any{
					"type":    "object",
					"enabled": true,
				},
			},
		},
	}

	data, _ := json.Marshal(mapping)
	return data
}

func (e *ESClient) BulkIndex(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, event := range events {
		meta := map[string]any{
			"index": map[string]any{
				"_index": e.index,
				"_id":    event.EventID,
			},
		}
		metaBytes, _ := json.Marshal(meta)
		buf.Write(metaBytes)
		buf.WriteByte('\n')

		docBytes, _ := json.Marshal(event)
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	res, err := e.client.Bulk(
		bytes.NewReader(buf.Bytes()),
		e.client.Bulk.WithContext(ctx),
		e.client.Bulk.WithRefresh("false"),
	)
	if err != nil {
		return fmt.Errorf("bulk index request failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("bulk index error: %s", res.String())
	}

	log.Printf("Indexed %d events", len(events))
	return nil
}

func (e *ESClient) SearchProcessTree(ctx context.Context, hostName, processGUID string, depth int) ([]Event, error) {
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							"host.name": hostName,
						},
					},
					map[string]any{
						"bool": map[string]any{
							"should": []any{
								map[string]any{
									"term": map[string]any{
										"process.guid": processGUID,
									},
								},
								map[string]any{
									"term": map[string]any{
										"parent.guid": processGUID,
									},
								},
							},
						},
					},
				},
			},
		},
		"sort": []any{
			map[string]any{
				"@timestamp": map[string]any{
					"order": "desc",
				},
			},
		},
		"size": 100,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := e.client.Search(
		e.client.Search.WithContext(ctx),
		e.client.Search.WithIndex(e.index),
		e.client.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("search error: %s", res.String())
	}

	var sr struct {
		Hits struct {
			Hits []struct {
				Source Event `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return nil, err
	}

	events := make([]Event, 0, len(sr.Hits.Hits))
	for _, hit := range sr.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
}

func (e *ESClient) VectorSearch(ctx context.Context, hostName, queryText string, embedding []float32, limit int) ([]Event, error) {
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							"host.name": hostName,
						},
					},
					map[string]any{
						"knn": map[string]any{
							"field":          "embedding",
							"query_vector":   embedding,
							"k":              limit,
							"num_candidates": 100,
						},
					},
				},
			},
		},
		"size": limit,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := e.client.Search(
		e.client.Search.WithContext(ctx),
		e.client.Search.WithIndex(e.index),
		e.client.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("vector search error: %s", res.String())
	}

	var sr struct {
		Hits struct {
			Hits []struct {
				Source Event `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return nil, err
	}

	events := make([]Event, 0, len(sr.Hits.Hits))
	for _, hit := range sr.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
}

func (e *ESClient) HybridSearch(ctx context.Context, hostName, queryText string, embedding []float32, limit int) ([]Event, error) {
	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"term": map[string]any{
							"host.name": hostName,
						},
					},
					map[string]any{
						"bool": map[string]any{
							"should": []any{
								map[string]any{
									"multi_match": map[string]any{
										"query":  queryText,
										"fields": []string{"command.line", "image.path^2", "file.path"},
										"type":   "best_fields",
									},
								},
								map[string]any{
									"knn": map[string]any{
										"field":          "embedding",
										"query_vector":   embedding,
										"k":              limit,
										"num_candidates": 100,
									},
								},
							},
						},
					},
				},
			},
		},
		"size": limit,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := e.client.Search(
		e.client.Search.WithContext(ctx),
		e.client.Search.WithIndex(e.index),
		e.client.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("hybrid search error: %s", res.String())
	}

	var sr struct {
		Hits struct {
			Hits []struct {
				Source Event `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		return nil, err
	}

	events := make([]Event, 0, len(sr.Hits.Hits))
	for _, hit := range sr.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
}

func (e *ESClient) IndexAnalysisResult(ctx context.Context, result AnalysisResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}

	req := esapi.IndexRequest{
		Index:      AnalysisIndex,
		DocumentID: result.EventID + "-" + result.Timestamp.Format(time.RFC3339),
		Body:       bytes.NewReader(data),
		Refresh:    "false",
	}

	res, err := req.Do(ctx, e.client)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("index analysis error: %s", res.String())
	}

	return nil
}
