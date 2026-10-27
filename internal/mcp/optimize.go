package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/comma-compliance/arc-relay/internal/llm"
)

// PromptVersion is a hash identifier for the current system prompt.
// Bump this when the prompt changes to invalidate cached optimizations.
const PromptVersion = "v1.1"

// batchConcurrency caps concurrent LLM calls within one server's optimization.
const batchConcurrency = 4

// OptimizerSystemPrompt is the system prompt used for LLM-based tool optimization.
const OptimizerSystemPrompt = `You optimize MCP tool metadata for LLM use. Compress descriptions and JSON Schemas without changing tool behavior, decision boundaries, or required semantics.

Optimize for correct tool choice and correct parameter construction, not for human-readable completeness.
Preserve the tool name exactly.
Never add, remove, strengthen, or weaken validation semantics.
Return ONLY valid JSON: an array of objects with {name, description, inputSchema}. No markdown fences or other text.

CRITICAL CONSTRAINT: Your output MUST be smaller than the input. Never expand, elaborate, or add detail. If a description is already concise (under ~150 characters), return it unchanged. If a schema is already minimal, return it unchanged. When in doubt, keep the original text rather than rephrasing into something longer.

DESCRIPTION RULES
1. Keep only what an LLM needs to:
   - know what the tool does
   - know when to use it
   - know when NOT to use it, including similar tools by name
   - see safety/destructive warnings
   - understand required argument semantics not obvious from names/schema
   - understand omission/default/null behavior when it changes behavior
2. Remove boilerplate, repeated explanations, Args blocks that duplicate schema, and most examples.
3. Keep at most 1 very short example only if syntax or notation is otherwise easy to misuse.
4. For tools with multiple modes/actions, preserve the discriminator and the required fields for each mode/action.
5. Keep descriptions contrastive and distinguishable from similar tools.
6. Compress mutating/high-risk tools more conservatively than read-only tools.
7. Preserve "use X instead" guidance where it affects tool selection.
8. If a description is already short and clear, return it as-is. Do NOT rephrase short descriptions.

SCHEMA RULES
1. Keep all behavior/validation keywords and references needed for correctness, including:
   type, properties, required, enum, const, format, pattern, minimum, maximum, items,
   additionalProperties, oneOf, anyOf, allOf, not, if, then, else, dependentRequired,
   dependentSchemas, prefixItems, $ref, $defs/definitions when referenced.
2. Remove non-behavioral metadata when safe:
   $schema, $id, title, examples, deprecated, readOnly, writeOnly,
   contentMediaType, contentEncoding, x-* vendor extensions.
3. Remove default only if omission behavior is not important for correct tool use.
4. Remove property descriptions only when the name plus validation is already sufficient.
   Keep them for required, ambiguous, overloaded, safety-relevant, or behavior-changing params.
5. Deduplicate repeated descriptions across anyOf/oneOf branches by hoisting to property level.
6. Minify the JSON (no unnecessary whitespace).
7. If a schema is already compact with no removable metadata, return it unchanged.`

// ToolAudit represents the analysis of a server's tool definitions.
type ToolAudit struct {
	ServerID       string     `json:"server_id"`
	ServerName     string     `json:"server_name"`
	ToolCount      int        `json:"tool_count"`
	OriginalChars  int        `json:"original_chars"`
	OptimizedChars int        `json:"optimized_chars,omitempty"` // 0 if not yet optimized
	EstTokens      int        `json:"est_tokens"`                // original_chars / 4
	SavingsPercent float64    `json:"savings_percent,omitempty"`
	ToolsHash      string     `json:"tools_hash"`
	HasOptimized   bool       `json:"has_optimized"`
	IsStale        bool       `json:"is_stale"`
	Status         string     `json:"status"`
	Tools          []ToolStat `json:"tools,omitempty"`
}

// ToolStat holds size info for a single tool, with optional optimized values.
type ToolStat struct {
	Name          string `json:"name"`
	DescChars     int    `json:"desc_chars"`
	SchemaChar    int    `json:"schema_chars"`
	TotalChars    int    `json:"total_chars"`
	OptDescChars  int    `json:"opt_desc_chars,omitempty"`
	OptSchemaChar int    `json:"opt_schema_chars,omitempty"`
	OptTotalChars int    `json:"opt_total_chars,omitempty"`
}

// AuditTools analyzes tool definitions and returns size statistics.
func AuditTools(tools []Tool) ([]ToolStat, int) {
	var stats []ToolStat
	total := 0
	for _, t := range tools {
		descLen := len(t.Description)
		schemaLen := len(t.InputSchema)
		toolTotal := descLen + schemaLen
		total += toolTotal
		stats = append(stats, ToolStat{
			Name:       t.Name,
			DescChars:  descLen,
			SchemaChar: schemaLen,
			TotalChars: toolTotal,
		})
	}
	return stats, total
}

// HashTools computes a SHA-256 hash of the tool definitions for change detection.
// Tools are sorted by name first so the hash is stable regardless of server return order.
func HashTools(tools []Tool) string {
	sorted := make([]Tool, len(tools))
	copy(sorted, tools)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	h := sha256.New()
	for _, t := range sorted {
		h.Write([]byte(t.Name))
		h.Write([]byte(t.Description))
		h.Write(t.InputSchema)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// PruneSchema applies deterministic, safe transformations to a JSON schema.
// This removes non-validation metadata without needing an LLM call.
func PruneSchema(schema json.RawMessage) json.RawMessage {
	if len(schema) == 0 {
		return schema
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(schema, &obj); err != nil {
		return schema // not an object, return as-is
	}

	// Keys safe to remove (non-validation metadata)
	removeKeys := []string{
		"$schema", "$id", "title", "examples", "example",
		"deprecated", "readOnly", "writeOnly",
		"contentMediaType", "contentEncoding",
	}
	for _, key := range removeKeys {
		delete(obj, key)
	}

	// Remove x-* vendor extensions
	for key := range obj {
		if strings.HasPrefix(key, "x-") {
			delete(obj, key)
		}
	}

	// Recursively prune nested objects and schema composition keywords
	for key, val := range obj {
		switch key {
		case "properties":
			obj[key] = pruneProperties(val)
		case "items", "$defs", "definitions", "if", "then", "else", "not":
			obj[key] = pruneNested(val)
		case "anyOf", "oneOf", "allOf", "prefixItems":
			obj[key] = pruneArray(val)
		}
	}

	result, err := json.Marshal(obj)
	if err != nil {
		return schema
	}
	return result
}

func pruneProperties(raw json.RawMessage) json.RawMessage {
	var props map[string]json.RawMessage
	if err := json.Unmarshal(raw, &props); err != nil {
		return raw
	}
	for key, val := range props {
		props[key] = PruneSchema(val)
	}
	result, _ := json.Marshal(props)
	return result
}

func pruneNested(raw json.RawMessage) json.RawMessage {
	// Could be object or array
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for key, val := range obj {
			obj[key] = PruneSchema(val)
		}
		result, _ := json.Marshal(obj)
		return result
	}
	return pruneArray(raw)
}

func pruneArray(raw json.RawMessage) json.RawMessage {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return raw
	}
	for i, val := range arr {
		arr[i] = PruneSchema(val)
	}
	result, _ := json.Marshal(arr)
	return result
}

// OptimizeTools uses an LLM to optimize tool definitions for reduced token usage.
// Tools are sent in batches to stay within context limits.
func OptimizeTools(ctx context.Context, client *llm.Client, tools []Tool) ([]Tool, error) {
	if len(tools) == 0 {
		return tools, nil
	}

	// First apply deterministic schema pruning
	pruned := make([]Tool, len(tools))
	for i, t := range tools {
		pruned[i] = Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: PruneSchema(t.InputSchema),
		}
	}

	// If no LLM client, return just the pruned version
	if client == nil || !client.Available() {
		return pruned, nil
	}

	// Batch tools by character budget so large schemas don't overflow output tokens.
	// Target ~30K input chars per batch - the LLM output will be smaller after compression.
	const charBudget = 30000
	batches := batchBySize(pruned, charBudget)

	// Run batches concurrently; results are reassembled in batch order. The
	// first failure cancels the rest, since any failed batch fails the run.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([][]Tool, len(batches))
	var firstErr error
	var errOnce sync.Once
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for batchIdx, batch := range batches {
		wg.Add(1)
		go func(batchIdx int, batch []Tool) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			result, err := optimizeBatch(ctx, client, batch)
			if err != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("optimizing batch %d of %d (%d tools): %w", batchIdx+1, len(batches), len(batch), err)
					cancel()
				})
				return
			}
			results[batchIdx] = result
		}(batchIdx, batch)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var optimized []Tool
	for _, r := range results {
		optimized = append(optimized, r...)
	}

	// Verify all tools are accounted for with no duplicates
	if len(optimized) != len(tools) {
		return nil, fmt.Errorf("LLM returned %d tools but expected %d", len(optimized), len(tools))
	}

	expectedNames := make(map[string]bool, len(tools))
	for _, t := range tools {
		expectedNames[t.Name] = true
	}
	seenNames := make(map[string]bool, len(optimized))
	for _, t := range optimized {
		if !expectedNames[t.Name] {
			return nil, fmt.Errorf("LLM returned unknown tool name %q", t.Name)
		}
		if seenNames[t.Name] {
			return nil, fmt.Errorf("LLM returned duplicate tool name %q", t.Name)
		}
		seenNames[t.Name] = true
	}

	// Per-tool safety: if the LLM expanded a tool, keep the pruned original.
	// Match by name, not position, since the LLM may reorder output.
	prunedByName := make(map[string]Tool, len(pruned))
	for _, t := range pruned {
		prunedByName[t.Name] = t
	}
	for i, opt := range optimized {
		orig := prunedByName[opt.Name]
		optSize := len(opt.Description) + len(opt.InputSchema)
		origSize := len(orig.Description) + len(orig.InputSchema)
		if optSize >= origSize {
			optimized[i] = orig
		}
	}

	return optimized, nil
}

// optimizeBatch sends a batch of tools to the LLM for optimization.
func optimizeBatch(ctx context.Context, client *llm.Client, tools []Tool) ([]Tool, error) {
	// Build the user prompt with tool definitions
	toolsJSON, err := json.MarshalIndent(tools, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling tools: %w", err)
	}

	userPrompt := fmt.Sprintf("Optimize these %d MCP tool definitions. Return ONLY a JSON array of the optimized tools.\n\n%s", len(tools), string(toolsJSON))

	result, err := client.Complete(ctx, OptimizerSystemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	// Parse the response - extract JSON from the response text
	jsonStr := extractJSON(result.Text)

	var optimized []Tool
	if err := json.Unmarshal([]byte(jsonStr), &optimized); err != nil {
		return nil, fmt.Errorf("parsing LLM response as JSON: %w (response: %.500s)", err, result.Text)
	}

	return optimized, nil
}

// batchBySize splits tools into batches where each batch's total character
// count stays under the given budget. Tools larger than the budget get their
// own single-tool batch.
func batchBySize(tools []Tool, budget int) [][]Tool {
	var batches [][]Tool
	var current []Tool
	currentSize := 0

	for _, t := range tools {
		toolSize := len(t.Description) + len(t.InputSchema)
		// If adding this tool would exceed budget, flush current batch
		if len(current) > 0 && currentSize+toolSize > budget {
			batches = append(batches, current)
			current = nil
			currentSize = 0
		}
		current = append(current, t)
		currentSize += toolSize
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

// extractJSON finds and extracts a JSON array from LLM response text,
// handling cases where the LLM wraps it in markdown code fences.
func extractJSON(text string) string {
	text = strings.TrimSpace(text)

	// Try to find JSON array directly
	if strings.HasPrefix(text, "[") {
		return text
	}

	// Strip markdown code fences
	re := regexp.MustCompile("(?s)```(?:json)?\\s*\n?(.*?)\\s*```")
	if matches := re.FindStringSubmatch(text); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Last resort: find first [ and last ]
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start >= 0 && end > start {
		return text[start : end+1]
	}

	return text
}
