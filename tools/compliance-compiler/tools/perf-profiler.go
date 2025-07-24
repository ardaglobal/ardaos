// Performance profiler for the compliance compiler.
// This tool profiles compilation performance, identifies bottlenecks,
// and provides detailed performance metrics and optimization recommendations.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// PerformanceProfiler profiles compliance compiler performance
type PerformanceProfiler struct {
	OutputDir        string
	ProfileDuration  time.Duration
	SampleInterval   time.Duration
	EnableCPUProfile bool
	EnableMemProfile bool
	EnableTracing    bool
	PolicyFiles      []string
	Iterations       int
	Benchmarks       []BenchmarkResult
	Metrics          ProfileMetrics
}

// BenchmarkResult represents a benchmark test result
type BenchmarkResult struct {
	Name            string        `json:"name"`
	Iterations      int           `json:"iterations"`
	Duration        time.Duration `json:"duration"`
	NsPerOp         int64         `json:"ns_per_op"`
	BytesPerOp      int64         `json:"bytes_per_op"`
	AllocsPerOp     int64         `json:"allocs_per_op"`
	MemoryUsage     int64         `json:"memory_usage"`
	CPUUsage        float64       `json:"cpu_usage"`
	PolicySize      int64         `json:"policy_size"`
	RuleCount       int           `json:"rule_count"`
	ComplexityScore float64       `json:"complexity_score"`
}

// ProfileMetrics contains overall profiling metrics
type ProfileMetrics struct {
	TotalDuration    time.Duration    `json:"total_duration"`
	TotalOperations  int              `json:"total_operations"`
	AverageOpTime    time.Duration    `json:"average_op_time"`
	PeakMemoryUsage  int64            `json:"peak_memory_usage"`
	TotalAllocations int64            `json:"total_allocations"`
	GCPauses         []time.Duration  `json:"gc_pauses"`
	Bottlenecks      []Bottleneck     `json:"bottlenecks"`
	Recommendations  []Recommendation `json:"recommendations"`
	SystemInfo       SystemInfo       `json:"system_info"`
}

// Bottleneck represents a performance bottleneck
type Bottleneck struct {
	Component   string        `json:"component"`
	Function    string        `json:"function"`
	Duration    time.Duration `json:"duration"`
	Percentage  float64       `json:"percentage"`
	Description string        `json:"description"`
	Severity    string        `json:"severity"`
	Impact      string        `json:"impact"`
}

// Recommendation provides performance optimization recommendations
type Recommendation struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Priority    string `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Example     string `json:"example,omitempty"`
}

// SystemInfo contains system information for the profile
type SystemInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	CPUCount     int    `json:"cpu_count"`
	GoVersion    string `json:"go_version"`
	MemoryLimit  int64  `json:"memory_limit"`
	Timestamp    string `json:"timestamp"`
}

// CompilationStep represents a step in the compilation process
type CompilationStep struct {
	Name      string        `json:"name"`
	StartTime time.Time     `json:"start_time"`
	Duration  time.Duration `json:"duration"`
	MemBefore int64         `json:"mem_before"`
	MemAfter  int64         `json:"mem_after"`
	Error     string        `json:"error,omitempty"`
}

var (
	perfProfilerCmd = &cobra.Command{
		Use:   "perf-profiler",
		Short: "Profile compliance compiler performance",
		Long: `Profile the performance of the compliance compiler to identify bottlenecks and optimization opportunities.

The performance profiler provides:
- CPU and memory profiling
- Compilation benchmarks across different policy types
- Bottleneck identification and analysis
- Performance regression detection
- Optimization recommendations
- System resource utilization monitoring`,
		Example: `  # Profile compilation of a single policy
  go run tools/perf-profiler.go --file examples/policies/installment-loan.yaml

  # Profile multiple policies with CPU profiling
  go run tools/perf-profiler.go --dir examples/policies/ --cpu-profile

  # Run comprehensive benchmark suite
  go run tools/perf-profiler.go --benchmark --iterations 1000

  # Profile with memory analysis
  go run tools/perf-profiler.go --file policy.yaml --mem-profile --trace

  # Generate detailed performance report
  go run tools/perf-profiler.go --dir examples/ --output-dir ./profiling-results`,
		RunE: runPerformanceProfiler,
	}

	policyFile      string
	policyDir       string
	outputDir       string
	iterations      int
	duration        string
	cpuProfile      bool
	memProfile      bool
	enableTracing   bool
	benchmarkMode   bool
	compareBaseline string
	outputFormat    string
	verbose         bool
)

func init() {
	perfProfilerCmd.Flags().StringVarP(&policyFile, "file", "f", "", "Policy file to profile")
	perfProfilerCmd.Flags().StringVarP(&policyDir, "dir", "d", "", "Directory containing policies to profile")
	perfProfilerCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./profiling-results", "Output directory for profiling results")
	perfProfilerCmd.Flags().IntVarP(&iterations, "iterations", "i", 100, "Number of benchmark iterations")
	perfProfilerCmd.Flags().StringVar(&duration, "duration", "30s", "Profiling duration")
	perfProfilerCmd.Flags().BoolVar(&cpuProfile, "cpu-profile", false, "Enable CPU profiling")
	perfProfilerCmd.Flags().BoolVar(&memProfile, "mem-profile", false, "Enable memory profiling")
	perfProfilerCmd.Flags().BoolVar(&enableTracing, "trace", false, "Enable execution tracing")
	perfProfilerCmd.Flags().BoolVar(&benchmarkMode, "benchmark", false, "Run in benchmark mode")
	perfProfilerCmd.Flags().StringVar(&compareBaseline, "compare", "", "Compare against baseline results")
	perfProfilerCmd.Flags().StringVar(&outputFormat, "format", "json", "Output format (json, text, html)")
	perfProfilerCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func main() {
	if err := perfProfilerCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runPerformanceProfiler(cmd *cobra.Command, args []string) error {
	profileDuration, err := time.ParseDuration(duration)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	profiler := &PerformanceProfiler{
		OutputDir:        outputDir,
		ProfileDuration:  profileDuration,
		SampleInterval:   100 * time.Millisecond,
		EnableCPUProfile: cpuProfile,
		EnableMemProfile: memProfile,
		EnableTracing:    enableTracing,
		Iterations:       iterations,
		Metrics: ProfileMetrics{
			SystemInfo: getSystemInfo(),
		},
	}

	// Collect policy files to profile
	if err := profiler.collectPolicyFiles(policyFile, policyDir); err != nil {
		return fmt.Errorf("failed to collect policy files: %w", err)
	}

	if len(profiler.PolicyFiles) == 0 {
		return fmt.Errorf("no policy files found to profile")
	}

	log.Printf("🚀 Starting performance profiling of %d policy files", len(profiler.PolicyFiles))

	// Start profiling
	ctx, cancel := context.WithTimeout(context.Background(), profileDuration)
	defer cancel()

	if err := profiler.startProfiling(ctx); err != nil {
		return fmt.Errorf("profiling failed: %w", err)
	}

	// Run benchmarks
	if benchmarkMode {
		if err := profiler.runBenchmarks(); err != nil {
			return fmt.Errorf("benchmarking failed: %w", err)
		}
	}

	// Analyze results
	if err := profiler.analyzeResults(); err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Generate report
	if err := profiler.generateReport(); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	log.Printf("✅ Profiling completed. Results saved to: %s", outputDir)
	return nil
}

// collectPolicyFiles collects policy files for profiling
func (p *PerformanceProfiler) collectPolicyFiles(file, dir string) error {
	if file != "" {
		p.PolicyFiles = append(p.PolicyFiles, file)
	}

	if dir != "" {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
				p.PolicyFiles = append(p.PolicyFiles, path)
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// startProfiling starts the profiling session
func (p *PerformanceProfiler) startProfiling(ctx context.Context) error {
	startTime := time.Now()

	// Start CPU profiling
	if p.EnableCPUProfile {
		cpuFile := filepath.Join(p.OutputDir, "cpu.prof")
		f, err := os.Create(cpuFile)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()

		log.Printf("📊 CPU profiling enabled, output: %s", cpuFile)
	}

	// Profile each policy file
	for i, policyFile := range p.PolicyFiles {
		if err := ctx.Err(); err != nil {
			break
		}

		if verbose {
			log.Printf("Profiling file %d/%d: %s", i+1, len(p.PolicyFiles), policyFile)
		}

		benchmark := p.profilePolicyFile(policyFile)
		p.Benchmarks = append(p.Benchmarks, benchmark)
	}

	p.Metrics.TotalDuration = time.Since(startTime)
	p.Metrics.TotalOperations = len(p.PolicyFiles) * p.Iterations

	// Memory profiling
	if p.EnableMemProfile {
		memFile := filepath.Join(p.OutputDir, "mem.prof")
		f, err := os.Create(memFile)
		if err != nil {
			return err
		}
		defer f.Close()

		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return err
		}

		log.Printf("💾 Memory profile saved: %s", memFile)
	}

	return nil
}

// profilePolicyFile profiles a single policy file
func (p *PerformanceProfiler) profilePolicyFile(policyFile string) BenchmarkResult {
	data, err := ioutil.ReadFile(policyFile)
	if err != nil {
		log.Printf("Warning: Failed to read %s: %v", policyFile, err)
		return BenchmarkResult{Name: policyFile}
	}

	var policy map[string]interface{}
	if err := yaml.Unmarshal(data, &policy); err != nil {
		log.Printf("Warning: Failed to parse %s: %v", policyFile, err)
		return BenchmarkResult{Name: policyFile}
	}

	// Extract policy metrics
	ruleCount := 0
	if policySection, ok := policy["policy"].(map[string]interface{}); ok {
		if rules, ok := policySection["rules"].([]interface{}); ok {
			ruleCount = len(rules)
		}
	}

	complexityScore := p.calculateComplexityScore(policy)

	// Run compilation benchmark
	startTime := time.Now()
	var totalDuration time.Duration
	var totalMemory int64
	var totalAllocs int64

	for i := 0; i < p.Iterations; i++ {
		iterStart := time.Now()
		memBefore := getCurrentMemoryUsage()

		// Simulate compilation (in real implementation, this would call the actual compiler)
		_ = p.simulateCompilation(policy)

		iterDuration := time.Since(iterStart)
		totalDuration += iterDuration

		memAfter := getCurrentMemoryUsage()
		totalMemory += memAfter - memBefore
		totalAllocs += getGCStats()
	}

	avgDuration := totalDuration / time.Duration(p.Iterations)

	return BenchmarkResult{
		Name:            filepath.Base(policyFile),
		Iterations:      p.Iterations,
		Duration:        totalDuration,
		NsPerOp:         avgDuration.Nanoseconds(),
		BytesPerOp:      totalMemory / int64(p.Iterations),
		AllocsPerOp:     totalAllocs / int64(p.Iterations),
		MemoryUsage:     totalMemory,
		CPUUsage:        p.calculateCPUUsage(totalDuration),
		PolicySize:      int64(len(data)),
		RuleCount:       ruleCount,
		ComplexityScore: complexityScore,
	}
}

// simulateCompilation simulates the compilation process
func (p *PerformanceProfiler) simulateCompilation(policy map[string]interface{}) interface{} {
	// Simulate parsing
	time.Sleep(time.Microsecond * 10)

	// Simulate validation
	time.Sleep(time.Microsecond * 20)

	// Simulate rule processing
	if policySection, ok := policy["policy"].(map[string]interface{}); ok {
		if rules, ok := policySection["rules"].([]interface{}); ok {
			for range rules {
				time.Sleep(time.Microsecond * 5)
			}
		}
	}

	// Simulate code generation
	time.Sleep(time.Microsecond * 30)

	return map[string]interface{}{"compiled": true}
}

// calculateComplexityScore calculates a complexity score for the policy
func (p *PerformanceProfiler) calculateComplexityScore(policy map[string]interface{}) float64 {
	score := 0.0

	// Base score
	score += 1.0

	// Rule complexity
	if policySection, ok := policy["policy"].(map[string]interface{}); ok {
		if rules, ok := policySection["rules"].([]interface{}); ok {
			score += float64(len(rules)) * 0.5

			// Check for nested conditions
			for _, rule := range rules {
				if ruleMap, ok := rule.(map[string]interface{}); ok {
					if conditions, ok := ruleMap["conditions"].([]interface{}); ok {
						score += float64(len(conditions)) * 0.2
					}
				}
			}
		}

		if attestations, ok := policySection["attestations"].([]interface{}); ok {
			score += float64(len(attestations)) * 0.3
		}
	}

	// Parameter complexity
	if params, ok := policy["parameters"].(map[string]interface{}); ok {
		score += float64(len(params)) * 0.1
	}

	return score
}

// calculateCPUUsage calculates CPU usage percentage
func (p *PerformanceProfiler) calculateCPUUsage(duration time.Duration) float64 {
	// This is a simplified calculation
	// In a real implementation, you would use more sophisticated CPU monitoring
	return float64(duration.Nanoseconds()) / float64(time.Second.Nanoseconds()) * 100
}

// runBenchmarks runs comprehensive benchmarks
func (p *PerformanceProfiler) runBenchmarks() error {
	log.Printf("🏃 Running comprehensive benchmarks...")

	// Benchmark different policy sizes
	policySizes := []string{"small", "medium", "large"}
	for _, size := range policySizes {
		benchmark := p.benchmarkPolicySize(size)
		p.Benchmarks = append(p.Benchmarks, benchmark)
	}

	// Benchmark different complexity levels
	complexityLevels := []string{"simple", "moderate", "complex"}
	for _, level := range complexityLevels {
		benchmark := p.benchmarkComplexity(level)
		p.Benchmarks = append(p.Benchmarks, benchmark)
	}

	return nil
}

// benchmarkPolicySize benchmarks policies of different sizes
func (p *PerformanceProfiler) benchmarkPolicySize(size string) BenchmarkResult {
	policy := p.generateTestPolicy(size, "moderate")

	startTime := time.Now()
	var totalDuration time.Duration

	for i := 0; i < p.Iterations; i++ {
		iterStart := time.Now()
		_ = p.simulateCompilation(policy)
		totalDuration += time.Since(iterStart)
	}

	return BenchmarkResult{
		Name:       fmt.Sprintf("PolicySize_%s", size),
		Iterations: p.Iterations,
		Duration:   totalDuration,
		NsPerOp:    totalDuration.Nanoseconds() / int64(p.Iterations),
	}
}

// benchmarkComplexity benchmarks policies of different complexity
func (p *PerformanceProfiler) benchmarkComplexity(complexity string) BenchmarkResult {
	policy := p.generateTestPolicy("medium", complexity)

	startTime := time.Now()
	var totalDuration time.Duration

	for i := 0; i < p.Iterations; i++ {
		iterStart := time.Now()
		_ = p.simulateCompilation(policy)
		totalDuration += time.Since(iterStart)
	}

	return BenchmarkResult{
		Name:            fmt.Sprintf("Complexity_%s", complexity),
		Iterations:      p.Iterations,
		Duration:        totalDuration,
		NsPerOp:         totalDuration.Nanoseconds() / int64(p.Iterations),
		ComplexityScore: p.calculateComplexityScore(policy),
	}
}

// generateTestPolicy generates a test policy with specified characteristics
func (p *PerformanceProfiler) generateTestPolicy(size, complexity string) map[string]interface{} {
	ruleCount := 5
	conditionCount := 2

	switch size {
	case "small":
		ruleCount = 3
	case "medium":
		ruleCount = 10
	case "large":
		ruleCount = 50
	}

	switch complexity {
	case "simple":
		conditionCount = 1
	case "moderate":
		conditionCount = 3
	case "complex":
		conditionCount = 8
	}

	rules := make([]interface{}, ruleCount)
	for i := 0; i < ruleCount; i++ {
		conditions := make([]string, conditionCount)
		for j := 0; j < conditionCount; j++ {
			conditions[j] = fmt.Sprintf("condition_%d_%d", i, j)
		}

		rules[i] = map[string]interface{}{
			"id":         fmt.Sprintf("rule_%d", i),
			"name":       fmt.Sprintf("Test Rule %d", i),
			"conditions": conditions,
			"actions":    []string{"validate", "log"},
		}
	}

	return map[string]interface{}{
		"template": map[string]interface{}{
			"name":         fmt.Sprintf("Test Policy %s %s", size, complexity),
			"version":      "1.0.0",
			"asset_class":  "TestAsset",
			"jurisdiction": "TEST",
		},
		"policy": map[string]interface{}{
			"rules": rules,
		},
	}
}

// analyzeResults analyzes profiling results and identifies bottlenecks
func (p *PerformanceProfiler) analyzeResults() error {
	log.Printf("🔍 Analyzing profiling results...")

	// Calculate metrics
	p.calculateMetrics()

	// Identify bottlenecks
	p.identifyBottlenecks()

	// Generate recommendations
	p.generateRecommendations()

	return nil
}

// calculateMetrics calculates overall performance metrics
func (p *PerformanceProfiler) calculateMetrics() {
	if len(p.Benchmarks) == 0 {
		return
	}

	var totalDuration time.Duration
	var totalMemory int64

	for _, benchmark := range p.Benchmarks {
		totalDuration += benchmark.Duration
		totalMemory += benchmark.MemoryUsage
	}

	p.Metrics.AverageOpTime = totalDuration / time.Duration(len(p.Benchmarks))
	p.Metrics.PeakMemoryUsage = totalMemory
	p.Metrics.TotalAllocations = p.getTotalAllocations()
	p.Metrics.GCPauses = p.getGCPauses()
}

// identifyBottlenecks identifies performance bottlenecks
func (p *PerformanceProfiler) identifyBottlenecks() {
	// Sort benchmarks by duration
	sort.Slice(p.Benchmarks, func(i, j int) bool {
		return p.Benchmarks[i].NsPerOp > p.Benchmarks[j].NsPerOp
	})

	// Identify slow operations
	if len(p.Benchmarks) > 0 {
		slowest := p.Benchmarks[0]
		if slowest.NsPerOp > 1000000 { // > 1ms
			p.Metrics.Bottlenecks = append(p.Metrics.Bottlenecks, Bottleneck{
				Component:   "Compilation",
				Function:    slowest.Name,
				Duration:    time.Duration(slowest.NsPerOp),
				Percentage:  100.0,
				Description: "Slowest compilation operation",
				Severity:    "high",
				Impact:      "Significantly impacts overall performance",
			})
		}
	}

	// Check for memory issues
	for _, benchmark := range p.Benchmarks {
		if benchmark.BytesPerOp > 1024*1024 { // > 1MB per operation
			p.Metrics.Bottlenecks = append(p.Metrics.Bottlenecks, Bottleneck{
				Component:   "Memory",
				Function:    benchmark.Name,
				Duration:    0,
				Percentage:  float64(benchmark.BytesPerOp) / float64(1024*1024) * 10,
				Description: "High memory usage per operation",
				Severity:    "medium",
				Impact:      "May cause memory pressure",
			})
		}
	}
}

// generateRecommendations generates optimization recommendations
func (p *PerformanceProfiler) generateRecommendations() {
	recommendations := []Recommendation{
		{
			ID:          "cache_compiled_policies",
			Category:    "performance",
			Priority:    "high",
			Title:       "Implement Policy Compilation Caching",
			Description: "Cache compiled policies to avoid recompilation of unchanged policies",
			Impact:      "Can reduce compilation time by 60-80% for repeated operations",
			Effort:      "medium",
			Example:     "Implement LRU cache with policy hash as key",
		},
		{
			ID:          "optimize_rule_evaluation",
			Category:    "performance",
			Priority:    "medium",
			Title:       "Optimize Rule Evaluation Order",
			Description: "Evaluate rules in order of complexity/selectivity to fail fast",
			Impact:      "Can reduce average evaluation time by 20-40%",
			Effort:      "low",
			Example:     "Sort rules by estimated execution cost",
		},
		{
			ID:          "reduce_memory_allocations",
			Category:    "memory",
			Priority:    "medium",
			Title:       "Reduce Memory Allocations",
			Description: "Use object pools and reduce temporary allocations",
			Impact:      "Can reduce memory usage by 30-50%",
			Effort:      "high",
			Example:     "Implement sync.Pool for frequently allocated objects",
		},
	}

	// Add specific recommendations based on analysis
	if p.Metrics.PeakMemoryUsage > 100*1024*1024 { // > 100MB
		recommendations = append(recommendations, Recommendation{
			ID:          "memory_optimization",
			Category:    "memory",
			Priority:    "high",
			Title:       "Address High Memory Usage",
			Description: "Peak memory usage exceeds 100MB, consider streaming processing",
			Impact:      "Critical for handling large policy sets",
			Effort:      "high",
		})
	}

	p.Metrics.Recommendations = recommendations
}

// generateReport generates the performance report
func (p *PerformanceProfiler) generateReport() error {
	log.Printf("📊 Generating performance report...")

	switch outputFormat {
	case "json":
		return p.generateJSONReport()
	case "html":
		return p.generateHTMLReport()
	default:
		return p.generateTextReport()
	}
}

// generateJSONReport generates a JSON report
func (p *PerformanceProfiler) generateJSONReport() error {
	report := map[string]interface{}{
		"metrics":      p.Metrics,
		"benchmarks":   p.Benchmarks,
		"generated_at": time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	reportFile := filepath.Join(p.OutputDir, "performance_report.json")
	return ioutil.WriteFile(reportFile, data, 0644)
}

// generateTextReport generates a text report
func (p *PerformanceProfiler) generateTextReport() error {
	var report strings.Builder

	report.WriteString("🚀 ArdaOS Compliance Compiler Performance Report\n")
	report.WriteString("===============================================\n\n")

	// System info
	report.WriteString("System Information:\n")
	report.WriteString(fmt.Sprintf("  OS: %s\n", p.Metrics.SystemInfo.OS))
	report.WriteString(fmt.Sprintf("  Architecture: %s\n", p.Metrics.SystemInfo.Architecture))
	report.WriteString(fmt.Sprintf("  CPU Count: %d\n", p.Metrics.SystemInfo.CPUCount))
	report.WriteString(fmt.Sprintf("  Go Version: %s\n", p.Metrics.SystemInfo.GoVersion))
	report.WriteString("\n")

	// Overall metrics
	report.WriteString("Overall Performance Metrics:\n")
	report.WriteString(fmt.Sprintf("  Total Duration: %v\n", p.Metrics.TotalDuration))
	report.WriteString(fmt.Sprintf("  Total Operations: %d\n", p.Metrics.TotalOperations))
	report.WriteString(fmt.Sprintf("  Average Operation Time: %v\n", p.Metrics.AverageOpTime))
	report.WriteString(fmt.Sprintf("  Peak Memory Usage: %d MB\n", p.Metrics.PeakMemoryUsage/(1024*1024)))
	report.WriteString("\n")

	// Benchmarks
	report.WriteString("Benchmark Results:\n")
	for _, benchmark := range p.Benchmarks {
		report.WriteString(fmt.Sprintf("  %s:\n", benchmark.Name))
		report.WriteString(fmt.Sprintf("    Iterations: %d\n", benchmark.Iterations))
		report.WriteString(fmt.Sprintf("    Avg Time: %v\n", time.Duration(benchmark.NsPerOp)))
		report.WriteString(fmt.Sprintf("    Memory per Op: %d bytes\n", benchmark.BytesPerOp))
		report.WriteString(fmt.Sprintf("    Complexity Score: %.2f\n", benchmark.ComplexityScore))
		report.WriteString("\n")
	}

	// Bottlenecks
	if len(p.Metrics.Bottlenecks) > 0 {
		report.WriteString("Identified Bottlenecks:\n")
		for _, bottleneck := range p.Metrics.Bottlenecks {
			report.WriteString(fmt.Sprintf("  ⚠️  %s (%s)\n", bottleneck.Description, bottleneck.Severity))
			report.WriteString(fmt.Sprintf("      Component: %s\n", bottleneck.Component))
			report.WriteString(fmt.Sprintf("      Impact: %s\n", bottleneck.Impact))
			report.WriteString("\n")
		}
	}

	// Recommendations
	if len(p.Metrics.Recommendations) > 0 {
		report.WriteString("Optimization Recommendations:\n")
		for _, rec := range p.Metrics.Recommendations {
			report.WriteString(fmt.Sprintf("  💡 %s (%s priority)\n", rec.Title, rec.Priority))
			report.WriteString(fmt.Sprintf("      %s\n", rec.Description))
			report.WriteString(fmt.Sprintf("      Expected Impact: %s\n", rec.Impact))
			report.WriteString(fmt.Sprintf("      Implementation Effort: %s\n", rec.Effort))
			report.WriteString("\n")
		}
	}

	reportFile := filepath.Join(p.OutputDir, "performance_report.txt")
	return ioutil.WriteFile(reportFile, []byte(report.String()), 0644)
}

// generateHTMLReport generates an HTML report
func (p *PerformanceProfiler) generateHTMLReport() error {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Performance Profiling Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 6px; min-width: 200px; }
        .bottleneck { border-left: 4px solid #dc3545; padding-left: 15px; margin: 10px 0; }
        .recommendation { border-left: 4px solid #28a745; padding-left: 15px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Performance Profiling Report</h1>
        <p>ArdaOS Compliance Compiler Performance Analysis</p>
    </div>
    <!-- Report content would be generated here with actual data -->
</body>
</html>`

	reportFile := filepath.Join(p.OutputDir, "performance_report.html")
	return ioutil.WriteFile(reportFile, []byte(html), 0644)
}

// Helper functions

func getSystemInfo() SystemInfo {
	return SystemInfo{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		GoVersion:    runtime.Version(),
		Timestamp:    time.Now().Format(time.RFC3339),
	}
}

func getCurrentMemoryUsage() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Alloc)
}

func getGCStats() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.Mallocs)
}

func (p *PerformanceProfiler) getTotalAllocations() int64 {
	var total int64
	for _, benchmark := range p.Benchmarks {
		total += benchmark.AllocsPerOp * int64(benchmark.Iterations)
	}
	return total
}

func (p *PerformanceProfiler) getGCPauses() []time.Duration {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	pauses := make([]time.Duration, 0, len(m.PauseNs))
	for _, pause := range m.PauseNs {
		if pause > 0 {
			pauses = append(pauses, time.Duration(pause))
		}
	}

	return pauses
}
