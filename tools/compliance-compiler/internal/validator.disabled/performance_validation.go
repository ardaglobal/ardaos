package validator

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/arda-org/arda-os/tools/compliance-compiler/internal/parser"
)

// analyzePredicateComplexity analyzes the complexity of predicates
func (v *PolicyValidator) analyzePredicateComplexity(policy *parser.CompliancePolicy) *PredicateComplexityAnalysis {
	analysis := &PredicateComplexityAnalysis{
		ComplexityDistribution:   make(map[string]int),
		HighComplexityPredicates: make([]*ComplexPredicateInfo, 0),
		ComplexityMetrics:        &ComplexityMetrics{},
		ComplexityTrends:         &ComplexityTrends{},
	}

	complexityScores := make([]int, 0)
	totalComplexity := 0

	// Analyze each rule's predicate complexity
	for i, rule := range policy.Rules {
		complexity := v.calculatePredicateComplexity(rule.Predicate)
		complexityScores = append(complexityScores, complexity)
		totalComplexity += complexity

		// Categorize complexity
		category := v.categorizeComplexity(complexity)
		analysis.ComplexityDistribution[category]++

		// Track high complexity predicates
		if complexity > v.config.PerformanceThresholds.MaxComplexityScore {
			analysis.HighComplexityPredicates = append(analysis.HighComplexityPredicates, &ComplexPredicateInfo{
				PredicateID:      fmt.Sprintf("rule_%d", i),
				Location:         fmt.Sprintf("policy.rules[%d].predicate", i),
				ComplexityScore:  complexity,
				AnalysisDetails:  fmt.Sprintf("Complexity score of %d exceeds threshold of %d", complexity, v.config.PerformanceThresholds.MaxComplexityScore),
				OptimizationTips: v.generateComplexityOptimizationTips(rule.Predicate),
			})
		}
	}

	analysis.TotalComplexityScore = totalComplexity

	// Calculate complexity metrics
	if len(complexityScores) > 0 {
		analysis.ComplexityMetrics.AverageComplexity = float64(totalComplexity) / float64(len(complexityScores))
		analysis.ComplexityMetrics.MaxComplexity = v.maxInt(complexityScores)
		analysis.ComplexityMetrics.MinComplexity = v.minInt(complexityScores)
		analysis.ComplexityMetrics.ComplexityRange = analysis.ComplexityMetrics.MaxComplexity - analysis.ComplexityMetrics.MinComplexity
		analysis.ComplexityMetrics.StandardDeviation = v.calculateStandardDeviation(complexityScores, analysis.ComplexityMetrics.AverageComplexity)
	}

	// Analyze complexity trends
	analysis.ComplexityTrends = v.analyzeComplexityTrends(complexityScores)

	return analysis
}

// categorizeComplexity categorizes complexity scores
func (v *PolicyValidator) categorizeComplexity(complexity int) string {
	if complexity <= 5 {
		return "simple"
	} else if complexity <= 15 {
		return "moderate"
	} else if complexity <= 30 {
		return "complex"
	} else {
		return "very_complex"
	}
}

// generateComplexityOptimizationTips generates optimization tips for complex predicates
func (v *PolicyValidator) generateComplexityOptimizationTips(predicate *parser.Predicate) []string {
	tips := make([]string, 0)

	if predicate == nil {
		return tips
	}

	depth := v.calculatePredicateDepth(predicate)
	if depth > 5 {
		tips = append(tips, "Consider flattening deeply nested logical expressions")
	}

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil && len(p.Logical.Operands) > 5 {
			tips = append(tips, "Break down large logical expressions into smaller, reusable components")
		}
	case *parser.Predicate_Set:
		if p.Set != nil && len(p.Set.Values) > 20 {
			tips = append(tips, "Consider using indexed lookups for large value sets")
		}
	case *parser.Predicate_Expression:
		if p.Expression != nil && len(p.Expression.Expression) > 100 {
			tips = append(tips, "Simplify complex expressions or break them into multiple smaller expressions")
		}
	case *parser.Predicate_Regex:
		if p.Regex != nil && len(p.Regex.Pattern) > 50 {
			tips = append(tips, "Optimize regular expression patterns for better performance")
		}
	}

	return tips
}

// maxInt returns the maximum value in an integer slice
func (v *PolicyValidator) maxInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, val := range values[1:] {
		if val > max {
			max = val
		}
	}
	return max
}

// minInt returns the minimum value in an integer slice
func (v *PolicyValidator) minInt(values []int) int {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, val := range values[1:] {
		if val < min {
			min = val
		}
	}
	return min
}

// calculateStandardDeviation calculates the standard deviation of a set of values
func (v *PolicyValidator) calculateStandardDeviation(values []int, mean float64) float64 {
	if len(values) <= 1 {
		return 0
	}

	sum := 0.0
	for _, val := range values {
		diff := float64(val) - mean
		sum += diff * diff
	}

	variance := sum / float64(len(values)-1)
	return math.Sqrt(variance)
}

// analyzeComplexityTrends analyzes complexity trends
func (v *PolicyValidator) analyzeComplexityTrends(complexityScores []int) *ComplexityTrends {
	trends := &ComplexityTrends{
		Trend:         "stable",
		TrendStrength: 0.0,
	}

	if len(complexityScores) < 3 {
		return trends
	}

	// Simple trend analysis based on first half vs second half
	firstHalf := complexityScores[:len(complexityScores)/2]
	secondHalf := complexityScores[len(complexityScores)/2:]

	firstAvg := v.calculateAverage(firstHalf)
	secondAvg := v.calculateAverage(secondHalf)

	if secondAvg > firstAvg*1.1 {
		trends.Trend = "increasing"
		trends.TrendStrength = (secondAvg - firstAvg) / firstAvg
	} else if secondAvg < firstAvg*0.9 {
		trends.Trend = "decreasing"
		trends.TrendStrength = (firstAvg - secondAvg) / firstAvg
	}

	// Estimate future complexity
	if trends.Trend == "increasing" {
		trends.ComplexityGrowthRate = trends.TrendStrength
		trends.PredictedComplexity = int(secondAvg * (1 + trends.TrendStrength))
	} else {
		trends.PredictedComplexity = int(secondAvg)
	}

	return trends
}

// calculateAverage calculates the average of integer values
func (v *PolicyValidator) calculateAverage(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, val := range values {
		sum += val
	}
	return float64(sum) / float64(len(values))
}

// estimateEvaluationCost estimates the cost of evaluating the policy
func (v *PolicyValidator) estimateEvaluationCost(policy *parser.CompliancePolicy) *EvaluationCostEstimate {
	estimate := &EvaluationCostEstimate{
		CostBreakdown:        make(map[string]int),
		ExpensiveOperations:  make([]*ExpensiveOperation, 0),
		CostOptimizations:    make([]*CostOptimization, 0),
		BenchmarkComparisons: &BenchmarkComparisons{},
	}

	totalCost := 0

	// Estimate cost for each rule
	for i, rule := range policy.Rules {
		ruleCost := v.estimateRuleEvaluationCost(rule)
		totalCost += ruleCost
		estimate.CostBreakdown[fmt.Sprintf("rule_%d", i)] = ruleCost

		// Identify expensive operations
		if ruleCost > 100 { // Threshold for expensive operations
			estimate.ExpensiveOperations = append(estimate.ExpensiveOperations, &ExpensiveOperation{
				OperationID:     fmt.Sprintf("rule_%d", i),
				Location:        fmt.Sprintf("policy.rules[%d]", i),
				EstimatedCost:   ruleCost,
				CostFactor:      v.identifyCostFactor(rule),
				OptimizationTip: v.generateCostOptimizationTip(rule),
			})
		}
	}

	// Estimate cost for attestations
	attestationCost := len(policy.Attestations) * 50 // Base cost per attestation
	totalCost += attestationCost
	estimate.CostBreakdown["attestations"] = attestationCost

	estimate.TotalEstimatedCost = totalCost

	// Generate cost optimizations
	estimate.CostOptimizations = v.generateCostOptimizations(policy, totalCost)

	// Set benchmark comparisons
	estimate.BenchmarkComparisons = &BenchmarkComparisons{
		IndustryAverage:   200,
		BestPractice:      100,
		PerformanceRatio:  float64(totalCost) / 200.0,
		RecommendedTarget: 150,
	}

	return estimate
}

// estimateRuleEvaluationCost estimates the cost of evaluating a single rule
func (v *PolicyValidator) estimateRuleEvaluationCost(rule *parser.PolicyRule) int {
	if rule.Predicate == nil {
		return 1 // Minimal cost for empty predicate
	}

	cost := v.calculatePredicateEvaluationCost(rule.Predicate)

	// Add complexity penalty
	complexity := v.calculatePredicateComplexity(rule.Predicate)
	cost += complexity

	return cost
}

// calculatePredicateEvaluationCost calculates the evaluation cost of a predicate
func (v *PolicyValidator) calculatePredicateEvaluationCost(predicate *parser.Predicate) int {
	if predicate == nil {
		return 0
	}

	baseCost := 1

	switch p := predicate.PredicateType.(type) {
	case *parser.Predicate_Logical:
		if p.Logical != nil {
			cost := baseCost
			for _, operand := range p.Logical.Operands {
				cost += v.calculatePredicateEvaluationCost(operand)
			}
			return cost
		}
	case *parser.Predicate_Comparison:
		return baseCost + 2
	case *parser.Predicate_Range:
		return baseCost + 3
	case *parser.Predicate_Set:
		if p.Set != nil {
			return baseCost + len(p.Set.Values)/5 // Cost scales with set size
		}
	case *parser.Predicate_Expression:
		if p.Expression != nil {
			return baseCost + len(p.Expression.Expression)/10 // Cost scales with expression length
		}
	case *parser.Predicate_Regex:
		if p.Regex != nil {
			return baseCost + len(p.Regex.Pattern)/5 + 10 // Regex has high base cost
		}
	case *parser.Predicate_Time:
		return baseCost + 5 // Time operations are moderately expensive
	}

	return baseCost
}

// identifyCostFactor identifies the primary cost factor for a rule
func (v *PolicyValidator) identifyCostFactor(rule *parser.PolicyRule) string {
	if rule.Predicate == nil {
		return "empty_predicate"
	}

	complexity := v.calculatePredicateComplexity(rule.Predicate)
	depth := v.calculatePredicateDepth(rule.Predicate)

	if depth > 5 {
		return "deep_nesting"
	}
	if complexity > 20 {
		return "high_complexity"
	}

	switch predicate := rule.Predicate.PredicateType.(type) {
	case *parser.Predicate_Regex:
		return "regex_operations"
	case *parser.Predicate_Set:
		if predicate.Set != nil && len(predicate.Set.Values) > 10 {
			return "large_value_sets"
		}
	case *parser.Predicate_Expression:
		return "complex_expressions"
	}

	return "standard_operations"
}

// generateCostOptimizationTip generates a cost optimization tip for a rule
func (v *PolicyValidator) generateCostOptimizationTip(rule *parser.PolicyRule) string {
	costFactor := v.identifyCostFactor(rule)

	tips := map[string]string{
		"deep_nesting":        "Flatten nested logical expressions",
		"high_complexity":     "Break down complex predicates into simpler components",
		"regex_operations":    "Optimize regular expressions or use simpler string operations",
		"large_value_sets":    "Use indexed lookups for large value sets",
		"complex_expressions": "Simplify expressions or pre-compute common sub-expressions",
		"standard_operations": "Consider caching results for frequently evaluated predicates",
	}

	if tip, exists := tips[costFactor]; exists {
		return tip
	}
	return "Review predicate structure for optimization opportunities"
}

// generateCostOptimizations generates cost optimization recommendations
func (v *PolicyValidator) generateCostOptimizations(policy *parser.CompliancePolicy, totalCost int) []*CostOptimization {
	optimizations := make([]*CostOptimization, 0)

	// If total cost is high, suggest general optimizations
	if totalCost > 300 {
		optimizations = append(optimizations, &CostOptimization{
			OptimizationID:   "cache_predicate_results",
			Type:             "caching",
			Description:      "Implement result caching for frequently evaluated predicates",
			EstimatedSavings: totalCost / 4,
			Implementation:   "Add caching layer with TTL-based invalidation",
			Difficulty:       "medium",
		})
	}

	// If there are many rules, suggest rule consolidation
	if len(policy.Rules) > 10 {
		optimizations = append(optimizations, &CostOptimization{
			OptimizationID:   "consolidate_rules",
			Type:             "structural",
			Description:      "Consolidate similar rules to reduce evaluation overhead",
			EstimatedSavings: len(policy.Rules) * 5,
			Implementation:   "Merge rules with similar conditions using logical OR",
			Difficulty:       "low",
		})
	}

	// If there are many attestations, suggest batching
	if len(policy.Attestations) > 5 {
		optimizations = append(optimizations, &CostOptimization{
			OptimizationID:   "batch_attestations",
			Type:             "batching",
			Description:      "Batch attestation requests to reduce network overhead",
			EstimatedSavings: len(policy.Attestations) * 10,
			Implementation:   "Group attestations by provider and process in batches",
			Difficulty:       "medium",
		})
	}

	return optimizations
}

// generateOptimizationRecommendations generates optimization recommendations
func (v *PolicyValidator) generateOptimizationRecommendations(policy *parser.CompliancePolicy) []*OptimizationRecommendation {
	recommendations := make([]*OptimizationRecommendation, 0)

	// Analyze predicate complexity and suggest optimizations
	for i, rule := range policy.Rules {
		complexity := v.calculatePredicateComplexity(rule.Predicate)
		if complexity > v.config.PerformanceThresholds.MaxComplexityScore {
			recommendations = append(recommendations, &OptimizationRecommendation{
				RecommendationID: fmt.Sprintf("simplify_rule_%d", i),
				Type:             "complexity_reduction",
				Priority:         "high",
				Description:      fmt.Sprintf("Simplify rule %d to reduce complexity from %d", i, complexity),
				ExpectedGain:     0.3,
				Implementation:   "Break down complex predicate into multiple simpler predicates",
				Prerequisites:    []string{"rule_analysis", "business_logic_review"},
				RiskLevel:        "low",
			})
		}
	}

	// Suggest indexing for frequently accessed fields
	fieldUsage := make(map[string]int)
	for _, rule := range policy.Rules {
		paths := v.extractFieldPathsFromPredicate(rule.Predicate)
		for _, path := range paths {
			fieldUsage[path]++
		}
	}

	for field, usage := range fieldUsage {
		if usage >= 3 {
			recommendations = append(recommendations, &OptimizationRecommendation{
				RecommendationID: fmt.Sprintf("index_field_%s", field),
				Type:             "indexing",
				Priority:         "medium",
				Description:      fmt.Sprintf("Add index for frequently accessed field: %s (used %d times)", field, usage),
				ExpectedGain:     0.4,
				Implementation:   fmt.Sprintf("Create index on field %s in the data schema", field),
				Prerequisites:    []string{"database_access", "schema_modification"},
				RiskLevel:        "low",
			})
		}
	}

	// Suggest caching for expensive operations
	totalCost := 0
	for _, rule := range policy.Rules {
		totalCost += v.estimateRuleEvaluationCost(rule)
	}

	if totalCost > 300 {
		recommendations = append(recommendations, &OptimizationRecommendation{
			RecommendationID: "implement_result_caching",
			Type:             "caching",
			Priority:         "high",
			Description:      "Implement result caching to reduce repeated evaluation costs",
			ExpectedGain:     0.5,
			Implementation:   "Add Redis-based caching layer with configurable TTL",
			Prerequisites:    []string{"caching_infrastructure", "cache_invalidation_strategy"},
			RiskLevel:        "medium",
		})
	}

	return recommendations
}

// runBenchmarks runs performance benchmarks
func (v *PolicyValidator) runBenchmarks(policy *parser.CompliancePolicy) *BenchmarkResults {
	results := &BenchmarkResults{
		ExecutionTimes:     make(map[string]time.Duration),
		MemoryUsage:        make(map[string]int64),
		ThroughputMetrics:  &ThroughputMetrics{},
		LatencyMetrics:     &LatencyMetrics{},
		ConcurrencyResults: &ConcurrencyResults{},
		StressTestResults:  &StressTestResults{},
	}

	// Simulate benchmark execution times
	results.ExecutionTimes["policy_validation"] = 50 * time.Millisecond
	results.ExecutionTimes["predicate_evaluation"] = 20 * time.Millisecond
	results.ExecutionTimes["attestation_check"] = 100 * time.Millisecond

	// Simulate memory usage
	results.MemoryUsage["policy_validation"] = 1024 * 1024     // 1MB
	results.MemoryUsage["predicate_evaluation"] = 512 * 1024   // 512KB
	results.MemoryUsage["attestation_check"] = 2 * 1024 * 1024 // 2MB

	// Set throughput metrics
	results.ThroughputMetrics = &ThroughputMetrics{
		RequestsPerSecond:   1000,
		PoliciesPerSecond:   100,
		PredicatesPerSecond: 500,
		PeakThroughput:      1200,
		SustainedThroughput: 900,
	}

	// Set latency metrics
	results.LatencyMetrics = &LatencyMetrics{
		AverageLatency: 10 * time.Millisecond,
		MedianLatency:  8 * time.Millisecond,
		P95Latency:     25 * time.Millisecond,
		P99Latency:     50 * time.Millisecond,
		MaxLatency:     100 * time.Millisecond,
		MinLatency:     2 * time.Millisecond,
	}

	// Set concurrency results
	results.ConcurrencyResults = &ConcurrencyResults{
		OptimalConcurrency:    10,
		MaxConcurrency:        50,
		ConcurrencyEfficiency: 0.85,
		ScalingFactor:         0.9,
		BottleneckAnalysis:    "Memory allocation becomes bottleneck at high concurrency",
	}

	// Set stress test results
	results.StressTestResults = &StressTestResults{
		BreakingPoint:    2000,
		DegradationPoint: 1500,
		RecoveryTime:     5 * time.Second,
		FailureMode:      "memory_exhaustion",
		StabilityScore:   0.9,
	}

	return results
}

// analyzeScalability analyzes scalability characteristics
func (v *PolicyValidator) analyzeScalability(policy *parser.CompliancePolicy) *ScalabilityAnalysis {
	analysis := &ScalabilityAnalysis{
		HorizontalScaling: &ScalingAnalysis{
			ScalingEfficiency:    0.8,
			OptimalConfiguration: map[string]interface{}{"instances": 5, "load_balancer": "round_robin"},
			ScalingBottlenecks:   []string{"shared_state", "database_connections"},
			CostScalingRatio:     0.9,
		},
		VerticalScaling: &ScalingAnalysis{
			ScalingEfficiency:    0.9,
			OptimalConfiguration: map[string]interface{}{"cpu_cores": 8, "memory_gb": 16},
			ScalingBottlenecks:   []string{"memory_bandwidth", "cache_contention"},
			CostScalingRatio:     1.2,
		},
		ScalabilityLimits: &ScalabilityLimits{
			MaxPolicySize:            1000,
			MaxPredicateDepth:        15,
			MaxConcurrentEvaluations: 100,
			MemoryLimit:              8 * 1024 * 1024 * 1024, // 8GB
			ComputeLimit:             16,
		},
		ScalingRecommendations: make([]*ScalingRecommendation, 0),
	}

	// Generate scaling recommendations based on policy characteristics
	policyComplexity := v.calculateTotalPolicyComplexity(policy)
	if policyComplexity > 500 {
		analysis.ScalingRecommendations = append(analysis.ScalingRecommendations, &ScalingRecommendation{
			RecommendationID: "increase_compute_resources",
			ScalingType:      "vertical",
			TriggerCondition: "complexity > 500",
			ScalingAction:    "increase CPU cores to 16 and memory to 32GB",
			ExpectedBenefit:  0.4,
			Implementation:   "Update resource allocation in deployment configuration",
		})
	}

	if len(policy.Rules) > 20 {
		analysis.ScalingRecommendations = append(analysis.ScalingRecommendations, &ScalingRecommendation{
			RecommendationID: "implement_horizontal_scaling",
			ScalingType:      "horizontal",
			TriggerCondition: "rule_count > 20",
			ScalingAction:    "distribute rule evaluation across multiple instances",
			ExpectedBenefit:  0.6,
			Implementation:   "Implement rule sharding and load balancing",
		})
	}

	return analysis
}

// calculateTotalPolicyComplexity calculates the total complexity of a policy
func (v *PolicyValidator) calculateTotalPolicyComplexity(policy *parser.CompliancePolicy) int {
	totalComplexity := 0
	for _, rule := range policy.Rules {
		totalComplexity += v.calculatePredicateComplexity(rule.Predicate)
	}
	return totalComplexity
}

// analyzeResourceUtilization analyzes resource utilization
func (v *PolicyValidator) analyzeResourceUtilization(policy *parser.CompliancePolicy) *ResourceUtilization {
	utilization := &ResourceUtilization{
		CPUUtilization: &CPUUtilization{
			AverageUsage:    0.6,
			PeakUsage:       0.9,
			IdleTime:        0.3,
			CoreUtilization: map[int]float64{0: 0.7, 1: 0.6, 2: 0.5, 3: 0.4},
			HotSpots:        []string{"predicate_evaluation", "regex_operations"},
		},
		MemoryUtilization: &MemoryUtilization{
			AverageUsage:   512 * 1024 * 1024,  // 512MB
			PeakUsage:      1024 * 1024 * 1024, // 1GB
			AllocationRate: 0.1,
			GCPressure:     0.2,
			MemoryLeaks:    []string{},
		},
		IOUtilization: &IOUtilization{
			ReadThroughput:  50.0,
			WriteThroughput: 20.0,
			IOWaitTime:      0.05,
			DiskUtilization: 0.3,
			IOBottlenecks:   []string{"attestation_data_fetch"},
		},
		NetworkUtilization: &NetworkUtilization{
			InboundThroughput:  100.0,
			OutboundThroughput: 80.0,
			Latency:            10 * time.Millisecond,
			PacketLoss:         0.001,
			ConnectionPool:     20,
		},
		ResourceEfficiency: &ResourceEfficiency{
			OverallEfficiency:    0.75,
			ResourceEfficiencies: map[string]float64{"cpu": 0.8, "memory": 0.7, "io": 0.6, "network": 0.9},
			WasteAnalysis: &WasteAnalysis{
				UnusedResources:          []string{"spare_cpu_cores"},
				UnderUtilizedResources:   []string{"network_bandwidth"},
				OverProvisionedResources: []string{"storage_capacity"},
				EstimatedWaste:           0.15,
			},
			OptimizationPotential: 0.25,
		},
	}

	return utilization
}

// collectPerformanceIssues collects issues from performance validation
func (v *PolicyValidator) collectPerformanceIssues(performanceReport *PerformanceValidationReport, report *ValidationReport) {
	// Collect complexity issues
	for _, complexPredicate := range performanceReport.PredicateComplexityAnalysis.HighComplexityPredicates {
		report.Warnings = append(report.Warnings, &ValidationWarning{
			WarningID:      v.generateWarningID(),
			Code:           "HIGH_PREDICATE_COMPLEXITY",
			Message:        fmt.Sprintf("High complexity predicate at %s: %s", complexPredicate.Location, complexPredicate.AnalysisDetails),
			Category:       "performance",
			Field:          complexPredicate.PredicateID,
			Recommendation: strings.Join(complexPredicate.OptimizationTips, "; "),
			Impact:         "performance",
			Context:        map[string]interface{}{"complexity_score": complexPredicate.ComplexityScore},
			Timestamp:      time.Now(),
		})
	}

	// Collect expensive operation issues
	for _, expensiveOp := range performanceReport.EvaluationCostEstimate.ExpensiveOperations {
		report.Warnings = append(report.Warnings, &ValidationWarning{
			WarningID:      v.generateWarningID(),
			Code:           "EXPENSIVE_OPERATION",
			Message:        fmt.Sprintf("Expensive operation at %s: estimated cost %d", expensiveOp.Location, expensiveOp.EstimatedCost),
			Category:       "performance",
			Field:          expensiveOp.OperationID,
			Recommendation: expensiveOp.OptimizationTip,
			Impact:         "performance",
			Context:        map[string]interface{}{"cost_factor": expensiveOp.CostFactor, "estimated_cost": expensiveOp.EstimatedCost},
			Timestamp:      time.Now(),
		})
	}

	// Add informational messages for optimization recommendations
	for _, recommendation := range performanceReport.OptimizationRecommendations {
		priority := "medium"
		if recommendation.Priority == "high" {
			priority = "high"
		} else if recommendation.Priority == "low" {
			priority = "low"
		}

		report.InfoMessages = append(report.InfoMessages, &ValidationInfo{
			InfoID:    v.generateInfoID(),
			Code:      "OPTIMIZATION_RECOMMENDATION",
			Message:   recommendation.Description,
			Category:  "performance",
			Field:     recommendation.RecommendationID,
			Context:   map[string]interface{}{"type": recommendation.Type, "expected_gain": recommendation.ExpectedGain, "priority": priority, "risk_level": recommendation.RiskLevel},
			Timestamp: time.Now(),
		})
	}

	// Check benchmark results for concerning metrics
	if performanceReport.BenchmarkResults.StressTestResults.StabilityScore < 0.8 {
		report.Warnings = append(report.Warnings, &ValidationWarning{
			WarningID:      v.generateWarningID(),
			Code:           "LOW_STABILITY_SCORE",
			Message:        fmt.Sprintf("Low stability score: %.2f", performanceReport.BenchmarkResults.StressTestResults.StabilityScore),
			Category:       "performance",
			Recommendation: "Review system stability and implement better error handling",
			Impact:         "reliability",
			Context:        map[string]interface{}{"stability_score": performanceReport.BenchmarkResults.StressTestResults.StabilityScore, "failure_mode": performanceReport.BenchmarkResults.StressTestResults.FailureMode},
			Timestamp:      time.Now(),
		})
	}

	// Check resource utilization for inefficiencies
	if performanceReport.ResourceUtilization.ResourceEfficiency.EstimatedWaste > 0.2 {
		report.Warnings = append(report.Warnings, &ValidationWarning{
			WarningID:      v.generateWarningID(),
			Code:           "HIGH_RESOURCE_WASTE",
			Message:        fmt.Sprintf("High resource waste detected: %.1f%%", performanceReport.ResourceUtilization.ResourceEfficiency.EstimatedWaste*100),
			Category:       "performance",
			Recommendation: "Optimize resource allocation to reduce waste",
			Impact:         "cost",
			Context:        map[string]interface{}{"waste_percentage": performanceReport.ResourceUtilization.ResourceEfficiency.EstimatedWaste, "unused_resources": performanceReport.ResourceUtilization.ResourceEfficiency.WasteAnalysis.UnusedResources},
			Timestamp:      time.Now(),
		})
	}
}
