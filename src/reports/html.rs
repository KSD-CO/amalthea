use chrono::{DateTime, Utc};

pub struct HtmlReportGenerator {
    pub title: String,
    pub test_results: Vec<TestResult>,
    pub security_results: Vec<SecurityResult>,
    pub generated_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
}

#[derive(Clone)]
pub struct TestResult {
    pub endpoint: String,
    pub method: String,
    pub status: TestStatus,
    pub response_time: Option<u64>,
    pub expected_status: u16,
    pub actual_status: Option<u16>,
    pub description: String,
}

#[derive(Clone)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone)]
pub struct SecurityResult {
    pub vulnerability_type: String,
    pub endpoint: String,
    pub severity: SecuritySeverity,
    pub details: String,
    pub recommendation: String,
}

#[derive(Clone, Debug)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl HtmlReportGenerator {
    pub fn new(title: String, provider: String, model: String) -> Self {
        Self {
            title,
            test_results: Vec::new(),
            security_results: Vec::new(),
            generated_at: Utc::now(),
            provider,
            model,
        }
    }

    pub fn add_test_result(&mut self, result: TestResult) {
        self.test_results.push(result);
    }

    pub fn add_security_result(&mut self, result: SecurityResult) {
        self.security_results.push(result);
    }

    pub fn generate_html(&self) -> String {
        let stats = self.calculate_stats();
        
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Amalthea API Test Report - {}</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .vulnerability-critical {{ border-left-color: #dc2626; }}
        .vulnerability-high {{ border-left-color: #ea580c; }}
        .vulnerability-medium {{ border-left-color: #ca8a04; }}
        .vulnerability-low {{ border-left-color: #2563eb; }}
        .test-passed {{ color: #059669; }}
        .test-failed {{ color: #dc2626; }}
        .test-skipped {{ color: #6b7280; }}
    </style>
</head>
<body class="bg-gray-50">
    <!-- Header -->
    <header class="bg-blue-600 text-white p-6">
        <div class="flex items-center justify-between">
            <div class="flex items-center">
                <img src="https://amalthea.cloud/amalthea.png" alt="Amalthea" class="w-12 h-12 mr-4" onerror="this.style.display='none'">
                <h1 class="text-3xl font-bold">{}</h1>
            </div>
            <div class="text-right">
                <p class="text-sm">Generated: {}</p>
                <p class="text-sm">Provider: {} ({})</p>
            </div>
        </div>
    </header>

    <!-- Executive Summary -->
    <section class="p-6 grid grid-cols-1 md:grid-cols-4 gap-6">
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Total Tests</h3>
            <p class="text-4xl font-bold text-blue-600">{}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Success Rate</h3>
            <p class="text-4xl font-bold text-green-600">{:.1}%</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Security Issues</h3>
            <p class="text-4xl font-bold text-red-600">{}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold text-gray-600">Avg Response</h3>
            <p class="text-4xl font-bold text-purple-600">{}ms</p>
        </div>
    </section>

    <!-- Charts Section -->
    <section class="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-xl font-semibold mb-4">Test Results Distribution</h3>
            <canvas id="testResultsChart" width="400" height="200"></canvas>
        </div>
        
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-xl font-semibold mb-4">Security Risk Assessment</h3>
            <canvas id="securityChart" width="400" height="200"></canvas>
        </div>
    </section>

    {}

    {}

    <!-- JavaScript for Charts -->
    <script>
        // Test Results Chart
        const testCtx = document.getElementById('testResultsChart').getContext('2d');
        new Chart(testCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Passed', 'Failed', 'Skipped'],
                datasets: [{{
                    data: [{}, {}, {}],
                    backgroundColor: ['#10b981', '#ef4444', '#6b7280']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});

        // Security Chart
        const secCtx = document.getElementById('securityChart').getContext('2d');
        new Chart(secCtx, {{
            type: 'bar',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    label: 'Security Issues',
                    data: [{}, {}, {}, {}],
                    backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#2563eb']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});
    </script>

    <footer class="bg-gray-800 text-white p-6 mt-12">
        <div class="text-center">
            <p class="text-sm">Generated by <a href="https://amalthea.cloud" class="text-blue-400 hover:underline">Amalthea v0.2.3</a></p>
            <p class="text-xs text-gray-400 mt-2">Built with ❤️ by KSD.CO using Rust 🦀</p>
        </div>
    </footer>
</body>
</html>"#,
            self.title,
            self.title,
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.provider,
            self.model,
            stats.total_tests,
            stats.success_rate,
            stats.total_security_issues,
            stats.avg_response_time,
            self.generate_security_section(),
            self.generate_test_results_section(),
            stats.passed_count,
            stats.failed_count,
            stats.skipped_count,
            stats.critical_count,
            stats.high_count,
            stats.medium_count,
            stats.low_count,
        )
    }

    fn generate_security_section(&self) -> String {
        if self.security_results.is_empty() {
            return String::new();
        }

        let mut section = String::from(r#"
    <!-- Security Assessment -->
    <section class="p-6">
        <h2 class="text-2xl font-bold mb-6 text-red-600">🛡️ Security Assessment</h2>
        <div class="space-y-4">"#);

        for result in &self.security_results {
            let (severity_class, severity_color) = match result.severity {
                SecuritySeverity::Critical => ("vulnerability-critical", "red"),
                SecuritySeverity::High => ("vulnerability-high", "orange"),
                SecuritySeverity::Medium => ("vulnerability-medium", "yellow"),
                SecuritySeverity::Low => ("vulnerability-low", "blue"),
            };

            section.push_str(&format!(
                r#"
            <div class="bg-white rounded-lg shadow p-6 border-l-4 {}">
                <div class="flex justify-between items-start">
                    <div>
                        <h4 class="text-lg font-semibold text-{}-700">🔍 {}</h4>
                        <p class="text-gray-600">Endpoint: {}</p>
                    </div>
                    <span class="bg-{}-100 text-{}-800 px-3 py-1 rounded-full text-sm font-medium">{:?}</span>
                </div>
                <div class="mt-4">
                    <p class="text-gray-700"><strong>Details:</strong> {}</p>
                    <p class="text-gray-700"><strong>Recommendation:</strong> {}</p>
                </div>
            </div>"#,
                severity_class,
                severity_color,
                result.vulnerability_type,
                result.endpoint,
                severity_color,
                severity_color,
                result.severity,
                result.details,
                result.recommendation
            ));
        }

        section.push_str("        </div>\n    </section>");
        section
    }

    fn generate_test_results_section(&self) -> String {
        let mut section = String::from(r#"
    <!-- Test Results -->
    <section class="p-6">
        <h2 class="text-2xl font-bold mb-6">📋 Test Results</h2>
        <div class="bg-white rounded-lg shadow overflow-hidden">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Endpoint</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Method</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Expected</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actual</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Response Time</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">"#);

        for result in &self.test_results {
            let (status_text, status_class) = match result.status {
                TestStatus::Passed => ("✅ PASSED", "text-green-600"),
                TestStatus::Failed => ("❌ FAILED", "text-red-600"),
                TestStatus::Skipped => ("⏭️ SKIPPED", "text-yellow-600"),
            };

            let response_time = result.response_time
                .map(|rt| format!("{}ms", rt))
                .unwrap_or_else(|| "-".to_string());

            let expected_status = format!("{}", result.expected_status);
            let actual_status = result.actual_status
                .map(|status| {
                    if matches!(result.status, TestStatus::Passed) {
                        format!("<span class='text-green-600'>{}</span>", status)
                    } else if matches!(result.status, TestStatus::Failed) {
                        format!("<span class='text-red-600'>{}</span>", status)
                    } else {
                        format!("{}", status)
                    }
                })
                .unwrap_or_else(|| "<span class='text-gray-400'>-</span>".to_string());

            section.push_str(&format!(
                r#"
                    <tr class="hover:bg-gray-50">
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{}</td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">{}</span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium {}">{}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <span class="px-2 py-1 text-xs font-medium rounded bg-gray-100">{}</span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm">{}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{}</td>
                        <td class="px-6 py-4 text-sm text-gray-500 max-w-xs truncate">{}</td>
                    </tr>"#,
                result.endpoint,
                result.method,
                status_class,
                status_text,
                expected_status,
                actual_status,
                response_time,
                result.description
            ));
        }

        section.push_str("                </tbody>\n            </table>\n        </div>\n    </section>");
        section
    }

    fn calculate_stats(&self) -> ReportStats {
        let total_tests = self.test_results.len();
        let passed_count = self.test_results.iter().filter(|r| matches!(r.status, TestStatus::Passed)).count();
        let failed_count = self.test_results.iter().filter(|r| matches!(r.status, TestStatus::Failed)).count();
        let skipped_count = self.test_results.iter().filter(|r| matches!(r.status, TestStatus::Skipped)).count();
        
        let success_rate = if total_tests > 0 {
            (passed_count as f64 / total_tests as f64) * 100.0
        } else {
            0.0
        };

        let avg_response_time = {
            let times: Vec<u64> = self.test_results.iter()
                .filter_map(|r| r.response_time)
                .collect();
            if times.is_empty() {
                0
            } else {
                times.iter().sum::<u64>() / times.len() as u64
            }
        };

        let critical_count = self.security_results.iter().filter(|r| matches!(r.severity, SecuritySeverity::Critical)).count();
        let high_count = self.security_results.iter().filter(|r| matches!(r.severity, SecuritySeverity::High)).count();
        let medium_count = self.security_results.iter().filter(|r| matches!(r.severity, SecuritySeverity::Medium)).count();
        let low_count = self.security_results.iter().filter(|r| matches!(r.severity, SecuritySeverity::Low)).count();

        ReportStats {
            total_tests,
            passed_count,
            failed_count,
            skipped_count,
            success_rate,
            avg_response_time,
            total_security_issues: self.security_results.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
        }
    }
}

struct ReportStats {
    total_tests: usize,
    passed_count: usize,
    failed_count: usize,
    skipped_count: usize,
    success_rate: f64,
    avg_response_time: u64,
    total_security_issues: usize,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
}
