// Development server with live reload for the compliance compiler.
// This tool provides a local development server with hot reloading capabilities
// for policy development and testing.
package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// DevServer provides live reload development server functionality
type DevServer struct {
	Port          int
	ProjectRoot   string
	TemplatesDir  string
	WatchDirs     []string
	AutoReload    bool
	DebugMode     bool
	clients       map[*websocket.Conn]bool
	clientsMux    sync.RWMutex
	watcher       *fsnotify.Watcher
	upgrader      websocket.Upgrader
	compiler      *CompilerService
	validator     *ValidatorService
	lastBuildTime time.Time
	buildErrors   []string
	buildWarnings []string
}

// CompilerService handles policy compilation
type CompilerService struct {
	BinaryPath   string
	TempDir      string
	OutputFormat string
}

// ValidatorService handles policy validation
type ValidatorService struct {
	BinaryPath     string
	StrictMode     bool
	FailOnWarnings bool
}

// FileInfo represents file information for the web interface
type FileInfo struct {
	Path        string     `json:"path"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Size        int64      `json:"size"`
	ModTime     time.Time  `json:"mod_time"`
	IsDirectory bool       `json:"is_directory"`
	Children    []FileInfo `json:"children,omitempty"`
}

// BuildResult represents compilation/validation results
type BuildResult struct {
	Success      bool      `json:"success"`
	Errors       []string  `json:"errors"`
	Warnings     []string  `json:"warnings"`
	BuildTime    time.Time `json:"build_time"`
	Duration     string    `json:"duration"`
	FilesChanged []string  `json:"files_changed"`
}

// PolicyInfo represents policy information
type PolicyInfo struct {
	Name                string                 `json:"name"`
	Version             string                 `json:"version"`
	AssetClass          string                 `json:"asset_class"`
	Jurisdiction        string                 `json:"jurisdiction"`
	RegulatoryFramework []string               `json:"regulatory_framework"`
	RuleCount           int                    `json:"rule_count"`
	ParameterCount      int                    `json:"parameter_count"`
	AttestationCount    int                    `json:"attestation_count"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// LiveReloadMessage represents a websocket message for live reload
type LiveReloadMessage struct {
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"`
}

var (
	devServerCmd = &cobra.Command{
		Use:   "dev-server",
		Short: "Start development server with live reload",
		Long: `Start a development server with live reload capabilities for policy development.

The development server provides:
- Live reload when policy files change
- Web-based policy editor and validator
- Real-time compilation feedback
- Template browser and documentation
- Debug information and logs`,
		Example: `  # Start development server on default port
  go run tools/dev-server.go

  # Start on custom port with debug mode
  go run tools/dev-server.go --port 8080 --debug

  # Watch additional directories
  go run tools/dev-server.go --watch-dir /custom/templates --watch-dir /custom/policies`,
		RunE: runDevServer,
	}

	port       int
	debugMode  bool
	watchDirs  []string
	autoReload bool
	bindAddr   string
)

func init() {
	devServerCmd.Flags().IntVarP(&port, "port", "p", 3000, "Port to run the development server on")
	devServerCmd.Flags().BoolVarP(&debugMode, "debug", "d", false, "Enable debug mode")
	devServerCmd.Flags().StringSliceVar(&watchDirs, "watch-dir", []string{}, "Additional directories to watch for changes")
	devServerCmd.Flags().BoolVar(&autoReload, "auto-reload", true, "Enable automatic reload on file changes")
	devServerCmd.Flags().StringVar(&bindAddr, "bind", "localhost", "Address to bind the server to")
}

func main() {
	if err := devServerCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runDevServer(cmd *cobra.Command, args []string) error {
	projectRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Initialize development server
	server := &DevServer{
		Port:         port,
		ProjectRoot:  projectRoot,
		TemplatesDir: filepath.Join(projectRoot, "examples", "templates"),
		WatchDirs:    append([]string{filepath.Join(projectRoot, "examples")}, watchDirs...),
		AutoReload:   autoReload,
		DebugMode:    debugMode,
		clients:      make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
		},
		compiler: &CompilerService{
			BinaryPath:   filepath.Join(projectRoot, "bin", "compliance-compiler"),
			TempDir:      filepath.Join(projectRoot, "tmp"),
			OutputFormat: "json",
		},
		validator: &ValidatorService{
			BinaryPath:     filepath.Join(projectRoot, "bin", "compliance-compiler"),
			StrictMode:     false,
			FailOnWarnings: false,
		},
	}

	// Ensure binary exists
	if _, err := os.Stat(server.compiler.BinaryPath); os.IsNotExist(err) {
		log.Printf("Warning: Compliance compiler binary not found at %s. Please run 'make build' first.", server.compiler.BinaryPath)
	}

	// Initialize file watcher
	if server.AutoReload {
		if err := server.initWatcher(); err != nil {
			return fmt.Errorf("failed to initialize file watcher: %w", err)
		}
		defer server.watcher.Close()
	}

	// Set up HTTP routes
	router := mux.NewRouter()
	server.setupRoutes(router)

	// Start WebSocket handler
	go server.handleWebSocketConnections()

	address := fmt.Sprintf("%s:%d", bindAddr, server.Port)
	log.Printf("🚀 Development server starting on http://%s", address)
	log.Printf("📁 Project root: %s", server.ProjectRoot)
	log.Printf("📝 Templates directory: %s", server.TemplatesDir)
	if server.AutoReload {
		log.Printf("👀 Watching directories: %v", server.WatchDirs)
	}
	log.Printf("🔧 Debug mode: %v", server.DebugMode)

	return http.ListenAndServe(address, router)
}

// initWatcher initializes the file system watcher
func (s *DevServer) initWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	s.watcher = watcher

	// Add watch directories
	for _, dir := range s.WatchDirs {
		if err := s.addWatchDir(dir); err != nil {
			log.Printf("Warning: Failed to watch directory %s: %v", dir, err)
		}
	}

	// Start watching for file changes
	go s.watchFiles()

	return nil
}

// addWatchDir recursively adds a directory to the watcher
func (s *DevServer) addWatchDir(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			// Skip hidden directories and common build directories
			if strings.HasPrefix(info.Name(), ".") ||
				info.Name() == "node_modules" ||
				info.Name() == "build" ||
				info.Name() == "dist" ||
				info.Name() == "tmp" {
				return filepath.SkipDir
			}

			if err := s.watcher.Add(path); err != nil {
				log.Printf("Warning: Failed to add watch for %s: %v", path, err)
			}
		}

		return nil
	})
}

// watchFiles handles file system events
func (s *DevServer) watchFiles() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			if s.shouldProcessEvent(event) {
				if s.DebugMode {
					log.Printf("File changed: %s (%s)", event.Name, event.Op)
				}

				// Debounce rapid file changes
				time.Sleep(100 * time.Millisecond)

				// Process the file change
				s.handleFileChange(event.Name)
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("File watcher error: %v", err)
		}
	}
}

// shouldProcessEvent determines if a file event should be processed
func (s *DevServer) shouldProcessEvent(event fsnotify.Event) bool {
	// Only process write and create events
	if event.Op&fsnotify.Write == 0 && event.Op&fsnotify.Create == 0 {
		return false
	}

	// Only process yaml, yml, and json files
	ext := strings.ToLower(filepath.Ext(event.Name))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

// handleFileChange processes a file change event
func (s *DevServer) handleFileChange(filePath string) {
	startTime := time.Now()

	// Validate/compile the changed file
	result := BuildResult{
		BuildTime:    startTime,
		FilesChanged: []string{filePath},
	}

	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		// Validate policy file
		errors, warnings := s.validateFile(filePath)
		result.Errors = errors
		result.Warnings = warnings
		result.Success = len(errors) == 0
	}

	result.Duration = time.Since(startTime).String()
	s.lastBuildTime = startTime
	s.buildErrors = result.Errors
	s.buildWarnings = result.Warnings

	// Broadcast to all connected clients
	s.broadcastToClients(LiveReloadMessage{
		Type:    "file-changed",
		Data:    result,
		Message: fmt.Sprintf("File %s changed", filepath.Base(filePath)),
	})

	if s.DebugMode {
		log.Printf("Processed file change: %s (success: %v, duration: %s)",
			filepath.Base(filePath), result.Success, result.Duration)
	}
}

// validateFile validates a policy file
func (s *DevServer) validateFile(filePath string) ([]string, []string) {
	// This would call the actual compliance compiler for validation
	// For now, we'll simulate validation

	var errors []string
	var warnings []string

	// Read and parse the file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to read file: %v", err))
		return errors, warnings
	}

	// Try to parse as YAML
	var policy map[string]interface{}
	if err := yaml.Unmarshal(data, &policy); err != nil {
		errors = append(errors, fmt.Sprintf("Invalid YAML: %v", err))
		return errors, warnings
	}

	// Basic validation checks
	if template, ok := policy["template"].(map[string]interface{}); ok {
		if name, ok := template["name"].(string); !ok || name == "" {
			errors = append(errors, "Template name is required")
		}
		if version, ok := template["version"].(string); !ok || version == "" {
			errors = append(errors, "Template version is required")
		}
	} else {
		errors = append(errors, "Template section is required")
	}

	if policySection, ok := policy["policy"].(map[string]interface{}); ok {
		if rules, ok := policySection["rules"].([]interface{}); ok {
			if len(rules) == 0 {
				warnings = append(warnings, "Policy has no rules defined")
			}
		} else {
			warnings = append(warnings, "No rules section found in policy")
		}
	} else {
		errors = append(errors, "Policy section is required")
	}

	return errors, warnings
}

// setupRoutes configures HTTP routes
func (s *DevServer) setupRoutes(router *mux.Router) {
	// Static files
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static/"))))

	// API routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/files", s.handleGetFiles).Methods("GET")
	api.HandleFunc("/files/{path:.*}", s.handleGetFile).Methods("GET")
	api.HandleFunc("/validate", s.handleValidate).Methods("POST")
	api.HandleFunc("/compile", s.handleCompile).Methods("POST")
	api.HandleFunc("/templates", s.handleGetTemplates).Methods("GET")
	api.HandleFunc("/status", s.handleGetStatus).Methods("GET")

	// WebSocket endpoint
	router.HandleFunc("/ws", s.handleWebSocket)

	// Main application
	router.PathPrefix("/").HandlerFunc(s.handleIndex)
}

// handleIndex serves the main development interface
func (s *DevServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArdaOS Compliance Compiler - Development Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .header {
            background: #2563eb;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .status {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .files {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .file-item {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
            cursor: pointer;
        }
        .file-item:hover {
            background: #f8f9fa;
        }
        .error {
            color: #dc2626;
            background: #fef2f2;
            padding: 10px;
            border-radius: 4px;
            margin: 5px 0;
        }
        .warning {
            color: #d97706;
            background: #fffbeb;
            padding: 10px;
            border-radius: 4px;
            margin: 5px 0;
        }
        .success {
            color: #059669;
            background: #ecfdf5;
            padding: 10px;
            border-radius: 4px;
            margin: 5px 0;
        }
        #console {
            background: #1f2937;
            color: #f3f4f6;
            padding: 15px;
            border-radius: 8px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 14px;
            max-height: 300px;
            overflow-y: auto;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 ArdaOS Compliance Compiler</h1>
        <p>Development Server - Live Reload Enabled</p>
    </div>

    <div class="status">
        <h2>📊 Server Status</h2>
        <div id="status-info">
            <p><strong>Port:</strong> {{.Port}}</p>
            <p><strong>Project Root:</strong> {{.ProjectRoot}}</p>
            <p><strong>Auto Reload:</strong> {{.AutoReload}}</p>
            <p><strong>Debug Mode:</strong> {{.DebugMode}}</p>
        </div>
        <div id="build-status"></div>
    </div>

    <div class="files">
        <h2>📁 Template Files</h2>
        <div id="file-list">Loading...</div>
    </div>

    <div id="console">
        <div>Development server console - waiting for changes...</div>
    </div>

    <script>
        // WebSocket connection for live reload
        const ws = new WebSocket('ws://localhost:{{.Port}}/ws');
        const console = document.getElementById('console');
        const buildStatus = document.getElementById('build-status');

        ws.onmessage = function(event) {
            const message = JSON.parse(event.data);
            handleMessage(message);
        };

        function handleMessage(message) {
            const timestamp = new Date().toLocaleTimeString();

            switch(message.type) {
                case 'file-changed':
                    const result = message.data;
                    let statusClass = result.success ? 'success' : 'error';
                    let statusText = result.success ? '✅ Valid' : '❌ Invalid';

                    buildStatus.innerHTML = '<div class="' + statusClass + '">' + statusText + '</div>';

                    if (result.errors && result.errors.length > 0) {
                        result.errors.forEach(error => {
                            buildStatus.innerHTML += '<div class="error">Error: ' + error + '</div>';
                        });
                    }

                    if (result.warnings && result.warnings.length > 0) {
                        result.warnings.forEach(warning => {
                            buildStatus.innerHTML += '<div class="warning">Warning: ' + warning + '</div>';
                        });
                    }

                    appendToConsole('[' + timestamp + '] ' + message.message + ' (Duration: ' + result.duration + ')');
                    break;

                case 'reload':
                    location.reload();
                    break;

                default:
                    appendToConsole('[' + timestamp + '] ' + message.message);
            }
        }

        function appendToConsole(text) {
            const div = document.createElement('div');
            div.textContent = text;
            console.appendChild(div);
            console.scrollTop = console.scrollHeight;
        }

        // Load file list
        fetch('/api/files')
            .then(response => response.json())
            .then(files => {
                displayFiles(files);
            })
            .catch(error => {
                document.getElementById('file-list').innerHTML = 'Error loading files: ' + error;
            });

        function displayFiles(files) {
            const fileList = document.getElementById('file-list');
            fileList.innerHTML = '';

            files.forEach(file => {
                if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
                    const div = document.createElement('div');
                    div.className = 'file-item';
                    div.textContent = file.path;
                    div.onclick = () => openFile(file.path);
                    fileList.appendChild(div);
                }
            });
        }

        function openFile(path) {
            // This would open a file editor interface
            alert('Opening file: ' + path + '\n\n(File editor interface would be implemented here)');
        }
    </script>
</body>
</html>`

	tmpl, err := template.New("index").Parse(html)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Port        int
		ProjectRoot string
		AutoReload  bool
		DebugMode   bool
	}{
		Port:        s.Port,
		ProjectRoot: s.ProjectRoot,
		AutoReload:  s.AutoReload,
		DebugMode:   s.DebugMode,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleWebSocket handles WebSocket connections
func (s *DevServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	s.clientsMux.Lock()
	s.clients[conn] = true
	s.clientsMux.Unlock()

	if s.DebugMode {
		log.Printf("WebSocket client connected. Total clients: %d", len(s.clients))
	}

	// Send initial status
	s.sendToClient(conn, LiveReloadMessage{
		Type:    "connected",
		Message: "Connected to development server",
	})

	// Keep connection alive and handle disconnect
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			s.clientsMux.Lock()
			delete(s.clients, conn)
			s.clientsMux.Unlock()

			if s.DebugMode {
				log.Printf("WebSocket client disconnected. Total clients: %d", len(s.clients))
			}
			break
		}
	}
}

// handleWebSocketConnections manages WebSocket connections
func (s *DevServer) handleWebSocketConnections() {
	// This method can be used for periodic tasks or connection management
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if s.DebugMode && len(s.clients) > 0 {
			log.Printf("WebSocket health check. Active clients: %d", len(s.clients))
		}
	}
}

// broadcastToClients sends a message to all connected WebSocket clients
func (s *DevServer) broadcastToClients(message LiveReloadMessage) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()

	for conn := range s.clients {
		s.sendToClient(conn, message)
	}
}

// sendToClient sends a message to a specific WebSocket client
func (s *DevServer) sendToClient(conn *websocket.Conn, message LiveReloadMessage) {
	if err := conn.WriteJSON(message); err != nil {
		log.Printf("WebSocket write error: %v", err)
		// Remove problematic connection
		s.clientsMux.Lock()
		delete(s.clients, conn)
		s.clientsMux.Unlock()
		conn.Close()
	}
}

// API Handlers

// handleGetFiles returns the list of files in the project
func (s *DevServer) handleGetFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.getFileList(s.TemplatesDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// handleGetFile returns information about a specific file
func (s *DevServer) handleGetFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	filePath := vars["path"]

	fullPath := filepath.Join(s.ProjectRoot, filePath)
	info, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	fileInfo := FileInfo{
		Path:        filePath,
		Name:        info.Name(),
		Size:        info.Size(),
		ModTime:     info.ModTime(),
		IsDirectory: info.IsDir(),
	}

	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		fileInfo.Type = "policy"

		// Parse policy information
		if policyInfo, err := s.parsePolicyInfo(fullPath); err == nil {
			fileInfo.Type = "policy"
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"file_info":   fileInfo,
				"policy_info": policyInfo,
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileInfo)
}

// handleValidate validates a policy file
func (s *DevServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Content string `json:"content"`
		Path    string `json:"path,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Write content to temporary file
	tempFile := filepath.Join(s.compiler.TempDir, "temp_policy.yaml")
	if err := os.MkdirAll(s.compiler.TempDir, 0755); err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	if err := ioutil.WriteFile(tempFile, []byte(request.Content), 0644); err != nil {
		http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile)

	// Validate the file
	errors, warnings := s.validateFile(tempFile)

	result := BuildResult{
		Success:   len(errors) == 0,
		Errors:    errors,
		Warnings:  warnings,
		BuildTime: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleCompile compiles a policy file
func (s *DevServer) handleCompile(w http.ResponseWriter, r *http.Request) {
	// Similar to handleValidate but calls the compiler
	// Implementation would call the actual compliance compiler binary

	result := BuildResult{
		Success:   true,
		Errors:    []string{},
		Warnings:  []string{},
		BuildTime: time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleGetTemplates returns available policy templates
func (s *DevServer) handleGetTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.getTemplateList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(templates)
}

// handleGetStatus returns server status information
func (s *DevServer) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"port":              s.Port,
		"project_root":      s.ProjectRoot,
		"auto_reload":       s.AutoReload,
		"debug_mode":        s.DebugMode,
		"connected_clients": len(s.clients),
		"last_build_time":   s.lastBuildTime,
		"build_errors":      s.buildErrors,
		"build_warnings":    s.buildWarnings,
		"uptime":            time.Since(s.lastBuildTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// Helper methods

// getFileList returns a list of files in the specified directory
func (s *DevServer) getFileList(dir string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		relPath, _ := filepath.Rel(s.ProjectRoot, path)

		files = append(files, FileInfo{
			Path:        relPath,
			Name:        info.Name(),
			Size:        info.Size(),
			ModTime:     info.ModTime(),
			IsDirectory: info.IsDir(),
		})

		return nil
	})

	return files, err
}

// parsePolicyInfo extracts policy information from a YAML file
func (s *DevServer) parsePolicyInfo(filePath string) (*PolicyInfo, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var policy struct {
		Template struct {
			Name                string   `yaml:"name"`
			Version             string   `yaml:"version"`
			AssetClass          string   `yaml:"asset_class"`
			Jurisdiction        string   `yaml:"jurisdiction"`
			RegulatoryFramework []string `yaml:"regulatory_framework"`
		} `yaml:"template"`
		Parameters map[string]interface{} `yaml:"parameters"`
		Policy     struct {
			Rules        []interface{} `yaml:"rules"`
			Attestations []interface{} `yaml:"attestations"`
		} `yaml:"policy"`
	}

	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	info := &PolicyInfo{
		Name:                policy.Template.Name,
		Version:             policy.Template.Version,
		AssetClass:          policy.Template.AssetClass,
		Jurisdiction:        policy.Template.Jurisdiction,
		RegulatoryFramework: policy.Template.RegulatoryFramework,
		RuleCount:           len(policy.Policy.Rules),
		ParameterCount:      len(policy.Parameters),
		AttestationCount:    len(policy.Policy.Attestations),
		Metadata:            make(map[string]interface{}),
	}

	return info, nil
}

// getTemplateList returns a list of available templates
func (s *DevServer) getTemplateList() ([]PolicyInfo, error) {
	var templates []PolicyInfo

	err := filepath.Walk(s.TemplatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			if policyInfo, err := s.parsePolicyInfo(path); err == nil {
				templates = append(templates, *policyInfo)
			}
		}

		return nil
	})

	return templates, err
}
