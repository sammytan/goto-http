package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

//go:embed templates/*
var templates embed.FS

//go:embed static/*
var staticFiles embed.FS

// Server Web服务器
type Server struct {
	mu       sync.RWMutex
	router   *mux.Router
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
	stats    chan interface{}
}

// NewServer 创建新的Web服务器
func NewServer() *Server {
	s := &Server{
		router:  mux.NewRouter(),
		clients: make(map[*websocket.Conn]bool),
		stats:   make(chan interface{}, 100),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
	}

	s.setupRoutes()
	return s
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 静态文件
	s.router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticFiles)))

	// 页面路由
	s.router.HandleFunc("/", s.handleHome)
	s.router.HandleFunc("/dashboard", s.handleDashboard)
	s.router.HandleFunc("/attacks", s.handleAttacks)
	s.router.HandleFunc("/proxies", s.handleProxies)

	// API路由
	api := s.router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/stats", s.handleStats)
	api.HandleFunc("/ws", s.handleWebSocket)
	api.HandleFunc("/attacks", s.handleAttackAPI).Methods("POST", "GET")
	api.HandleFunc("/attacks/{id}", s.handleAttackControl).Methods("PUT", "DELETE")
}

// Start 启动服务器
func (s *Server) Start(addr string) error {
	go s.broadcastStats()
	return http.ListenAndServe(addr, s.router)
}

// handleHome 处理首页
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templates, "templates/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// handleDashboard 处理仪表盘页面
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templates, "templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// handleAttacks 处理攻击列表页面
func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templates, "templates/attacks.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// handleProxies 处理代理列表页面
func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templates, "templates/proxies.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// handleStats 处理统计数据API
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		// 这里添加更多统计数据
	}
	json.NewEncoder(w).Encode(stats)
}

// handleWebSocket 处理WebSocket连接
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
	}()

	// 保持连接活跃
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// handleAttackAPI 处理攻击相关API
func (s *Server) handleAttackAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// 获取攻击列表
		attacks := []map[string]interface{}{
			// 这里添加攻击列表数据
		}
		json.NewEncoder(w).Encode(attacks)
	case "POST":
		// 创建新的攻击
		var attack map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&attack); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// 处理攻击创建逻辑
		json.NewEncoder(w).Encode(attack)
	}
}

// handleAttackControl 处理攻击控制API
func (s *Server) handleAttackControl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id := vars["id"]

	switch r.Method {
	case "PUT":
		// 更新攻击状态
		var update map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// 处理攻击更新逻辑
		json.NewEncoder(w).Encode(update)
	case "DELETE":
		// 停止攻击
		response := map[string]string{"status": "stopped", "id": id}
		json.NewEncoder(w).Encode(response)
	}
}

// UpdateStats 更新统计数据
func (s *Server) UpdateStats(stats interface{}) {
	s.stats <- stats
}

// broadcastStats 广播统计数据
func (s *Server) broadcastStats() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case stats := <-s.stats:
			s.mu.RLock()
			for client := range s.clients {
				err := client.WriteJSON(stats)
				if err != nil {
					client.Close()
					delete(s.clients, client)
				}
			}
			s.mu.RUnlock()
		case <-ticker.C:
			// 定期发送心跳
			s.mu.RLock()
			for client := range s.clients {
				err := client.WriteMessage(websocket.PingMessage, nil)
				if err != nil {
					client.Close()
					delete(s.clients, client)
				}
			}
			s.mu.RUnlock()
		}
	}
}
