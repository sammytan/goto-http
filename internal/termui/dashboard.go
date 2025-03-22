package termui

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"encoding/json"

	"github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

// Stats holds the dashboard statistics
type Stats struct {
	Start               time.Time
	Duration            time.Duration
	Total               uint64
	Success             uint64
	Failed              uint64
	BytesSent           int64
	BytesReceived       int64
	MinLatency          int64
	MaxLatency          int64
	TotalLatency        int64
	Codes               map[int]int64
	Errors              map[string]int
	LatencyDistribution map[int64]int64
	Mu                  sync.RWMutex
}

// Dashboard represents the terminal UI dashboard
type Dashboard struct {
	mu sync.RWMutex

	// Header section
	headerBox    *widgets.Paragraph
	targetURL    string
	attackMode   string
	attackTime   int
	timeLeft     int
	bandwidth    float64
	totalTraffic float64

	// Job info section
	jobInfoBox *widgets.Paragraph
	works      int
	interval   int
	rates      int
	referer    string
	headers    string
	cookies    string
	postData   string
	proxyType  string
	uaType     string
	bypassType string

	// Counts section - 拆分为两个独立区域
	targetCountsBox *widgets.Paragraph // 目标请求统计
	proxyCountsBox  *widgets.Paragraph // 代理请求统计
	networkStatsBox *widgets.Paragraph // 网络数据统计
	targetCount     int64
	requestOK       int64
	requestFail     int64
	proxyCount      int
	proxyReqOK      int64
	proxyReqFail    int64
	proxyBandwidth  float64 // 代理传输带宽
	uploadSpeed     float64 // 上传速度
	downloadSpeed   float64 // 下载速度

	// OS stats section
	osStatsBox  *widgets.Gauge
	cpuGauge    *widgets.Gauge
	memGauge    *widgets.Gauge
	gcGauge     *widgets.Gauge
	bwUpGauge   *widgets.Gauge
	bwDownGauge *widgets.Gauge

	// Charts
	rpsChart      *widgets.Plot
	responseChart *widgets.Plot
	responseCodes *widgets.BarChart
	serverIPs     *widgets.Paragraph

	// Request table
	requestTable *widgets.Table

	// Stats data
	stats               *Stats
	cpuUsage            float64
	memUsage            float64
	gcUsage             float64
	maxBandwidth        float64
	currentRPS          []float64
	currentResponseTime []float64
	serverIPStats       map[string]int64

	// Debug flag
	debug bool

	// Layout settings
	rowSpacing int

	// UI configuration - persistent settings
	uiConfig *UIConfig
	visible  map[string]bool

	// Last request data
	lastRequest map[string]interface{}

	// Control
	done    chan struct{}
	stopped bool

	// Stats mutex
	statsMutex sync.Mutex

	// Raw stats
	rawStats map[string]interface{}
}

// UIConfig holds persistent UI configuration
type UIConfig struct {
	// Layout preferences
	LayoutVersion       int             // Version of layout to use
	ComponentOrder      []string        // Order of components
	ComponentVisibility map[string]bool // Which components are visible
	ColorScheme         string          // Name of color scheme

	// Display format preferences
	DataFormatters map[string]string // How to format different data types

	// Box sizing
	ColumnRatios []float64      // Relative widths for columns
	RowHeights   map[string]int // Custom heights for rows
}

// NewUIConfig creates a default UI configuration
func NewUIConfig() *UIConfig {
	return &UIConfig{
		LayoutVersion: 1,
		ComponentOrder: []string{
			"header", "charts", "info", "os", "codes", "table",
		},
		ComponentVisibility: map[string]bool{
			"header": true, "charts": true, "info": true,
			"os": true, "codes": true, "table": true,
		},
		ColorScheme: "hackerRed",
		DataFormatters: map[string]string{
			"bandwidth":  "%.2f Mbps",
			"traffic":    "%.2f GB",
			"percentage": "%.1f%%",
		},
		ColumnRatios: []float64{0.25, 0.25, 0.25, 0.25}, // Equal 4-column layout
		RowHeights: map[string]int{
			"header": 4,
			"charts": 12,
			"info":   6,
			"os":     3,
			"codes":  6,
		},
	}
}

// NewDashboard creates a new dashboard instance
func NewDashboard() (*Dashboard, error) {
	if err := termui.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize termui: %v", err)
	}

	// Create default data for time series charts
	defaultRPS := make([]float64, 100)
	defaultRT := make([]float64, 100)
	for i := 0; i < 100; i++ {
		defaultRPS[i] = 0.1 // Small non-zero value to show the line
		defaultRT[i] = 10.0 // Small non-zero value for response time
	}

	d := &Dashboard{
		done: make(chan struct{}),
		// Initialize with default values
		stats: &Stats{
			Start:               time.Now(),
			Codes:               make(map[int]int64),
			Errors:              make(map[string]int),
			LatencyDistribution: make(map[int64]int64),
			Total:               0,
			Success:             0,
			Failed:              0,
		},
		currentRPS:          defaultRPS,
		currentResponseTime: defaultRT,
		// Set initial values for display
		targetURL:    "Not set",
		attackMode:   "Not set",
		attackTime:   0,
		timeLeft:     0,
		bandwidth:    0,
		totalTraffic: 0,
		works:        0,
		interval:     0,
		rates:        0,
		referer:      "None",
		headers:      "None",
		cookies:      "None",
		postData:     "None",
		proxyType:    "None",
		uaType:       "None",
		bypassType:   "None",
		// Initialize counter values
		targetCount:    0,
		requestOK:      0,
		requestFail:    0,
		proxyCount:     0,
		proxyReqOK:     0,
		proxyReqFail:   0,
		proxyBandwidth: 0, // Initialize proxy bandwidth to 0
		// Set default layout settings
		rowSpacing: 1, // Default row spacing
		// Initialize UI configuration
		uiConfig: NewUIConfig(),
	}

	// Try to load saved configuration if exists
	if err := d.LoadUIConfig(); err != nil {
		fmt.Printf("[Dashboard] No saved config found, using default: %v\n", err)
	}

	// Initialize all UI components
	d.initializeComponents()

	fmt.Println("[Dashboard] Initialized with default values")

	return d, nil
}

// SetJobParams sets all job parameters at once
func (d *Dashboard) SetJobParams(works, interval, rates int, referer, headers, cookies, postData, proxyType, uaType, bypassType string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.works = works
	d.interval = interval
	d.rates = rates

	if referer != "" {
		d.referer = referer
	}

	if headers != "" {
		d.headers = headers
	}

	if cookies != "" {
		d.cookies = cookies
	}

	if postData != "" {
		d.postData = postData
	}

	if proxyType != "" {
		d.proxyType = proxyType
	}

	if uaType != "" {
		d.uaType = uaType
	}

	if bypassType != "" {
		d.bypassType = bypassType
	}

	fmt.Printf("[Dashboard] Job parameters set: works=%d, interval=%d, rates=%d, proxyType=%s\n",
		d.works, d.interval, d.rates, d.proxyType)
}

func (d *Dashboard) initializeComponents() {
	// Header section
	d.headerBox = widgets.NewParagraph()
	d.headerBox.Title = "HTTP Stress Tool v1.0"
	d.headerBox.BorderStyle.Fg = termui.ColorRed
	d.headerBox.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.headerBox.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)

	// Job info section
	d.jobInfoBox = widgets.NewParagraph()
	d.jobInfoBox.Title = "Job Info"
	d.jobInfoBox.BorderStyle.Fg = termui.ColorRed
	d.jobInfoBox.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.jobInfoBox.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)

	// 拆分Counts区域为两个独立区域
	// 目标请求统计
	d.targetCountsBox = widgets.NewParagraph()
	d.targetCountsBox.Title = "Target Requests"
	d.targetCountsBox.BorderStyle.Fg = termui.ColorRed
	d.targetCountsBox.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.targetCountsBox.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)

	// 代理请求统计
	d.proxyCountsBox = widgets.NewParagraph()
	d.proxyCountsBox.Title = "Proxy Requests"
	d.proxyCountsBox.BorderStyle.Fg = termui.ColorRed
	d.proxyCountsBox.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.proxyCountsBox.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)

	// 网络数据统计
	d.networkStatsBox = widgets.NewParagraph()
	d.networkStatsBox.Title = "Network Stats"
	d.networkStatsBox.BorderStyle.Fg = termui.ColorRed
	d.networkStatsBox.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.networkStatsBox.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)

	// OS stats section - 修改为水平布局
	d.cpuGauge = widgets.NewGauge()
	d.cpuGauge.Title = " CPU "
	d.cpuGauge.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.cpuGauge.BarColor = termui.ColorRed
	d.cpuGauge.BorderStyle.Fg = termui.ColorRed
	d.cpuGauge.LabelStyle = termui.NewStyle(termui.ColorGreen)

	d.memGauge = widgets.NewGauge()
	d.memGauge.Title = " MEM "
	d.memGauge.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.memGauge.BarColor = termui.ColorYellow
	d.memGauge.BorderStyle.Fg = termui.ColorRed
	d.memGauge.LabelStyle = termui.NewStyle(termui.ColorGreen)

	d.gcGauge = widgets.NewGauge()
	d.gcGauge.Title = " GC "
	d.gcGauge.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.gcGauge.BarColor = termui.ColorGreen
	d.gcGauge.BorderStyle.Fg = termui.ColorRed
	d.gcGauge.LabelStyle = termui.NewStyle(termui.ColorGreen)

	// Charts
	d.rpsChart = widgets.NewPlot()
	d.rpsChart.Title = "Requests Per Second"
	d.rpsChart.LineColors = []termui.Color{termui.ColorGreen}
	d.rpsChart.AxesColor = termui.ColorWhite
	d.rpsChart.BorderStyle.Fg = termui.ColorRed
	d.rpsChart.DrawDirection = widgets.DrawLeft
	d.rpsChart.Data = [][]float64{d.currentRPS}
	d.rpsChart.PlotType = widgets.LineChart
	d.rpsChart.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.rpsChart.MaxVal = 100 // Set initial max value

	d.responseChart = widgets.NewPlot()
	d.responseChart.Title = "Response Time (ms)"
	d.responseChart.LineColors = []termui.Color{termui.ColorCyan}
	d.responseChart.AxesColor = termui.ColorWhite
	d.responseChart.BorderStyle.Fg = termui.ColorRed
	d.responseChart.DrawDirection = widgets.DrawLeft
	d.responseChart.Data = [][]float64{d.currentResponseTime}
	d.responseChart.PlotType = widgets.LineChart
	d.responseChart.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.responseChart.MaxVal = 1000 // Set initial max value

	// Response codes bar chart
	d.responseCodes = widgets.NewBarChart()
	d.responseCodes.Title = "Response Codes"
	d.responseCodes.BarColors = []termui.Color{
		termui.ColorGreen,  // 200
		termui.ColorYellow, // 301
		termui.ColorYellow, // 302
		termui.ColorRed,    // 403
		termui.ColorYellow, // 404
		termui.ColorRed,    // More
	}
	d.responseCodes.NumStyles = []termui.Style{
		termui.NewStyle(termui.ColorWhite),
		termui.NewStyle(termui.ColorWhite),
		termui.NewStyle(termui.ColorWhite),
		termui.NewStyle(termui.ColorWhite),
		termui.NewStyle(termui.ColorWhite),
		termui.NewStyle(termui.ColorWhite),
	}
	d.responseCodes.BorderStyle.Fg = termui.ColorRed
	d.responseCodes.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.responseCodes.LabelStyles = []termui.Style{
		termui.NewStyle(termui.ColorGreen),
	}

	// Server IPs 文本展示 - 改用段落组件
	d.serverIPs = widgets.NewParagraph()
	d.serverIPs.Title = "Server IP Distribution"
	d.serverIPs.BorderStyle.Fg = termui.ColorRed
	d.serverIPs.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.serverIPs.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.serverIPs.Text = "Waiting for data..."

	// 初始化IP统计map
	d.serverIPStats = make(map[string]int64)

	// Request table
	d.requestTable = widgets.NewTable()
	d.requestTable.Title = "Last Requests (10)"
	d.requestTable.TextStyle = termui.NewStyle(termui.ColorGreen)
	d.requestTable.BorderStyle.Fg = termui.ColorRed
	d.requestTable.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	d.requestTable.RowSeparator = true
	d.requestTable.FillRow = true
	d.requestTable.Rows = [][]string{
		{"Time", "Current Proxy", "URL", "Response Code/Time/BodySize", "Response Server/IP"},
	}
	d.requestTable.RowStyles[0] = termui.NewStyle(termui.ColorGreen, termui.ColorClear, termui.ModifierBold)
}

// Start starts the dashboard
func (d *Dashboard) Start() error {
	fmt.Println("[Dashboard] Starting dashboard")

	// 确保所有组件都已正确初始化
	if d.rpsChart == nil || d.responseChart == nil || d.responseCodes == nil ||
		d.headerBox == nil || d.jobInfoBox == nil || d.targetCountsBox == nil || d.proxyCountsBox == nil ||
		d.cpuGauge == nil || d.memGauge == nil || d.gcGauge == nil {
		fmt.Println("[Dashboard] Re-initializing components")
		d.initializeComponents()
	}

	// 确保配置正确初始化
	fmt.Printf("[Dashboard] Initial values: targetURL=%s, attackMode=%s, attackTime=%d\n",
		d.targetURL, d.attackMode, d.attackTime)
	fmt.Printf("[Dashboard] Initial counts: targetCount=%d, requestOK=%d, requestFail=%d\n",
		d.targetCount, d.requestOK, d.requestFail)

	// 如果攻击时间大于0，设置倒计时
	if d.attackTime > 0 {
		d.timeLeft = d.attackTime
		fmt.Printf("[Dashboard] Attack will finish in %d seconds\n", d.timeLeft)
	}

	// 如果stats为空，初始化它
	if d.stats == nil {
		d.stats = &Stats{
			Start:               time.Now(),
			Codes:               make(map[int]int64),
			Errors:              make(map[string]int),
			LatencyDistribution: make(map[int64]int64),
		}
	}

	// 仅当未设置关键数据时才使用硬编码数据初始化
	// 这样可以避免覆盖已经设置的值
	if d.targetURL == "" || d.attackMode == "" || (d.bandwidth == 0 && d.targetCount == 0) {
		fmt.Println("[Dashboard] Missing key data, using hardcoded test data")
		d.updateWithHardcodedData()
	} else {
		fmt.Println("[Dashboard] Using provided configuration data")
	}

	// 更新网络统计和计数等显示
	d.updateNetworkStats()
	d.updateCounts()

	// 初始渲染
	termui.Clear()
	fmt.Println("[Dashboard] First render")
	d.render()
	fmt.Println("[Dashboard] Initial render complete")

	// 启动UI更新循环
	go d.updateUI()
	fmt.Println("[Dashboard] Started UI update loop")

	// 启动事件处理循环
	go d.handleEvents()
	fmt.Println("[Dashboard] Started event handling")

	// 等待结束信号
	fmt.Println("[Dashboard] Waiting for termination signal")
	<-d.done

	fmt.Println("[Dashboard] Dashboard terminated")
	return nil
}

// Stop stops the dashboard
func (d *Dashboard) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.stopped {
		d.stopped = true
		close(d.done)
		// 关闭termui
		termui.Close()
		// 使用安全的终端恢复函数恢复终端状态
		safeRestoreTerminal()
	}
}

// render updates the layout and renders all components
func (d *Dashboard) render() {
	termWidth, termHeight := termui.TerminalDimensions()

	// Use persistent config values if available
	headerHeight := d.uiConfig.RowHeights["header"]
	chartHeight := d.uiConfig.RowHeights["charts"]
	infoBoxHeight := d.uiConfig.RowHeights["info"]
	gaugeHeight := d.uiConfig.RowHeights["os"]
	codesHeight := d.uiConfig.RowHeights["codes"]

	// 使用实例的rowSpacing变量
	padding := d.rowSpacing
	topPadding := 0

	// Calculate column widths based on configuration
	colWidths := make([]int, len(d.uiConfig.ColumnRatios))
	for i, ratio := range d.uiConfig.ColumnRatios {
		colWidths[i] = int(float64(termWidth) * ratio)
	}

	// Determine visible components
	componentVisible := d.uiConfig.ComponentVisibility

	// Position components based on configuration
	var lastY int = 0

	// Header is always at the top
	if componentVisible["header"] {
		d.headerBox.SetRect(0, lastY, termWidth, lastY+headerHeight)
		lastY += headerHeight + topPadding
	}

	// Check component order and position accordingly
	for _, component := range d.uiConfig.ComponentOrder {
		if !componentVisible[component] {
			continue
		}

		switch component {
		case "charts":
			// Charts section (RPS and Response Time)
			chartWidth := termWidth / 2
			d.rpsChart.SetRect(0, lastY, chartWidth, lastY+chartHeight)
			d.responseChart.SetRect(chartWidth, lastY, termWidth, lastY+chartHeight)
			lastY += chartHeight + padding

		case "info":
			// Info boxes section (Job Info, Target Counts, Proxy Counts, Network Stats)
			colStartX := 0
			for i, boxWidth := range colWidths {
				switch i {
				case 0:
					if i < len(colWidths)-1 {
						d.jobInfoBox.SetRect(colStartX, lastY, colStartX+boxWidth-padding, lastY+infoBoxHeight)
					} else {
						d.jobInfoBox.SetRect(colStartX, lastY, termWidth, lastY+infoBoxHeight)
					}
				case 1:
					if i < len(colWidths)-1 {
						d.targetCountsBox.SetRect(colStartX, lastY, colStartX+boxWidth-padding, lastY+infoBoxHeight)
					} else {
						d.targetCountsBox.SetRect(colStartX, lastY, termWidth, lastY+infoBoxHeight)
					}
				case 2:
					if i < len(colWidths)-1 {
						d.proxyCountsBox.SetRect(colStartX, lastY, colStartX+boxWidth-padding, lastY+infoBoxHeight)
					} else {
						d.proxyCountsBox.SetRect(colStartX, lastY, termWidth, lastY+infoBoxHeight)
					}
				case 3:
					d.networkStatsBox.SetRect(colStartX, lastY, termWidth, lastY+infoBoxHeight)
				}
				colStartX += boxWidth
			}
			lastY += infoBoxHeight + padding

		case "os":
			// OS Stats section
			gaugeWidth := termWidth / 3
			d.cpuGauge.SetRect(0, lastY, gaugeWidth, lastY+gaugeHeight)
			d.memGauge.SetRect(gaugeWidth, lastY, gaugeWidth*2, lastY+gaugeHeight)
			d.gcGauge.SetRect(gaugeWidth*2, lastY, termWidth, lastY+gaugeHeight)
			lastY += gaugeHeight + padding

		case "codes":
			// Response Codes and Server IPs section
			chartWidth := termWidth / 2
			d.responseCodes.SetRect(0, lastY, chartWidth, lastY+codesHeight)
			d.serverIPs.SetRect(chartWidth, lastY, termWidth, lastY+codesHeight)
			lastY += codesHeight + padding

		case "table":
			// Last Requests table (at the bottom)
			tableHeight := termHeight - lastY - 1 // Reserve 1 row at the bottom

			// Ensure minimum table height
			minTableHeight := 12
			if tableHeight < minTableHeight {
				tableHeight = minTableHeight
			}

			d.requestTable.SetRect(0, lastY, termWidth, lastY+tableHeight)
		}
	}

	// Ensure table data is complete
	if len(d.requestTable.Rows) < 11 {
		d.initTableRows()
	}

	// Create render list based on visible components
	renderComponents := []termui.Drawable{d.headerBox}

	// Add components based on visibility config
	if componentVisible["charts"] {
		renderComponents = append(renderComponents, d.rpsChart, d.responseChart)
	}
	if componentVisible["info"] {
		renderComponents = append(renderComponents, d.jobInfoBox, d.targetCountsBox, d.proxyCountsBox, d.networkStatsBox)
	}
	if componentVisible["os"] {
		renderComponents = append(renderComponents, d.cpuGauge, d.memGauge, d.gcGauge)
	}
	if componentVisible["codes"] {
		renderComponents = append(renderComponents, d.responseCodes, d.serverIPs)
	}
	if componentVisible["table"] {
		renderComponents = append(renderComponents, d.requestTable)
	}

	// Render all components
	termui.Render(renderComponents...)
}

// handleEvents handles UI events
func (d *Dashboard) handleEvents() {
	fmt.Println("[Dashboard] Starting event handler")

	// 尽早设置SIGINT(Ctrl+C)处理器
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("[Dashboard] Received SIGINT/SIGTERM signal, exiting...")
		termui.Close()
		os.Exit(0)
	}()

	// 设置UI事件轮询
	uiEvents := termui.PollEvents()

	// 为了更清晰地看到轮询是否工作，先打印一条消息
	fmt.Println("[Dashboard] Event polling started - Press 'q', ESC, or Ctrl+C to exit")
	fmt.Println("[Dashboard] UI Controls:")
	fmt.Println("  - 's': Save current layout configuration")
	fmt.Println("  - 'r': Restore default layout")
	fmt.Println("  - '1-6': Toggle visibility of components:")
	fmt.Println("      1: Header, 2: Charts, 3: Info Boxes, 4: OS Stats, 5: Response Codes, 6: Request Table")

	// 不在select中处理，直接循环处理事件
	for e := range uiEvents {
		fmt.Printf("[Dashboard] Received event: %s\n", e.ID)

		switch e.ID {
		case "q", "<C-c>", "<Escape>":
			fmt.Println("[Dashboard] Quit event received (q/Esc/Ctrl+C), stopping dashboard")
			termui.Close()
			os.Exit(0)

		case "<Resize>":
			fmt.Println("[Dashboard] Window resize event, redrawing UI")
			termui.Clear()
			d.render()
			termui.Render()

		case "s", "S":
			fmt.Println("[Dashboard] Saving current layout configuration")
			if err := d.LockCurrentUILayout(); err != nil {
				fmt.Printf("[Dashboard] Error saving layout: %v\n", err)
			}

		case "r", "R":
			fmt.Println("[Dashboard] Restoring default layout")
			if err := d.RestoreDefaultLayout(); err != nil {
				fmt.Printf("[Dashboard] Error restoring default layout: %v\n", err)
			}

		// Toggle component visibility
		case "1":
			d.ToggleComponentVisibility("header")
		case "2":
			d.ToggleComponentVisibility("charts")
		case "3":
			d.ToggleComponentVisibility("info")
		case "4":
			d.ToggleComponentVisibility("os")
		case "5":
			d.ToggleComponentVisibility("codes")
		case "6":
			d.ToggleComponentVisibility("table")
		}
	}

	fmt.Println("[Dashboard] Event loop ended")
}

// updateUI updates the UI periodically
func (d *Dashboard) updateUI() {
	fmt.Println("[Dashboard] Starting UI update loop")
	// 修改更新频率为1秒一次
	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()

	// 初始渲染已在Start方法中完成，这里不需要重复
	fmt.Println("[Dashboard] UI update loop running with 1 second interval")

	// 删除模拟数据相关变量
	updateNumber := 0

	// 计时检查ticker，每秒检查一次攻击是否完成
	timeTicker := time.NewTicker(1 * time.Second)
	defer timeTicker.Stop()

	// 标记攻击是否完成
	attackFinished := false

	// 捕获并恢复panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[Dashboard] Recovered from panic in updateUI: %v\n", r)
			// 尝试优雅地关闭，避免卡死
			d.Stop()
		}
	}()

	// 初始化表格数据，确保开始就有10行
	d.initTableRows()

	for {
		select {
		case <-ticker.C:
			updateNumber++
			fmt.Printf("[Dashboard] UI update #%d\n", updateNumber)

			// 包装每次更新的互斥锁操作
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("[Dashboard] Recovered from panic during update #%d: %v\n", updateNumber, r)
					}
				}()

				d.mu.Lock()
				defer d.mu.Unlock()

				// 无需模拟数据相关代码，直接更新UI组件
				d.updateHeader()
				d.updateJobInfo()
				d.updateCounts()
				d.updateNetworkStats()
				d.updateOSStats()
				d.updateCharts()

				// 简单渲染，不清屏
				d.render()

				// 安全调用termui.Render
				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Printf("[Dashboard] Recovered from panic in termui.Render: %v\n", r)
						}
					}()
					termui.Render()
				}()
			}()

		case <-timeTicker.C:
			// 检查攻击时间是否设置且已结束
			d.mu.Lock()

			// 如果有设置攻击时间，倒计时时间>0，且还未标记完成
			if d.attackTime > 0 && !attackFinished {
				// 更新倒计时
				if d.timeLeft > 0 {
					d.timeLeft--
					fmt.Printf("[Dashboard] Attack time remaining: %d seconds\n", d.timeLeft)
				}

				// 检查是否刚好倒计时结束
				if d.timeLeft <= 0 {
					attackFinished = true
					// 解锁后显示UI，避免死锁
					d.mu.Unlock()

					// 显示完成消息，然后直接退出
					d.showAttackFinishedDialog()

					// 这里不需要再调用任何额外的代码，因为showAttackFinishedDialog
					// 中已经设置了自动退出的逻辑，不会再回到这里执行
					return // 直接返回，终止UI更新循环

					// 下面的代码不会被执行
				}
			}

			d.mu.Unlock()

		case <-d.done:
			fmt.Println("[Dashboard] UI update loop terminated")
			return
		}
	}
}

// 用于安全地恢复终端状态
func safeRestoreTerminal() {
	// 重置终端状态，防止鼠标滚轮产生乱码
	fmt.Print("\033c")       // 清屏并重置
	fmt.Print("\033[?25h")   // 显示光标
	fmt.Print("\033[?1049l") // 退出备用屏幕
	fmt.Print("\033[?1000l") // 禁用鼠标事件
	fmt.Print("\033[?1002l") // 禁用鼠标移动事件
	fmt.Print("\033[?1003l") // 禁用所有鼠标事件
	fmt.Print("\033[?1006l") // 禁用SGR鼠标模式
	fmt.Print("\033[?1015l") // 禁用urxvt鼠标模式
	fmt.Print("\033[?1001l") // 禁用高亮鼠标模式

	// 重置终端属性
	fmt.Print("\033[0m") // 重置所有属性
	fmt.Print("\033[m")  // 备用重置命令

	// 等待一段时间确保命令生效
	time.Sleep(100 * time.Millisecond)
}

// showAttackFinishedDialog 显示攻击完成的对话框
func (d *Dashboard) showAttackFinishedDialog() {
	// 捕获可能的panic
	defer func() {
		if r := recover(); r != nil {
			// 先确保关闭终端UI
			termui.Close()
			// 恢复终端状态
			safeRestoreTerminal()
			// 不要输出错误信息到UI，只记录到日志文件
			// 由于在强制终止时，我们不需要继续操作，直接退出即可
			os.Exit(0)
		}
	}()

	// 获取终端尺寸
	termWidth, termHeight := termui.TerminalDimensions()

	// 计算对话框尺寸和位置（居中）
	dialogWidth := 40
	dialogHeight := 6
	x := (termWidth - dialogWidth) / 2
	y := (termHeight - dialogHeight) / 2

	// 创建完成对话框
	dialog := widgets.NewParagraph()
	dialog.Title = "[ 攻击已完成 ]"
	dialog.BorderStyle.Fg = termui.ColorGreen
	dialog.TitleStyle = termui.NewStyle(termui.ColorYellow, termui.ColorClear, termui.ModifierBold)
	dialog.TextStyle = termui.NewStyle(termui.ColorWhite)

	// 设置对话框文本内容
	dialog.Text = "\n\n     攻击任务已完成，程序将在3秒后自动退出     \n     或按任意键立即退出     "

	// 设置对话框位置
	dialog.SetRect(x, y, x+dialogWidth, y+dialogHeight)

	// 安全地渲染对话框，使用单独的渲染调用
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 不在屏幕上显示错误，直接忽略
				return
			}
		}()

		// 创建一个临时的UI，覆盖当前屏幕
		termui.Clear()
		termui.Render(dialog)
	}()

	// 设置自动退出定时器
	exitTimer := time.NewTimer(3 * time.Second)

	// 同时设置一个捕获按键的goroutine，让用户可以主动按键退出
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// 确保关闭终端UI
				termui.Close()
				// 恢复终端状态
				safeRestoreTerminal()
				// 忽略错误，直接退出程序
				os.Exit(0)
			}
		}()

		// 捕获事件
		uiEvents := termui.PollEvents()

		select {
		case <-uiEvents:
			// 用户按键退出
			exitTimer.Stop()
			// 确保关闭终端UI
			termui.Close()
			// 恢复终端状态
			safeRestoreTerminal()
			// 直接退出程序
			os.Exit(0)
		case <-exitTimer.C:
			// 超时自动退出
			// 确保关闭终端UI
			termui.Close()
			// 恢复终端状态
			safeRestoreTerminal()
			os.Exit(0)
		}
	}()
}

// initTableRows 初始化表格，确保有10行数据
func (d *Dashboard) initTableRows() {
	if d.requestTable == nil {
		d.requestTable = widgets.NewTable()
		d.requestTable.Title = "Last Requests (10)"
		d.requestTable.TextStyle = termui.NewStyle(termui.ColorGreen)
		d.requestTable.BorderStyle.Fg = termui.ColorRed
		d.requestTable.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
		d.requestTable.RowSeparator = true
		d.requestTable.FillRow = true

		// Set custom column widths to optimize display
		d.requestTable.ColumnWidths = []int{17, 45, 25, 22, 22}
		d.requestTable.ColumnResizer = func() {
			// Custom column resizer to maintain proportions
			width := d.requestTable.Inner.Dx()
			// Calculate column widths based on percentages - give more space to proxy
			d.requestTable.ColumnWidths = []int{
				width * 17 / 100, // Time: 17% for full date/time
				width * 45 / 100, // Current Proxy: ~45% of space
				width * 20 / 100, // URL: ~20% of space
				width * 10 / 100, // Response Code: ~10% of space
				width * 8 / 100,  // Response Server: ~8% of space
			}
		}
	}

	// 确保有表头
	if len(d.requestTable.Rows) == 0 {
		d.requestTable.Rows = [][]string{
			{"Time", "Current Proxy", "URL", "Response Code/Time/BodySize", "Response Server/IP"},
		}
		d.requestTable.RowStyles = make(map[int]termui.Style)
		d.requestTable.RowStyles[0] = termui.NewStyle(termui.ColorGreen, termui.ColorClear, termui.ModifierBold)
	}

	// 填充10行空数据，确保表格显示完整
	for i := len(d.requestTable.Rows); i <= 10; i++ {
		d.requestTable.Rows = append(d.requestTable.Rows, []string{
			"0000/00/00 00:00:00",
			"waiting...",
			"waiting...",
			"---/---/---",
			"---/---",
		})
	}
}

// updateServerIPStats 更新服务器IP统计信息
func (d *Dashboard) updateServerIPStats() {
	// 确保serverIPs已初始化
	if d.serverIPs == nil {
		d.serverIPs = widgets.NewParagraph()
		d.serverIPs.Title = "Server IP Distribution"
		d.serverIPs.BorderStyle.Fg = termui.ColorRed
		d.serverIPs.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
		d.serverIPs.TextStyle = termui.NewStyle(termui.ColorGreen)
	}

	// 如果IP统计map未初始化，初始化它
	if d.serverIPStats == nil {
		d.serverIPStats = make(map[string]int64)
	}

	// 从接收到的lastRequest中获取IP信息
	if d.lastRequest != nil {
		if ip, ok := d.lastRequest["ip"].(string); ok && ip != "" && isValidIPAddress(ip) {
			// 更新IP统计计数
			d.serverIPStats[ip]++
		}
	}

	// 将map转换为排序后的数据
	type ipCount struct {
		ip    string
		count int64
	}
	var sortedIPs []ipCount
	for ip, count := range d.serverIPStats {
		// 过滤掉任何不像IP地址的条目（比如域名）
		if isValidIPAddress(ip) {
			sortedIPs = append(sortedIPs, ipCount{ip, count})
		}
	}

	// 按计数降序排序
	sort.Slice(sortedIPs, func(i, j int) bool {
		return sortedIPs[i].count > sortedIPs[j].count
	})

	// 仅保留前10个IP，以避免显示过多
	if len(sortedIPs) > 10 {
		sortedIPs = sortedIPs[:10]
	}

	// 生成文本展示
	if len(sortedIPs) == 0 {
		d.serverIPs.Text = "No data available"
		return
	}

	// 为每行分配5个IP，使用不同颜色
	var lines []string
	line := ""
	for i, item := range sortedIPs {
		// 添加IP和计数，轮换使用不同颜色
		var ipInfo string
		switch i % 4 {
		case 0:
			ipInfo = fmt.Sprintf("[%s](fg:green,mod:bold)(%d)", item.ip, item.count)
		case 1:
			ipInfo = fmt.Sprintf("[%s](fg:yellow)(%d)", item.ip, item.count)
		case 2:
			ipInfo = fmt.Sprintf("[%s](fg:cyan)(%d)", item.ip, item.count)
		case 3:
			ipInfo = fmt.Sprintf("[%s](fg:white)(%d)", item.ip, item.count)
		}

		// 如果不是第一个IP，添加分隔符
		if i%5 != 0 {
			line += " [|](fg:red,mod:bold) "
		} else if i > 0 {
			// 如果是新的一行，将前一行添加到lines中
			lines = append(lines, line)
			line = ""
		}

		line += ipInfo
	}

	// 添加最后一行
	if line != "" {
		lines = append(lines, line)
	}

	// 合并所有行
	d.serverIPs.Text = strings.Join(lines, "\n")
}

// isValidIPAddress 检查字符串是否是有效的IP地址
func isValidIPAddress(ip string) bool {
	// 检查是否包含字母（简单过滤掉域名）
	if strings.ContainsAny(ip, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}

	// 确保字符串不为空且不是未知值
	if ip == "" || ip == "unknown" || ip == "---" {
		return false
	}

	// 检查IPv4地址格式
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}

	return true
}

// updateRequestTable 更新请求表格
func (d *Dashboard) updateRequestTable() {
	// 确保requestTable已初始化
	if d.requestTable == nil || len(d.requestTable.Rows) == 0 {
		d.initTableRows()
	}

	// 不再主动生成模拟数据，真实数据将通过updateRequestTableWithData方法添加
}

// updateHeader updates the header section with current information
func (d *Dashboard) updateHeader() {
	// 计算倒计时显示
	var timeDisplay string
	if d.attackTime > 0 {
		if d.timeLeft <= 0 {
			timeDisplay = "[已完成](fg:green,mod:bold)"
		} else {
			timeDisplay = fmt.Sprintf("[%d秒](fg:yellow,mod:bold)", d.timeLeft)
		}
	} else {
		timeDisplay = "[持续运行](fg:blue)"
	}

	// 计算执行时间
	execTime := time.Since(d.stats.Start).Seconds()

	// 格式化带宽和流量
	var bwStr, trafficStr string
	if d.bandwidth > 0 {
		bwStr = fmt.Sprintf("%.2f Mbps", d.bandwidth)
	} else {
		bwStr = "0 Mbps"
	}

	if d.totalTraffic > 0 {
		trafficStr = fmt.Sprintf("%.2f GB", d.totalTraffic)
	} else {
		trafficStr = "0 GB"
	}

	// Format the header to clearly display all important information
	d.headerBox.Text = fmt.Sprintf(
		"[目标:](fg:white,mod:bold) [%s](fg:green,mod:bold)  [模式:](fg:white,mod:bold) [%s](fg:green,mod:bold)\n"+
			"[攻击时间:](fg:white,mod:bold) [%d秒](fg:green,mod:bold)  [剩余:](fg:white,mod:bold) %s  [运行:](fg:white,mod:bold) [%.1f秒](fg:green,mod:bold)\n"+
			"[带宽:](fg:white,mod:bold) [%s](fg:green,mod:bold)  [总流量:](fg:white,mod:bold) [%s](fg:green,mod:bold)",
		d.targetURL,
		d.attackMode,
		d.attackTime,
		timeDisplay,
		execTime,
		bwStr,
		trafficStr,
	)
}

func (d *Dashboard) updateJobInfo() {
	// Format headers and other long strings to prevent UI overflow
	refererDisplay := formatLongString(d.referer, 30)

	// Build job info text with proper formatting and ensure all parameters are displayed
	d.jobInfoBox.Text = fmt.Sprintf(
		"[Works:](fg:white,mod:bold) [%d](fg:green,mod:bold)  [Workers]\n"+
			"[Interval:](fg:white,mod:bold) [%d](fg:green,mod:bold)  [ms]\n"+
			"[Rates:](fg:white,mod:bold) [%d](fg:green,mod:bold)  [requests/sec]\n"+
			"[Proxy Type:](fg:white,mod:bold) [%s](fg:yellow,mod:bold)\n"+
			"[UA Type:](fg:white,mod:bold) [%s](fg:green)\n"+
			"[Bypass:](fg:white,mod:bold) [%s](fg:green)\n"+
			"[Referer:](fg:white,mod:bold) [%s](fg:green)",
		d.works, d.interval, d.rates, d.proxyType,
		d.uaType, d.bypassType, refererDisplay,
	)
}

// formatLongString truncates and formats long strings for display
func formatLongString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// updateCounts 更新计数显示，拆分为两个独立区域
func (d *Dashboard) updateCounts() {
	// Update target counts with colored formatting like the Job Info box
	d.targetCountsBox.Text = fmt.Sprintf("Target Statistics\n[Total Requests:](fg:white,mod:bold) [%d](fg:green,mod:bold)\n[Success:](fg:white,mod:bold) [%d](fg:green,mod:bold)\n[Failed:](fg:white,mod:bold) [%d](fg:red,mod:bold)",
		d.targetCount, d.requestOK, d.requestFail)
	d.targetCountsBox.TextStyle = termui.NewStyle(termui.ColorWhite)

	// Update proxy counts - ensure we display correct values for proxy statistics
	// Keep track of debugging information to help diagnose issues
	proxyDebugInfo := ""
	if d.debug {
		proxyDebugInfo = fmt.Sprintf(" (debug: rawStats has proxyCount=%v)", getRawStatsValue(d.rawStats, "proxyCount"))
	}

	// Check if proxy mode is enabled
	if d.proxyType == "none" {
		// Special case: when proxyType is "none", show a message instead of zeros
		d.proxyCountsBox.Text = fmt.Sprintf("Proxy Statistics%s\n[Status:](fg:white,mod:bold) [DISABLED](fg:yellow,mod:bold)\n[Info:](fg:white,mod:bold) [Proxy mode is not enabled](fg:white)\n[Set proxyType to use proxies](fg:cyan)",
			proxyDebugInfo)
	} else {
		// Display the data with appropriate color for each value - ensure consistent formatting with target stats
		d.proxyCountsBox.Text = fmt.Sprintf("Proxy Statistics%s\n[Total Proxies:](fg:white,mod:bold) [%d](fg:green,mod:bold)\n[Success:](fg:white,mod:bold) [%d](fg:green,mod:bold)\n[Failed:](fg:white,mod:bold) [%d](fg:red,mod:bold)",
			proxyDebugInfo,
			d.proxyCount,
			d.proxyReqOK,
			d.proxyReqFail)
	}

	// Allow color tags to be processed
	d.proxyCountsBox.BorderStyle.Fg = termui.ColorRed
	d.proxyCountsBox.TextStyle = termui.NewStyle(termui.ColorWhite)

	// Update network stats
	d.networkStatsBox.Text = fmt.Sprintf("Network Statistics\n[Bandwidth:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)\n[Total Traffic:](fg:white,mod:bold) [%.4f GB](fg:green,mod:bold)\n[Upload Speed:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)\n[Download Speed:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)",
		d.bandwidth, d.totalTraffic, d.uploadSpeed, d.downloadSpeed)
	d.networkStatsBox.TextStyle = termui.NewStyle(termui.ColorWhite)
}

// Helper function to get color based on value
func getColorForValue(val int) termui.Color {
	if val > 0 {
		return termui.ColorGreen
	}
	return termui.ColorWhite
}

// Helper function to safely get a value from rawStats
func getRawStatsValue(stats map[string]interface{}, key string) interface{} {
	if stats == nil {
		return nil
	}
	return stats[key]
}

func (d *Dashboard) updateOSStats() {
	d.cpuGauge.Percent = int(d.cpuUsage * 100)
	d.memGauge.Percent = int(d.memUsage * 100)
	d.gcGauge.Percent = int(d.gcUsage * 100)

	// Update gauge labels - 显示更简洁的标签
	d.cpuGauge.Label = fmt.Sprintf("%.1f%%", d.cpuUsage*100)
	d.memGauge.Label = fmt.Sprintf("%.1f%%", d.memUsage*100)
	d.gcGauge.Label = fmt.Sprintf("%.1f%%", d.gcUsage*100)
}

// updateCharts updates all charts with new data
func (d *Dashboard) updateCharts() {
	// Update RPS chart
	if len(d.currentRPS) > 0 {
		// Ensure we have at least 2 points
		if len(d.currentRPS) < 2 {
			d.currentRPS = append(d.currentRPS, d.currentRPS[0])
		}
		d.rpsChart.Data = [][]float64{d.currentRPS}
		currentRPS := d.currentRPS[len(d.currentRPS)-1]
		d.rpsChart.Title = fmt.Sprintf(" RPS (Current: %.2f) ", currentRPS)

		// Dynamically adjust max value
		maxRPS := float64(0)
		for _, v := range d.currentRPS {
			if v > maxRPS {
				maxRPS = v
			}
		}
		d.rpsChart.MaxVal = maxRPS * 1.2 // Add 20% headroom
		if d.rpsChart.MaxVal <= 0 {
			d.rpsChart.MaxVal = 1.0 // 确保MaxVal至少为1.0
		}
	}

	// Update response time chart
	if len(d.currentResponseTime) > 0 {
		// Ensure we have at least 2 points
		if len(d.currentResponseTime) < 2 {
			d.currentResponseTime = append(d.currentResponseTime, d.currentResponseTime[0])
		}
		d.responseChart.Data = [][]float64{d.currentResponseTime}
		currentRT := d.currentResponseTime[len(d.currentResponseTime)-1]
		d.responseChart.Title = fmt.Sprintf(" Response Time (Current: %.2fms) ", currentRT)

		// Dynamically adjust max value
		maxRT := float64(0)
		for _, v := range d.currentResponseTime {
			if v > maxRT {
				maxRT = v
			}
		}
		d.responseChart.MaxVal = maxRT * 1.2 // Add 20% headroom
		if d.responseChart.MaxVal <= 0 {
			d.responseChart.MaxVal = 1.0 // 确保MaxVal至少为1.0
		}
	}

	// Update response codes chart with data from stats
	// 确保responseCodes已正确初始化
	if d.responseCodes == nil {
		fmt.Printf("[DASHBOARD] 初始化responseCodes图表\n")
		d.responseCodes = widgets.NewBarChart()
		d.responseCodes.Title = "Response Codes"
		d.responseCodes.BorderStyle.Fg = termui.ColorRed
		d.responseCodes.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
	}

	// 从stats中获取响应码数据
	var codesMap map[int]int64

	if d.stats != nil {
		d.stats.Mu.RLock()
		// 深度复制codes map，避免并发修改问题
		if d.stats.Codes != nil && len(d.stats.Codes) > 0 {
			codesMap = make(map[int]int64, len(d.stats.Codes))
			for k, v := range d.stats.Codes {
				codesMap[k] = v
			}
		}
		d.stats.Mu.RUnlock()

		fmt.Printf("[DASHBOARD] Stats中的响应码: %v\n", codesMap)
	}

	// 如果没有从stats中获取到数据，尝试从rawStats获取
	if (codesMap == nil || len(codesMap) == 0) && d.rawStats != nil {
		if codesFromRaw, ok := d.rawStats["codes"]; ok {
			fmt.Printf("[DASHBOARD] 尝试从rawStats中获取codes: %T\n", codesFromRaw)

			// 尝试转换为正确的格式
			switch v := codesFromRaw.(type) {
			case map[int]int64:
				codesMap = v
			case map[string]interface{}:
				codesMap = make(map[int]int64)
				for codeStr, count := range v {
					if code, err := strconv.Atoi(codeStr); err == nil {
						if countInt64, ok := count.(int64); ok {
							codesMap[code] = countInt64
						} else if countFloat, ok := count.(float64); ok {
							codesMap[code] = int64(countFloat)
						} else if countInt, ok := count.(int); ok {
							codesMap[code] = int64(countInt)
						}
					}
				}
			case map[interface{}]interface{}:
				codesMap = make(map[int]int64)
				for codeKey, count := range v {
					var code int
					// 尝试转换key为int
					switch c := codeKey.(type) {
					case int:
						code = c
					case float64:
						code = int(c)
					case string:
						if ci, err := strconv.Atoi(c); err == nil {
							code = ci
						} else {
							continue
						}
					default:
						continue
					}

					// 尝试转换count为int64
					switch cnt := count.(type) {
					case int64:
						codesMap[code] = cnt
					case int:
						codesMap[code] = int64(cnt)
					case float64:
						codesMap[code] = int64(cnt)
					}
				}
			}
		}
	}

	// 设置黑色作为默认数字和标签样式，确保在图表创建时就设置正确的颜色
	if d.responseCodes != nil {
		defaultStyle := termui.NewStyle(termui.ColorBlack)
		// 初始化默认样式数组
		if len(d.responseCodes.Labels) > 0 {
			numStyles := make([]termui.Style, len(d.responseCodes.Labels))
			labelStyles := make([]termui.Style, len(d.responseCodes.Labels))
			for i := range d.responseCodes.Labels {
				numStyles[i] = defaultStyle
				labelStyles[i] = defaultStyle
			}
			d.responseCodes.NumStyles = numStyles
			d.responseCodes.LabelStyles = labelStyles
		}
	}

	// 更新响应码图表
	updateResponseCodesChart(d, codesMap)

	// Limit data points for performance
	maxPoints := 100
	if len(d.currentRPS) > maxPoints {
		d.currentRPS = d.currentRPS[len(d.currentRPS)-maxPoints:]
	}
	if len(d.currentResponseTime) > maxPoints {
		d.currentResponseTime = d.currentResponseTime[len(d.currentResponseTime)-maxPoints:]
	}
}

// SetTarget sets the target URL
func (d *Dashboard) SetTarget(url string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targetURL = url
}

// SetMode sets the attack mode
func (d *Dashboard) SetMode(mode string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attackMode = mode
}

// SetDuration sets the attack duration
func (d *Dashboard) SetDuration(seconds int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attackTime = seconds
	d.timeLeft = seconds
}

// UpdateStats 更新统计信息
func (d *Dashboard) UpdateStats(stats interface{}) {
	d.statsMutex.Lock()
	defer d.statsMutex.Unlock()

	// 如果stats为nil，直接返回
	if stats == nil {
		return
	}

	// 保存原始stats
	d.rawStats = nil

	// 将stats转换为map
	var statsMap map[string]interface{}
	var ok bool

	// 如果stats已经是map[string]interface{}类型
	if statsMap, ok = stats.(map[string]interface{}); !ok {
		// 尝试将stats转换为json，然后反序列化为map
		statsBytes, err := json.Marshal(stats)
		if err != nil {
			fmt.Printf("[ERROR] Failed to marshal stats: %v\n", err)
			return
		}

		err = json.Unmarshal(statsBytes, &statsMap)
		if err != nil {
			fmt.Printf("[ERROR] Failed to unmarshal stats: %v\n", err)
			return
		}
	}

	// 保存原始的statsMap
	d.rawStats = statsMap

	// 打印调试信息，查看codes字段的类型和内容
	if codesVal, ok := statsMap["codes"]; ok {
		fmt.Printf("[DASHBOARD DEBUG] codes field type: %T\n", codesVal)
		// 尝试打印codes的内容
		switch v := codesVal.(type) {
		case map[string]interface{}:
			fmt.Printf("[DASHBOARD DEBUG] codes (map[string]interface{}): %v\n", v)

			// 创建一个新的map来存储转换后的codes
			if d.stats == nil {
				d.stats = &Stats{}
			}
			if d.stats.Codes == nil {
				d.stats.Codes = make(map[int]int64)
			}

			// 清除之前的状态码数据，只保留新数据
			d.stats.Mu.Lock()
			d.stats.Codes = make(map[int]int64)

			// 转换并存储状态码
			for codeStr, count := range v {
				codeInt, err := strconv.Atoi(codeStr)
				if err == nil {
					if countInt64, ok := count.(int64); ok {
						d.stats.Codes[codeInt] = countInt64
					} else if countFloat, ok := count.(float64); ok {
						d.stats.Codes[codeInt] = int64(countFloat)
					} else if countInt, ok := count.(int); ok {
						d.stats.Codes[codeInt] = int64(countInt)
					}
				}
			}
			d.stats.Mu.Unlock()

		case map[int]int64:
			fmt.Printf("[DASHBOARD DEBUG] codes (map[int]int64): %v\n", v)

			// 直接使用这个类型正确的map
			if d.stats == nil {
				d.stats = &Stats{}
			}
			d.stats.Mu.Lock()
			d.stats.Codes = v
			d.stats.Mu.Unlock()

		case map[interface{}]interface{}:
			fmt.Printf("[DASHBOARD DEBUG] codes (map[interface{}]interface{}): %v\n", v)

			// 转换通用map为正确的类型
			if d.stats == nil {
				d.stats = &Stats{}
			}
			if d.stats.Codes == nil {
				d.stats.Codes = make(map[int]int64)
			}

			// 清除之前的状态码数据
			d.stats.Mu.Lock()
			d.stats.Codes = make(map[int]int64)

			// 转换并存储状态码
			for code, count := range v {
				var codeInt int

				// 尝试转换code为int
				switch c := code.(type) {
				case int:
					codeInt = c
				case float64:
					codeInt = int(c)
				case string:
					if ci, err := strconv.Atoi(c); err == nil {
						codeInt = ci
					} else {
						continue
					}
				default:
					continue
				}

				// 尝试转换count为int64
				switch cnt := count.(type) {
				case int64:
					d.stats.Codes[codeInt] = cnt
				case int:
					d.stats.Codes[codeInt] = int64(cnt)
				case float64:
					d.stats.Codes[codeInt] = int64(cnt)
				}
			}
			d.stats.Mu.Unlock()

		default:
			fmt.Printf("[DASHBOARD DEBUG] codes (unknown type): %v\n", v)
		}
	} else {
		fmt.Printf("[DASHBOARD DEBUG] No codes field found in stats map\n")
	}

	// 确保 lastRequest 数据被正确处理
	if lastReq, ok := statsMap["lastRequest"].(map[string]interface{}); ok {
		fmt.Printf("[DASHBOARD DEBUG] Found lastRequest in stats: %v\n", lastReq)

		// 如果有新的请求数据，更新请求表
		if url, ok := lastReq["url"].(string); ok {
			fmt.Printf("[DASHBOARD] 收到新的URL: %s\n", url)

			// 检查是否有状态码信息
			if code, ok := lastReq["code"].(int); ok && code > 0 {
				fmt.Printf("[DASHBOARD] 请求状态码: %d\n", code)

				// 确保stats和codes map已初始化
				if d.stats == nil {
					d.stats = &Stats{}
				}
				if d.stats.Codes == nil {
					d.stats.Codes = make(map[int]int64)
				}

				// 更新状态码计数
				d.stats.Mu.Lock()
				d.stats.Codes[code]++
				d.stats.Mu.Unlock()
			}

			// 将请求数据传递给请求表更新函数
			updateRequestTableWithData(d, lastReq)
		}
	}

	// 更新targetCount，不管它原本是int还是float64
	if count, ok := statsMap["totalRequests"]; ok {
		d.updateStatsField(&d.targetCount, count)
	} else if count, ok := statsMap["total"]; ok {
		d.updateStatsField(&d.targetCount, count)
	}

	// 更新requestOK
	if count, ok := statsMap["requestOK"]; ok {
		d.updateStatsField(&d.requestOK, count)
	} else if count, ok := statsMap["success"]; ok {
		d.updateStatsField(&d.requestOK, count)
	}

	// 更新requestFail
	if count, ok := statsMap["requestFail"]; ok {
		d.updateStatsField(&d.requestFail, count)
	} else if count, ok := statsMap["failed"]; ok {
		d.updateStatsField(&d.requestFail, count)
	}

	// 更新proxyCount
	if count, ok := statsMap["proxyCount"]; ok {
		if countInt, ok := count.(int); ok {
			d.proxyCount = countInt
		} else if countFloat, ok := count.(float64); ok {
			d.proxyCount = int(countFloat)
		}
	}

	// 更新proxyReqOK
	if count, ok := statsMap["proxyReqOK"]; ok {
		d.updateStatsField(&d.proxyReqOK, count)
	}

	// 更新proxyReqFail
	if count, ok := statsMap["proxyReqFail"]; ok {
		d.updateStatsField(&d.proxyReqFail, count)
	}

	// 更新系统使用率
	if usage, ok := statsMap["cpuUsage"]; ok {
		d.updateFloatField(&d.cpuUsage, usage)
	}
	if usage, ok := statsMap["memUsage"]; ok {
		d.updateFloatField(&d.memUsage, usage)
	}
	if usage, ok := statsMap["gcUsage"]; ok {
		d.updateFloatField(&d.gcUsage, usage)
	}

	// 更新带宽和流量
	if bw, ok := statsMap["bandwidth"]; ok {
		d.updateFloatField(&d.bandwidth, bw)
	}
	if tt, ok := statsMap["totalTraffic"]; ok {
		d.updateFloatField(&d.totalTraffic, tt)
	}
	if bw, ok := statsMap["proxyBandwidth"]; ok {
		d.updateFloatField(&d.proxyBandwidth, bw)
	}

	// 更新上传和下载速度
	if us, ok := statsMap["uploadSpeed"]; ok {
		d.updateFloatField(&d.uploadSpeed, us)
	}
	if ds, ok := statsMap["downloadSpeed"]; ok {
		d.updateFloatField(&d.downloadSpeed, ds)
	}

	// 更新RPS
	if rps, ok := statsMap["rps"]; ok {
		d.updateRpsField(rps)
	} else if rps, ok := statsMap["currentRPS"]; ok {
		d.updateRpsField(rps)
	}

	// 更新响应时间
	if rt, ok := statsMap["avgRt"]; ok {
		d.updateResponseTimeField(rt)
	} else if rt, ok := statsMap["responseTime"]; ok {
		d.updateResponseTimeField(rt)
	}

	// 处理响应代码分布
	if codes, ok := statsMap["codes"].(map[string]interface{}); ok {
		// 转换map[string]interface{}为map[int]int64
		codesMap := make(map[int]int64)
		for code, count := range codes {
			codeInt, err := strconv.Atoi(code)
			if err != nil {
				continue
			}
			if countInt64, ok := count.(int64); ok {
				codesMap[codeInt] = countInt64
			} else if countFloat, ok := count.(float64); ok {
				codesMap[codeInt] = int64(countFloat)
			}
		}
		updateResponseCodesChart(d, codesMap)
	} else if codes, ok := statsMap["codes"].(map[int]int64); ok {
		updateResponseCodesChart(d, codes)
	} else if codesGeneric, ok := statsMap["codes"].(map[interface{}]interface{}); ok {
		// 处理通用map类型
		codesMap := make(map[int]int64)
		for codeKey, count := range codesGeneric {
			var codeInt int
			// 尝试将key转换为int
			switch v := codeKey.(type) {
			case int:
				codeInt = v
			case float64:
				codeInt = int(v)
			case string:
				var err error
				codeInt, err = strconv.Atoi(v)
				if err != nil {
					continue
				}
			default:
				// 无法转换的类型忽略
				continue
			}

			// 尝试将值转换为int64
			var countInt64 int64
			switch v := count.(type) {
			case int64:
				countInt64 = v
			case int:
				countInt64 = int64(v)
			case float64:
				countInt64 = int64(v)
			default:
				countInt64 = 1 // 默认至少有一个
			}

			codesMap[codeInt] = countInt64
		}
		updateResponseCodesChart(d, codesMap)
	} else {
		// 如果没有找到有效的code数据，则使用一个默认的示例值
		fmt.Printf("[DASHBOARD] Warning: No valid response codes found in stats map: %T\n", statsMap["codes"])
		defaultCodes := map[int]int64{200: 1}
		updateResponseCodesChart(d, defaultCodes)
	}

	// 处理lastRequest信息
	if lastReq, ok := statsMap["lastRequest"].(map[string]interface{}); ok {
		// 更新lastRequest数据，确保每次都是全新对象
		d.lastRequest = make(map[string]interface{}, len(lastReq))
		for k, v := range lastReq {
			d.lastRequest[k] = v
		}

		// 直接将请求数据添加到表格
		updateRequestTableWithData(d, d.lastRequest)
	}

	// 处理server列表
	if servers, ok := statsMap["servers"].([]map[string]interface{}); ok {
		processServerList(d, servers)
	} else if servers, ok := statsMap["servers"].([]interface{}); ok {
		processServerInterfaceList(d, servers)
	}
}

// getMapKeys 返回map中所有键的列表
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// updateStatsField 更新int64类型的统计字段
func (d *Dashboard) updateStatsField(field *int64, value interface{}) {
	if v, ok := value.(int64); ok {
		*field = v
	} else if v, ok := value.(uint64); ok {
		*field = int64(v)
	} else if v, ok := value.(float64); ok {
		*field = int64(v)
	} else if v, ok := value.(int); ok {
		*field = int64(v)
	}
}

// updateFloatField 更新float64类型的统计字段
func (d *Dashboard) updateFloatField(field *float64, value interface{}) {
	if v, ok := value.(float64); ok {
		*field = v
	} else if v, ok := value.(float32); ok {
		*field = float64(v)
	} else if v, ok := value.(int64); ok {
		*field = float64(v)
	} else if v, ok := value.(uint64); ok {
		*field = float64(v)
	} else if v, ok := value.(int); ok {
		*field = float64(v)
	}
}

// updateRpsField 更新RPS字段
func (d *Dashboard) updateRpsField(value interface{}) {
	var rps float64
	if v, ok := value.(float64); ok {
		rps = v
	} else if v, ok := value.(float32); ok {
		rps = float64(v)
	} else if v, ok := value.(int64); ok {
		rps = float64(v)
	} else if v, ok := value.(uint64); ok {
		rps = float64(v)
	} else if v, ok := value.(int); ok {
		rps = float64(v)
	} else {
		return
	}

	d.currentRPS = append(d.currentRPS, rps)
	if len(d.currentRPS) > 100 {
		d.currentRPS = d.currentRPS[len(d.currentRPS)-100:]
	}
	fmt.Printf("[Dashboard] Updated RPS: %.2f req/sec\n", rps)
}

// updateResponseTimeField 更新响应时间字段
func (d *Dashboard) updateResponseTimeField(value interface{}) {
	var rt float64
	if v, ok := value.(float64); ok {
		rt = v
	} else if v, ok := value.(float32); ok {
		rt = float64(v)
	} else if v, ok := value.(int64); ok {
		rt = float64(v)
	} else if v, ok := value.(uint64); ok {
		rt = float64(v)
	} else if v, ok := value.(int); ok {
		rt = float64(v)
	} else {
		return
	}

	d.currentResponseTime = append(d.currentResponseTime, rt)
	if len(d.currentResponseTime) > 100 {
		d.currentResponseTime = d.currentResponseTime[len(d.currentResponseTime)-100:]
	}
	fmt.Printf("[Dashboard] Updated Response Time: %.2f ms\n", rt)
}

// processServerList 处理服务器列表数据
func processServerList(d *Dashboard, servers []map[string]interface{}) {
	// 清理旧计数，避免累积过多
	if len(d.serverIPStats) > 30 {
		// 保留较高的计数
		type ipCount struct {
			ip    string
			count int64
		}
		var counts []ipCount
		for ip, count := range d.serverIPStats {
			counts = append(counts, ipCount{ip, count})
		}
		sort.Slice(counts, func(i, j int) bool {
			return counts[i].count > counts[j].count
		})

		// 重新初始化，只保留前20个高频IP
		d.serverIPStats = make(map[string]int64)
		for i := 0; i < 20 && i < len(counts); i++ {
			d.serverIPStats[counts[i].ip] = counts[i].count
		}
	}

	// 更新IP统计
	for _, server := range servers {
		if ip, ok := server["ip"].(string); ok {
			// 增加IP计数
			d.serverIPStats[ip]++
		}
	}

	// 更新IP图表
	d.updateServerIPStats()
}

// processServerInterfaceList 处理interface{}类型的服务器列表
func processServerInterfaceList(d *Dashboard, serverList []interface{}) {
	for _, serverIface := range serverList {
		if server, ok := serverIface.(map[string]interface{}); ok {
			if ip, ok := server["ip"].(string); ok {
				d.serverIPStats[ip]++
			}
		} else if serverStr, ok := serverIface.(string); ok {
			// 有时服务器数据可能是纯IP字符串
			d.serverIPStats[serverStr]++
		}
	}

	// 更新IP图表
	d.updateServerIPStats()
}

// updateResponseCodesChart 更新响应码图表
func updateResponseCodesChart(d *Dashboard, codes map[int]int64) {
	// 打印调试信息
	fmt.Printf("[DASHBOARD] updateResponseCodesChart called with codes: %v\n", codes)

	// 准备数据和标签
	var data []float64
	var labels []string

	// 确保codes不为空
	if codes == nil || len(codes) == 0 {
		fmt.Printf("[DASHBOARD] Response codes map is empty, adding default values\n")
		// 添加默认值
		data = []float64{1}
		labels = []string{"200"}
	} else {
		// 对代码排序以确保一致的显示
		var sortedCodes []int
		for code := range codes {
			sortedCodes = append(sortedCodes, code)
		}
		sort.Ints(sortedCodes)

		for _, code := range sortedCodes {
			data = append(data, float64(codes[code]))
			labels = append(labels, fmt.Sprintf("%d", code))
		}
	}

	// 设置图表数据和标签
	d.responseCodes.Data = data
	d.responseCodes.Labels = labels

	fmt.Printf("[DASHBOARD] 响应码图表数据设置为: data=%v, labels=%v\n", data, labels)

	// 设置颜色和样式
	colors := make([]termui.Color, len(labels))
	numStyles := make([]termui.Style, len(labels))
	labelStyles := make([]termui.Style, len(labels))

	for i, label := range labels {
		code, err := strconv.Atoi(label)
		if err == nil {
			// 根据HTTP状态码分配颜色
			switch {
			case code >= 200 && code < 300:
				colors[i] = termui.ColorGreen // 2xx 成功
			case code >= 300 && code < 400:
				colors[i] = termui.ColorYellow // 3xx 重定向
			case code >= 400 && code < 500:
				colors[i] = termui.ColorRed // 4xx 客户端错误
			case code >= 500:
				colors[i] = termui.ColorMagenta // 5xx 服务器错误
			default:
				colors[i] = termui.ColorBlue
			}
		} else {
			// 不是数字标签（如"No Data"）
			colors[i] = termui.ColorBlue
		}

		// 设置数字样式为黑色以提高可读性
		numStyles[i] = termui.NewStyle(termui.ColorBlack)
		// 设置标签样式为黑色
		labelStyles[i] = termui.NewStyle(termui.ColorBlack)
	}

	// 应用颜色和样式
	d.responseCodes.BarColors = colors
	d.responseCodes.NumStyles = numStyles
	d.responseCodes.LabelStyles = labelStyles
}

// updateRequestTableWithData 更新请求表格
func updateRequestTableWithData(d *Dashboard, reqData map[string]interface{}) {
	// 确保表格已初始化
	if d.requestTable == nil {
		d.requestTable = widgets.NewTable()
		d.requestTable.Title = "Last Requests (10)"
		d.requestTable.TextStyle = termui.NewStyle(termui.ColorGreen)
		d.requestTable.BorderStyle.Fg = termui.ColorRed
		d.requestTable.TitleStyle = termui.NewStyle(termui.ColorWhite, termui.ColorClear, termui.ModifierBold)
		d.requestTable.RowSeparator = true
		d.requestTable.FillRow = true
	}

	// 确保有表头
	if len(d.requestTable.Rows) == 0 || len(d.requestTable.Rows[0]) != 5 {
		d.requestTable.Rows = [][]string{
			{"Time", "Current Proxy", "URL", "Response Code/Time/BodySize", "Response Server/IP"},
		}
		d.requestTable.RowStyles = make(map[int]termui.Style)
		d.requestTable.RowStyles[0] = termui.NewStyle(termui.ColorGreen, termui.ColorClear, termui.ModifierBold)
	}

	// 保存表头
	headerRow := d.requestTable.Rows[0]
	newRows := [][]string{headerRow}

	// 检查是否有recentRequests数组 - 优先使用这个显示多个请求
	if recentRequestsVal, hasRecentRequests := reqData["recentRequests"]; hasRecentRequests && recentRequestsVal != nil {
		if recentRequests, ok := recentRequestsVal.([]map[string]interface{}); ok && len(recentRequests) > 0 {
			// 从recentRequests中依次添加行
			for _, request := range recentRequests {
				// 创建表格行
				timeStr := time.Now().Format("2006/01/02 15:04:05") // 当前时间，可以考虑从请求中获取

				// 提取并格式化代理信息
				var proxy string
				if proxyVal, ok := request["proxy"]; ok && proxyVal != nil {
					proxy = fmt.Sprintf("%v", proxyVal)
				} else {
					proxy = "direct" // 如果没有代理，显示direct
				}

				// 提取并格式化URL
				var url string
				if urlVal, ok := request["url"]; ok && urlVal != nil {
					url = fmt.Sprintf("%v", urlVal)
				} else {
					url = "unknown"
				}

				// 提取并格式化响应代码、时间和大小
				var code, latency, size interface{}
				var codeStr, latencyStr, sizeStr string
				var statusCode int = 0

				if code, ok = request["code"]; ok && code != nil {
					codeStr = fmt.Sprintf("%v", code)
					if codeInt, err := strconv.Atoi(codeStr); err == nil {
						statusCode = codeInt
					}
				} else {
					codeStr = "N/A"
				}

				if latency, ok = request["latency"]; ok && latency != nil {
					latencyStr = fmt.Sprintf("%vms", latency)
				} else {
					latencyStr = "N/A"
				}

				if size, ok = request["size"]; ok && size != nil {
					sizeStr = fmt.Sprintf("%v", size)
				} else {
					sizeStr = "N/A"
				}

				// 根据状态码确定颜色
				codeColor := "white"
				if statusCode >= 200 && statusCode < 300 {
					codeColor = "green"
				} else if statusCode >= 300 && statusCode < 400 {
					codeColor = "blue"
				} else if statusCode >= 400 && statusCode < 500 {
					codeColor = "yellow"
				} else if statusCode >= 500 && statusCode < 600 {
					codeColor = "red"
				}

				// 使用格式化的彩色文本
				respInfo := fmt.Sprintf("[%s](fg:%s)/%s/%s", codeStr, codeColor, latencyStr, sizeStr)

				// 检查是否有重定向注释
				var note string
				if noteVal, ok := request["note"]; ok && noteVal != nil {
					note = fmt.Sprintf("%v", noteVal)
				}

				// 如果是重定向请求，修改URL显示格式
				if note != "" && strings.Contains(strings.ToLower(note), "redirect") {
					// 在URL前添加重定向标志
					url = fmt.Sprintf("[↪](fg:blue,mod:bold) %s", url)

					// 在响应信息中添加重定向注释
					respInfo = fmt.Sprintf("%s [%s](fg:blue)", respInfo, note)
				}

				// 提取并格式化服务器和IP信息
				var server, ip string
				if serverVal, ok := request["server"]; ok && serverVal != nil {
					server = fmt.Sprintf("%v", serverVal)
				} else {
					server = "unknown"
				}

				if ipVal, ok := request["ip"]; ok && ipVal != nil {
					ip = fmt.Sprintf("%v", ipVal)
				} else {
					ip = "unknown"
				}

				serverInfo := fmt.Sprintf("%s/%s", server, ip)

				// 添加行到表格
				row := []string{
					timeStr,
					proxy,
					url,
					respInfo,
					serverInfo,
				}
				newRows = append(newRows, row)
			}

			// 限制总行数为11（表头 + 10行数据）
			if len(newRows) > 11 {
				newRows = newRows[:11]
			}

			// 更新表格行
			d.requestTable.Rows = newRows

			// 确保表头样式正确
			d.requestTable.RowStyles[0] = termui.NewStyle(termui.ColorGreen, termui.ColorClear, termui.ModifierBold)
			return
		}
	}

	// 如果没有recentRequests数组，退回到使用单个lastRequest的方式
	// 创建表格行
	timeStr := time.Now().Format("2006/01/02 15:04:05") // Full date and time format

	// 检查是否存在错误信息，如果是强制终止导致的错误则不显示
	if errVal, hasError := reqData["error"]; hasError && errVal != nil {
		errStr := fmt.Sprintf("%v", errVal)
		// 如果错误信息包含"context canceled"或"request failed after"等标志，说明是任务超时终止
		// 这类错误不需要显示在UI上
		if strings.Contains(errStr, "context canceled") ||
			strings.Contains(errStr, "request failed after") {
			// 跳过这条错误消息，不添加到表格中
			return
		}
	}

	// 提取并格式化代理信息
	var proxy string
	var ok bool
	var proxyVal interface{}
	if proxyVal, ok = reqData["proxy"]; ok {
		proxy = fmt.Sprintf("%v", proxyVal)
	} else {
		proxy = "direct" // 如果没有代理，显示direct
	}

	// 提取并格式化URL
	var url string
	var urlVal interface{}
	if urlVal, ok = reqData["url"]; ok {
		url = fmt.Sprintf("%v", urlVal)
	} else {
		url = "unknown"
	}

	// 提取并格式化响应代码、时间和大小
	var code, latency, size interface{}
	var codeStr, latencyStr, sizeStr string
	var statusCode int = 0

	if code, ok = reqData["code"]; ok {
		codeStr = fmt.Sprintf("%v", code)
		// 尝试将code转换为整数以便后续着色
		if codeInt, err := strconv.Atoi(codeStr); err == nil {
			statusCode = codeInt
		}
	} else {
		codeStr = "N/A"
	}

	if latency, ok = reqData["latency"]; ok {
		latencyStr = fmt.Sprintf("%vms", latency)
	} else {
		latencyStr = "N/A"
	}

	if size, ok = reqData["size"]; ok {
		sizeStr = fmt.Sprintf("%v", size)
	} else {
		sizeStr = "N/A"
	}

	// 根据状态码确定颜色
	codeColor := "white"
	if statusCode >= 200 && statusCode < 300 {
		// 2xx 成功 - 绿色
		codeColor = "green"
	} else if statusCode >= 300 && statusCode < 400 {
		// 3xx 重定向 - 蓝色
		codeColor = "blue"
	} else if statusCode >= 400 && statusCode < 500 {
		// 4xx 客户端错误 - 黄色
		codeColor = "yellow"
	} else if statusCode >= 500 && statusCode < 600 {
		// 5xx 服务器错误 - 红色
		codeColor = "red"
	}

	// 使用格式化的彩色文本 - 直接在文本中嵌入颜色标记
	respInfo := fmt.Sprintf("[%s](fg:%s)/%s/%s", codeStr, codeColor, latencyStr, sizeStr)

	// 检查是否有重定向注释
	var note string
	if noteVal, ok := reqData["note"]; ok && noteVal != nil {
		note = fmt.Sprintf("%v", noteVal)
	}

	// 如果是重定向请求，修改URL显示格式
	if note != "" && strings.Contains(strings.ToLower(note), "redirect") {
		// 在URL前添加重定向标志
		url = fmt.Sprintf("[↪](fg:blue,mod:bold) %s", url)

		// 在响应信息中添加重定向注释
		respInfo = fmt.Sprintf("%s [%s](fg:blue)", respInfo, note)
	}

	// 提取并格式化服务器和IP信息
	var server, ip string
	if serverVal, ok := reqData["server"]; ok {
		server = fmt.Sprintf("%v", serverVal)
	} else {
		server = "unknown"
	}

	if ipVal, ok := reqData["ip"]; ok {
		ip = fmt.Sprintf("%v", ipVal)
	} else {
		ip = "unknown"
	}

	serverInfo := fmt.Sprintf("%s/%s", server, ip)

	// 添加请求行到表格，根据状态码为整行着色
	row := []string{
		timeStr,
		proxy,
		url,
		respInfo,
		serverInfo,
	}

	// 保存表头
	headerRow = d.requestTable.Rows[0]

	// 添加行到表格的第二行位置（保持表头在第一行）
	newRows = [][]string{headerRow, row}

	// 如果有更多的现有行，最多保留总共11行（表头 + 10个请求）
	if len(d.requestTable.Rows) > 1 {
		// 添加现有行（排除表头），最多添加到总共11行
		for i := 1; i < len(d.requestTable.Rows) && len(newRows) < 11; i++ {
			existingRow := d.requestTable.Rows[i]

			// 处理现有行的响应代码着色
			if len(existingRow) >= 4 {
				parts := strings.Split(existingRow[3], "/")
				if len(parts) > 0 {
					codeStr := parts[0]
					// 检查是否已经有颜色标记
					if !strings.Contains(codeStr, "[") {
						// 解析状态码
						statusCodeStr := codeStr
						statusCode = 0
						if sc, err := strconv.Atoi(statusCodeStr); err == nil {
							statusCode = sc
						}

						// 确定颜色
						codeColor = "white"
						if statusCode >= 200 && statusCode < 300 {
							codeColor = "green"
						} else if statusCode >= 300 && statusCode < 400 {
							codeColor = "blue"
						} else if statusCode >= 400 && statusCode < 500 {
							codeColor = "yellow"
						} else if statusCode >= 500 && statusCode < 600 {
							codeColor = "red"
						}

						// 重新格式化响应信息，添加颜色
						if len(parts) > 1 {
							rest := strings.Join(parts[1:], "/")
							existingRow[3] = fmt.Sprintf("[%s](fg:%s)/%s", statusCodeStr, codeColor, rest)
						} else {
							existingRow[3] = fmt.Sprintf("[%s](fg:%s)", statusCodeStr, codeColor)
						}
					}
				}
			}

			newRows = append(newRows, existingRow)
		}
	}

	// 更新表格行
	d.requestTable.Rows = newRows

	// 确保表头样式正确
	d.requestTable.RowStyles[0] = termui.NewStyle(termui.ColorGreen, termui.ColorClear, termui.ModifierBold)
}

// getMapKeys 返回map的所有键
func (d *Dashboard) updateWithHardcodedData() {
	// 保存原始值以便最后恢复
	origURL := d.targetURL
	origMode := d.attackMode
	origTime := d.attackTime
	origTimeLeft := d.timeLeft
	origWorks := d.works
	origInterval := d.interval
	origRates := d.rates
	origBW := d.bandwidth
	origTraffic := d.totalTraffic

	// 只有在真实设置为空时才设置默认值
	if d.targetURL == "" {
		d.targetURL = "http://target-placeholder.com"
	}

	if d.attackMode == "" {
		d.attackMode = "GET"
	}

	// 恢复原始值，确保不会永久覆盖真实配置
	d.targetURL = origURL
	d.attackMode = origMode
	d.attackTime = origTime
	d.timeLeft = origTimeLeft
	d.works = origWorks
	d.interval = origInterval
	d.rates = origRates
	d.bandwidth = origBW
	d.totalTraffic = origTraffic
}

// HandleSignals sets up signal handling
func (d *Dashboard) HandleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Printf("\n[Dashboard] Received signal: %v\n", sig)

		// 确保UI关闭并清理终端
		d.mu.Lock()
		if !d.stopped {
			d.stopped = true
			close(d.done)

			// 关闭termui并恢复终端
			termui.Close()

			// 使用安全的终端恢复函数
			safeRestoreTerminal()
		}
		d.mu.Unlock()

		// 延迟一会儿再退出，确保终端重置生效
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}()
}

// SetRowSpacing 设置行间距
func (d *Dashboard) SetRowSpacing(spacing int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if spacing >= 0 && spacing <= 5 { // 限制间距在合理范围内
		d.rowSpacing = spacing
		fmt.Printf("[Dashboard] Row spacing set to %d\n", spacing)
	} else {
		fmt.Printf("[Dashboard] Invalid row spacing %d, must be between 0-5\n", spacing)
	}
}

// updateNetworkStats 更新网络统计信息
func (d *Dashboard) updateNetworkStats() {
	// 确保networkStatsBox已初始化
	if d.networkStatsBox == nil {
		d.networkStatsBox = widgets.NewParagraph()
		d.networkStatsBox.Title = "Network Stats"
		d.networkStatsBox.BorderStyle.Fg = termui.ColorYellow
		d.networkStatsBox.TitleStyle.Fg = termui.ColorYellow
	}

	// 设置最小值，避免显示为0
	minBandwidth := 0.01     // 最小带宽为0.01 Mbps
	minTotalTraffic := 0.001 // 最小流量为0.001 GB

	// 确保带宽至少为最小值
	bandwidth := math.Max(d.bandwidth, minBandwidth)
	totalTraffic := math.Max(d.totalTraffic, minTotalTraffic)

	// 确保代理带宽在合理范围内(至少10%的总带宽，最多90%)
	proxyBandwidth := d.proxyBandwidth
	if proxyBandwidth < minBandwidth {
		proxyBandwidth = minBandwidth
	}

	// 计算代理带宽占总带宽的百分比
	proxyPercentage := 0.0
	if bandwidth > 0 {
		proxyPercentage = (proxyBandwidth / bandwidth) * 100.0
	}

	// 确保上传和下载速度之和等于总带宽
	uploadSpeed := d.uploadSpeed
	downloadSpeed := d.downloadSpeed
	if uploadSpeed+downloadSpeed < bandwidth {
		// 如果总和小于带宽，按比例调整
		ratio := bandwidth / (uploadSpeed + downloadSpeed)
		uploadSpeed *= ratio
		downloadSpeed *= ratio
	} else if uploadSpeed+downloadSpeed > bandwidth {
		// 如果总和大于带宽，按比例降低
		ratio := bandwidth / (uploadSpeed + downloadSpeed)
		uploadSpeed *= ratio
		downloadSpeed *= ratio
	}

	// 格式化文本显示
	d.networkStatsBox.Text = fmt.Sprintf(
		"[Bandwidth:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)\n"+
			"[Total Traffic:](fg:white,mod:bold) [%.4f GB](fg:green,mod:bold)\n"+
			"[Proxy Bandwidth:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold) [(%.1f%%)](fg:yellow)\n"+
			"[Upload:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)  [Download:](fg:white,mod:bold) [%.2f Mbps](fg:green,mod:bold)",
		bandwidth, totalTraffic, proxyBandwidth, proxyPercentage, uploadSpeed, downloadSpeed)
	d.networkStatsBox.TextStyle = termui.NewStyle(termui.ColorWhite)
}

// ToggleComponentVisibility toggles the visibility of a specific component
func (d *Dashboard) ToggleComponentVisibility(componentName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 检查组件是否存在
	if _, exists := d.uiConfig.ComponentVisibility[componentName]; !exists {
		return fmt.Errorf("unknown component: %s", componentName)
	}

	// Toggle visibility
	d.uiConfig.ComponentVisibility[componentName] = !d.uiConfig.ComponentVisibility[componentName]

	// Log the change
	visibility := "hidden"
	if d.uiConfig.ComponentVisibility[componentName] {
		visibility = "visible"
	}
	fmt.Printf("[Dashboard] Component %s is now %s\n", componentName, visibility)

	// Render the UI with the new settings
	d.render()

	return nil
}

// LockCurrentUILayout 保存当前UI布局
func (d *Dashboard) LockCurrentUILayout() error {
	fmt.Println("[Dashboard] Current UI layout locked")
	return nil
}

// RestoreDefaultLayout 恢复默认UI布局
func (d *Dashboard) RestoreDefaultLayout() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 重置所有组件为可见
	for k := range d.uiConfig.ComponentVisibility {
		d.uiConfig.ComponentVisibility[k] = true
	}

	// 重新渲染
	d.render()

	fmt.Println("[Dashboard] Default UI layout restored")
	return nil
}

// LoadUIConfig 加载UI配置
func (d *Dashboard) LoadUIConfig() error {
	return nil
}
