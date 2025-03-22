package useragent

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UAType User-Agent类型
type UAType string

const (
	CN_MOBILE     UAType = "cn_mobile"     // 中国手机UA
	CN_APP        UAType = "cn_app"        // 中国手机APP UA
	GLOBAL_MOBILE UAType = "global_mobile" // 全球主流手机UA
	PC            UAType = "pc"            // PC浏览器UA
	SEARCH_ENGINE UAType = "search_engine" // 搜索引擎UA
	RANDOM        UAType = "random"        // 随机选择UA
	CUSTOM        UAType = "custom"        // 自定义UA文件
)

// Manager User-Agent管理器
type Manager struct {
	mu          sync.RWMutex
	uaMap       map[UAType][]string
	customFile  string
	currentType UAType
}

// NewManager 创建User-Agent管理器
func NewManager(uaType UAType, customFile string) (*Manager, error) {
	m := &Manager{
		uaMap:       make(map[UAType][]string),
		customFile:  customFile,
		currentType: uaType,
	}

	// 初始化随机数生成器
	rand.Seed(time.Now().UnixNano())

	// 如果是自定义UA文件
	if uaType == CUSTOM && customFile != "" {
		if err := m.loadFromFile(customFile); err != nil {
			return nil, err
		}
		return m, nil
	}

	// 加载内置UA文件
	if err := m.loadBuiltinUA(); err != nil {
		return nil, err
	}

	return m, nil
}

// loadBuiltinUA 加载内置UA文件
func (m *Manager) loadBuiltinUA() error {
	baseDir := "configs/useragents"
	files := map[UAType]string{
		CN_MOBILE:     filepath.Join(baseDir, "cn_mobile.txt"),
		CN_APP:        filepath.Join(baseDir, "cn_app.txt"),
		GLOBAL_MOBILE: filepath.Join(baseDir, "global_mobile.txt"),
		PC:            filepath.Join(baseDir, "pc.txt"),
		SEARCH_ENGINE: filepath.Join(baseDir, "search_engine.txt"),
	}

	for uaType, file := range files {
		if err := m.loadFromFile(file); err != nil {
			return fmt.Errorf("failed to load %s UA file: %v", uaType, err)
		}
	}

	return nil
}

// loadFromFile 从文件加载UA
func (m *Manager) loadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var uas []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		uas = append(uas, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	if m.currentType == CUSTOM {
		m.uaMap[CUSTOM] = uas
	} else {
		uaType := UAType(strings.TrimSuffix(filepath.Base(filename), ".txt"))
		m.uaMap[uaType] = uas
	}
	m.mu.Unlock()

	return nil
}

// GetUA 获取User-Agent
func (m *Manager) GetUA() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.currentType == RANDOM {
		// 随机选择一个UA类型
		var allUAs []string
		for _, uas := range m.uaMap {
			allUAs = append(allUAs, uas...)
		}
		if len(allUAs) == 0 {
			return ""
		}
		return allUAs[rand.Intn(len(allUAs))]
	}

	uas := m.uaMap[m.currentType]
	if len(uas) == 0 {
		return ""
	}
	return uas[rand.Intn(len(uas))]
}

// SetType 设置UA类型
func (m *Manager) SetType(uaType UAType) {
	m.mu.Lock()
	m.currentType = uaType
	m.mu.Unlock()
}

// GetTypes 获取所有可用的UA类型
func (m *Manager) GetTypes() []UAType {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var types []UAType
	for uaType := range m.uaMap {
		types = append(types, uaType)
	}
	return types
}

// Count 获取指定类型的UA数量
func (m *Manager) Count(uaType UAType) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.uaMap[uaType])
}
