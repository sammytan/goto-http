// WebSocket连接
let ws = null;
let charts = {};

// 初始化WebSocket连接
function initWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}/api/ws`);
    
    ws.onopen = () => {
        console.log('WebSocket连接已建立');
        updateStatus('已连接');
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateDashboard(data);
    };

    ws.onclose = () => {
        console.log('WebSocket连接已关闭');
        updateStatus('已断开');
        // 尝试重新连接
        setTimeout(initWebSocket, 5000);
    };

    ws.onerror = (error) => {
        console.error('WebSocket错误:', error);
        updateStatus('连接错误');
    };
}

// 更新仪表盘数据
function updateDashboard(data) {
    // 更新请求统计
    document.getElementById('total-requests').textContent = data.totalRequests;
    updateChart('request-chart', data.requestHistory);

    // 更新成功率
    const successRate = (data.successRate * 100).toFixed(2);
    document.getElementById('success-rate').textContent = `${successRate}%`;
    updateChart('success-chart', data.successHistory);

    // 更新延迟统计
    document.getElementById('avg-latency').textContent = `${data.avgLatency}ms`;
    updateChart('latency-chart', data.latencyHistory);

    // 更新错误率
    const errorRate = (data.errorRate * 100).toFixed(2);
    document.getElementById('error-rate').textContent = `${errorRate}%`;
    updateChart('error-chart', data.errorHistory);

    // 更新代理状态
    updateProxyList(data.proxies);

    // 更新攻击日志
    updateLogs(data.logs);
}

// 更新图表
function updateChart(chartId, data) {
    if (!charts[chartId]) {
        // 初始化图表
        charts[chartId] = new Chart(chartId, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: '#4CAF50',
                    fill: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'second'
                        }
                    }
                }
            }
        });
    }

    // 更新图表数据
    charts[chartId].data.labels = data.map(d => d.time);
    charts[chartId].data.datasets[0].data = data.map(d => d.value);
    charts[chartId].update();
}

// 更新代理列表
function updateProxyList(proxies) {
    const proxyList = document.getElementById('proxy-list');
    proxyList.innerHTML = '';

    proxies.forEach(proxy => {
        const proxyElement = document.createElement('div');
        proxyElement.className = `proxy-item ${proxy.status}`;
        proxyElement.innerHTML = `
            <span class="proxy-address">${proxy.address}</span>
            <span class="proxy-status">${proxy.status}</span>
            <span class="proxy-latency">${proxy.latency}ms</span>
        `;
        proxyList.appendChild(proxyElement);
    });
}

// 更新日志
function updateLogs(logs) {
    const logContainer = document.getElementById('log-container');
    
    logs.forEach(log => {
        const logElement = document.createElement('div');
        logElement.className = `log-item ${log.level}`;
        logElement.innerHTML = `
            <span class="log-time">${new Date(log.time).toLocaleTimeString()}</span>
            <span class="log-level">${log.level}</span>
            <span class="log-message">${log.message}</span>
        `;
        logContainer.appendChild(logElement);
    });

    // 保持滚动到最新的日志
    logContainer.scrollTop = logContainer.scrollHeight;

    // 限制日志数量
    while (logContainer.children.length > 100) {
        logContainer.removeChild(logContainer.firstChild);
    }
}

// 更新状态
function updateStatus(status) {
    const statusElement = document.createElement('div');
    statusElement.className = `status-message ${status.toLowerCase()}`;
    statusElement.textContent = status;
    
    const container = document.querySelector('.container');
    container.insertBefore(statusElement, container.firstChild);

    // 3秒后移除状态消息
    setTimeout(() => {
        statusElement.remove();
    }, 3000);
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
}); 