/**
 * Omegle Admin Panel JavaScript
 * Complete functionality for admin dashboard
 */

class AdminPanel {
    constructor() {
        this.baseURL = '/admin/api';
        this.token = localStorage.getItem('admin_token');
        this.currentSection = 'dashboard';
        this.charts = {};
        this.realTimeInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthentication();
        this.initializeCharts();
        this.startRealTimeUpdates();
    }

    // ==============================================
    // Authentication Methods
    // ==============================================

    checkAuthentication() {
        if (!this.token) {
            this.showLogin();
            return;
        }

        // Verify token
        this.verifyToken().then(valid => {
            if (valid) {
                this.showAdminPanel();
                this.loadDashboard();
            } else {
                this.showLogin();
            }
        });
    }

    async verifyToken() {
        try {
            const response = await this.apiCall('GET', '/auth/verify');
            return response.success;
        } catch (error) {
            return false;
        }
    }

    showLogin() {
        document.getElementById('loadingScreen').style.display = 'none';
        document.getElementById('loginModal').style.display = 'flex';
        document.getElementById('adminContainer').style.display = 'none';
    }

    showAdminPanel() {
        document.getElementById('loadingScreen').style.display = 'none';
        document.getElementById('loginModal').style.display = 'none';
        document.getElementById('adminContainer').style.display = 'flex';
    }

    async login(username, password) {
        try {
            const response = await fetch('/admin/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (result.success) {
                this.token = result.data.token;
                localStorage.setItem('admin_token', this.token);
                this.showAdminPanel();
                this.loadDashboard();
                this.showNotification('Login successful!', 'success');
            } else {
                this.showNotification(result.message || 'Login failed', 'error');
            }
        } catch (error) {
            this.showNotification('Login error: ' + error.message, 'error');
        }
    }

    logout() {
        localStorage.removeItem('admin_token');
        this.token = null;
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
        }
        this.showLogin();
        this.showNotification('Logged out successfully', 'info');
    }

    // ==============================================
    // API Methods
    // ==============================================

    async apiCall(method, endpoint, data = null) {
        const url = this.baseURL + endpoint;
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, options);
            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.message || 'API call failed');
            }

            return result;
        } catch (error) {
            console.error('API Error:', error);
            if (error.message.includes('unauthorized') || error.message.includes('401')) {
                this.logout();
            }
            throw error;
        }
    }

    // ==============================================
    // Event Listeners
    // ==============================================

    setupEventListeners() {
        // Login form
        document.getElementById('loginForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            this.login(username, password);
        });

        // Sidebar toggle
        document.getElementById('sidebarToggle').addEventListener('click', () => {
            this.toggleSidebar();
        });

        // Navigation links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                const section = e.target.closest('.nav-link').dataset.section;
                this.navigateToSection(section);
            });
        });

        // Chart period selector
        const chartPeriod = document.getElementById('chartPeriod');
        if (chartPeriod) {
            chartPeriod.addEventListener('change', () => {
                this.updateUserActivityChart();
            });
        }

        // User filters
        const userSearch = document.getElementById('userSearch');
        if (userSearch) {
            userSearch.addEventListener('input', () => {
                this.filterUsers();
            });
        }

        // Form submissions
        this.setupFormSubmissions();
    }

    setupFormSubmissions() {
        // App settings form
        const appSettingsForm = document.getElementById('appSettingsForm');
        if (appSettingsForm) {
            appSettingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveAppSettings();
            });
        }

        // Moderation settings form
        const moderationForm = document.getElementById('moderationSettingsForm');
        if (moderationForm) {
            moderationForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveModerationSettings();
            });
        }
    }

    // ==============================================
    // Navigation
    // ==============================================

    navigateToSection(section) {
        // Update active nav link
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-section="${section}"]`).classList.add('active');

        // Update page title
        const titles = {
            dashboard: 'Dashboard',
            users: 'User Management',
            chats: 'Chat Monitoring',
            reports: 'Reports & Moderation',
            content: 'Content Management',
            analytics: 'Analytics',
            coturn: 'COTURN Servers',
            settings: 'Settings',
            system: 'System'
        };
        document.getElementById('pageTitle').textContent = titles[section] || 'Admin Panel';

        // Show/hide sections
        document.querySelectorAll('.content-section').forEach(sect => {
            sect.classList.remove('active');
        });
        document.getElementById(section).classList.add('active');

        this.currentSection = section;

        // Load section data
        this.loadSectionData(section);
    }

    async loadSectionData(section) {
        switch (section) {
            case 'dashboard':
                await this.loadDashboard();
                break;
            case 'users':
                await this.loadUsers();
                break;
            case 'chats':
                await this.loadChats();
                break;
            case 'reports':
                await this.loadReports();
                break;
            case 'content':
                await this.loadContent();
                break;
            case 'analytics':
                await this.loadAnalytics();
                break;
            case 'coturn':
                await this.loadCoturnServers();
                break;
            case 'settings':
                await this.loadSettings();
                break;
            case 'system':
                await this.loadSystemInfo();
                break;
        }
    }

    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const mainContent = document.getElementById('mainContent');
        
        sidebar.classList.toggle('collapsed');
        mainContent.classList.toggle('expanded');
    }

    // ==============================================
    // Dashboard Methods
    // ==============================================

    async loadDashboard() {
        try {
            // Load dashboard stats
            const stats = await this.apiCall('GET', '/dashboard/stats');
            this.updateDashboardStats(stats.data);

            // Load chart data
            await this.updateUserActivityChart();
            await this.updateRegionChart();

            // Load recent activities
            await this.loadRecentActivities();

            // Load system alerts
            await this.loadSystemAlerts();

        } catch (error) {
            this.showNotification('Failed to load dashboard: ' + error.message, 'error');
        }
    }

    updateDashboardStats(stats) {
        // Update header stats
        document.getElementById('onlineUsers').textContent = stats.online_users || 0;
        document.getElementById('activeChats').textContent = stats.active_chats || 0;
        document.getElementById('totalUsers').textContent = stats.total_users || 0;

        // Update dashboard cards
        document.getElementById('dashTotalUsers').textContent = stats.total_users || 0;
        document.getElementById('dashOnlineUsers').textContent = stats.online_users || 0;
        document.getElementById('dashActiveChats').textContent = stats.active_chats || 0;
        document.getElementById('dashTotalChats').textContent = stats.total_chats_today || 0;

        // Update growth percentages
        document.getElementById('userGrowth').textContent = `+${stats.user_growth || 0}%`;
        document.getElementById('chatGrowth').textContent = `+${stats.chat_growth || 0}%`;
    }

    async loadRecentActivities() {
        try {
            const activities = await this.apiCall('GET', '/dashboard/activities');
            const container = document.getElementById('recentActivities');
            
            if (!activities.data || activities.data.length === 0) {
                container.innerHTML = '<p>No recent activities</p>';
                return;
            }

            container.innerHTML = activities.data.map(activity => `
                <div class="activity-item">
                    <div class="activity-icon">
                        <i class="fas fa-${this.getActivityIcon(activity.type)}"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${activity.description}</div>
                        <div class="activity-time">${this.formatTime(activity.timestamp)}</div>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Failed to load activities:', error);
        }
    }

    async loadSystemAlerts() {
        try {
            const alerts = await this.apiCall('GET', '/dashboard/alerts');
            const container = document.getElementById('systemAlerts');
            
            if (!alerts.data || alerts.data.length === 0) {
                container.innerHTML = '<p>No system alerts</p>';
                return;
            }

            container.innerHTML = alerts.data.map(alert => `
                <div class="alert-item">
                    <div class="alert-icon">
                        <i class="fas fa-${this.getAlertIcon(alert.level)}"></i>
                    </div>
                    <div class="alert-content">
                        <div class="alert-title">${alert.title}</div>
                        <div class="alert-time">${this.formatTime(alert.timestamp)}</div>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Failed to load alerts:', error);
        }
    }

    // ==============================================
    // Chart Methods
    // ==============================================

    initializeCharts() {
        // Initialize empty charts that will be populated later
        this.initUserActivityChart();
        this.initRegionChart();
        this.initChatAnalyticsChart();
        this.initUserGrowthChart();
    }

    initUserActivityChart() {
        const ctx = document.getElementById('userActivityChart');
        if (!ctx) return;

        this.charts.userActivity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Active Users',
                    data: [],
                    borderColor: 'rgb(102, 126, 234)',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'white'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'white'
                        }
                    }
                }
            }
        });
    }

    initRegionChart() {
        const ctx = document.getElementById('regionChart');
        if (!ctx) return;

        this.charts.region = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#667eea',
                        '#f093fb',
                        '#4caf50',
                        '#ff9800',
                        '#f44336',
                        '#2196f3'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'white',
                            padding: 20
                        }
                    }
                }
            }
        });
    }

    initChatAnalyticsChart() {
        const ctx = document.getElementById('chatAnalyticsChart');
        if (!ctx) return;

        this.charts.chatAnalytics = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Text', 'Video', 'Audio'],
                datasets: [{
                    label: 'Chat Types',
                    data: [],
                    backgroundColor: ['#667eea', '#f093fb', '#4caf50']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: 'white'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: 'white'
                        }
                    },
                    x: {
                        ticks: {
                            color: 'white'
                        }
                    }
                }
            }
        });
    }

    initUserGrowthChart() {
        const ctx = document.getElementById('userGrowthChart');
        if (!ctx) return;

        this.charts.userGrowth = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'User Growth',
                    data: [],
                    borderColor: '#4caf50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: 'white'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: 'white'
                        }
                    },
                    x: {
                        ticks: {
                            color: 'white'
                        }
                    }
                }
            }
        });
    }

    async updateUserActivityChart() {
        try {
            const period = document.getElementById('chartPeriod')?.value || 7;
            const data = await this.apiCall('GET', `/dashboard/chart/users?period=${period}`);
            
            if (this.charts.userActivity && data.data) {
                this.charts.userActivity.data.labels = data.data.labels;
                this.charts.userActivity.data.datasets[0].data = data.data.values;
                this.charts.userActivity.update();
            }
        } catch (error) {
            console.error('Failed to update user activity chart:', error);
        }
    }

    async updateRegionChart() {
        try {
            const data = await this.apiCall('GET', '/dashboard/chart/regions');
            
            if (this.charts.region && data.data) {
                this.charts.region.data.labels = data.data.labels;
                this.charts.region.data.datasets[0].data = data.data.values;
                this.charts.region.update();
            }
        } catch (error) {
            console.error('Failed to update region chart:', error);
        }
    }

    // ==============================================
    // User Management Methods
    // ==============================================

    async loadUsers(page = 1, limit = 50) {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: limit.toString()
            });

            // Add filters
            const search = document.getElementById('userSearch')?.value;
            const region = document.getElementById('userRegionFilter')?.value;
            const status = document.getElementById('userStatusFilter')?.value;

            if (search) params.append('search', search);
            if (region) params.append('region', region);
            if (status) params.append('status', status);

            const response = await this.apiCall('GET', `/users?${params}`);
            this.renderUsersTable(response.data, response.meta);
        } catch (error) {
            this.showNotification('Failed to load users: ' + error.message, 'error');
        }
    }

    renderUsersTable(users, meta) {
        const tbody = document.getElementById('usersTableBody');
        
        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center">No users found</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => `
            <tr>
                <td><input type="checkbox" class="user-checkbox" value="${user.id}"></td>
                <td>${user.id.substring(0, 8)}...</td>
                <td>${user.session_id.substring(0, 12)}...</td>
                <td>${user.region || 'Unknown'}</td>
                <td>${user.language || 'Unknown'}</td>
                <td>
                    <span class="badge ${user.is_online ? 'badge-success' : 'badge-secondary'}">
                        ${user.is_online ? 'Online' : 'Offline'}
                    </span>
                    ${user.is_banned ? '<span class="badge badge-danger">Banned</span>' : ''}
                </td>
                <td>${this.formatDate(user.created_at)}</td>
                <td>${this.formatDate(user.last_seen)}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="adminPanel.viewUser('${user.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    ${!user.is_banned ? 
                        `<button class="btn btn-sm btn-warning" onclick="adminPanel.banUser('${user.id}')">
                            <i class="fas fa-ban"></i>
                        </button>` :
                        `<button class="btn btn-sm btn-success" onclick="adminPanel.unbanUser('${user.id}')">
                            <i class="fas fa-check"></i>
                        </button>`
                    }
                    <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteUser('${user.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');

        this.renderPagination('usersPagination', meta);
    }

    async viewUser(userId) {
        try {
            const user = await this.apiCall('GET', `/users/${userId}`);
            const activity = await this.apiCall('GET', `/users/${userId}/activity`);
            
            this.showModal('User Details', `
                <div class="user-details">
                    <h4>User Information</h4>
                    <p><strong>ID:</strong> ${user.data.id}</p>
                    <p><strong>Session ID:</strong> ${user.data.session_id}</p>
                    <p><strong>IP Address:</strong> ${user.data.ip_address}</p>
                    <p><strong>Region:</strong> ${user.data.region}</p>
                    <p><strong>Language:</strong> ${user.data.language}</p>
                    <p><strong>Status:</strong> ${user.data.is_online ? 'Online' : 'Offline'}</p>
                    <p><strong>Created:</strong> ${this.formatDate(user.data.created_at)}</p>
                    <p><strong>Last Seen:</strong> ${this.formatDate(user.data.last_seen)}</p>
                    
                    <h4 class="mt-4">Recent Activity</h4>
                    <div class="activity-log">
                        ${activity.data.map(act => `
                            <div class="activity-entry">
                                <strong>${act.action}</strong> - ${this.formatDate(act.timestamp)}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `);
        } catch (error) {
            this.showNotification('Failed to load user details: ' + error.message, 'error');
        }
    }

    async banUser(userId) {
        if (!confirm('Are you sure you want to ban this user?')) return;

        try {
            await this.apiCall('POST', `/users/${userId}/ban`, {
                reason: 'Banned by admin',
                duration: null // Permanent ban
            });
            this.showNotification('User banned successfully', 'success');
            this.loadUsers();
        } catch (error) {
            this.showNotification('Failed to ban user: ' + error.message, 'error');
        }
    }

    async unbanUser(userId) {
        try {
            await this.apiCall('DELETE', `/users/${userId}/ban`);
            this.showNotification('User unbanned successfully', 'success');
            this.loadUsers();
        } catch (error) {
            this.showNotification('Failed to unban user: ' + error.message, 'error');
        }
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

        try {
            await this.apiCall('DELETE', `/users/${userId}`);
            this.showNotification('User deleted successfully', 'success');
            this.loadUsers();
        } catch (error) {
            this.showNotification('Failed to delete user: ' + error.message, 'error');
        }
    }

    async exportUsers() {
        try {
            const response = await fetch(`${this.baseURL}/users/export`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `users_export_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);
            
            this.showNotification('Users exported successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to export users: ' + error.message, 'error');
        }
    }

    filterUsers() {
        // Debounce the search
        clearTimeout(this.searchTimeout);
        this.searchTimeout = setTimeout(() => {
            this.loadUsers();
        }, 500);
    }

    // ==============================================
    // Chat Monitoring Methods
    // ==============================================

    async loadChats() {
        try {
            const response = await this.apiCall('GET', '/chats');
            this.renderChatsTable(response.data);
        } catch (error) {
            this.showNotification('Failed to load chats: ' + error.message, 'error');
        }
    }

    renderChatsTable(chats) {
        const tbody = document.getElementById('chatsTableBody');
        
        if (!chats || chats.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No chats found</td></tr>';
            return;
        }

        tbody.innerHTML = chats.map(chat => `
            <tr>
                <td>${chat.room_id}</td>
                <td>
                    <span class="badge badge-info">${chat.chat_type}</span>
                </td>
                <td>${chat.user_count || 2}</td>
                <td>
                    <span class="badge ${this.getStatusBadgeClass(chat.status)}">
                        ${chat.status}
                    </span>
                </td>
                <td>${this.formatDuration(chat.duration)}</td>
                <td>${chat.message_count || 0}</td>
                <td>${this.formatDate(chat.started_at)}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="adminPanel.viewChat('${chat.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    ${chat.status === 'active' ? 
                        `<button class="btn btn-sm btn-warning" onclick="adminPanel.endChat('${chat.id}')">
                            <i class="fas fa-stop"></i>
                        </button>` : ''
                    }
                    <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteChat('${chat.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    async viewChat(chatId) {
        try {
            const chat = await this.apiCall('GET', `/chats/${chatId}`);
            
            this.showModal('Chat Details', `
                <div class="chat-details">
                    <h4>Chat Information</h4>
                    <p><strong>Room ID:</strong> ${chat.data.room_id}</p>
                    <p><strong>Type:</strong> ${chat.data.chat_type}</p>
                    <p><strong>Status:</strong> ${chat.data.status}</p>
                    <p><strong>Started:</strong> ${this.formatDate(chat.data.started_at)}</p>
                    <p><strong>Duration:</strong> ${this.formatDuration(chat.data.duration)}</p>
                    
                    <h4 class="mt-4">Messages</h4>
                    <div class="chat-messages" style="max-height: 300px; overflow-y: auto;">
                        ${chat.data.messages ? chat.data.messages.map(msg => `
                            <div class="message">
                                <strong>User ${msg.user_id.substring(0, 8)}:</strong>
                                ${msg.content}
                                <small class="text-muted">${this.formatDate(msg.timestamp)}</small>
                            </div>
                        `).join('') : 'No messages'}
                    </div>
                </div>
            `);
        } catch (error) {
            this.showNotification('Failed to load chat details: ' + error.message, 'error');
        }
    }

    async endChat(chatId) {
        if (!confirm('Are you sure you want to end this chat?')) return;

        try {
            await this.apiCall('POST', `/chats/${chatId}/end`);
            this.showNotification('Chat ended successfully', 'success');
            this.loadChats();
        } catch (error) {
            this.showNotification('Failed to end chat: ' + error.message, 'error');
        }
    }

    async deleteChat(chatId) {
        if (!confirm('Are you sure you want to delete this chat? This action cannot be undone.')) return;

        try {
            await this.apiCall('DELETE', `/chats/${chatId}`);
            this.showNotification('Chat deleted successfully', 'success');
            this.loadChats();
        } catch (error) {
            this.showNotification('Failed to delete chat: ' + error.message, 'error');
        }
    }

    async refreshChats() {
        this.loadChats();
        this.showNotification('Chats refreshed', 'info');
    }

    // ==============================================
    // Reports & Moderation Methods
    // ==============================================

    async loadReports() {
        try {
            const response = await this.apiCall('GET', '/reports');
            this.renderReportsTable(response.data);
        } catch (error) {
            this.showNotification('Failed to load reports: ' + error.message, 'error');
        }
    }

    renderReportsTable(reports) {
        const tbody = document.getElementById('reportsTableBody');
        
        if (!reports || reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No reports found</td></tr>';
            return;
        }

        tbody.innerHTML = reports.map(report => `
            <tr>
                <td>${report.id.substring(0, 8)}...</td>
                <td>${report.reporter_id.substring(0, 8)}...</td>
                <td>${report.reported_user_id.substring(0, 8)}...</td>
                <td>${report.reason}</td>
                <td>
                    <span class="badge ${this.getReportStatusBadgeClass(report.status)}">
                        ${report.status}
                    </span>
                </td>
                <td>${this.formatDate(report.created_at)}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="adminPanel.viewReport('${report.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    ${report.status === 'pending' ? 
                        `<button class="btn btn-sm btn-success" onclick="adminPanel.resolveReport('${report.id}')">
                            <i class="fas fa-check"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="adminPanel.dismissReport('${report.id}')">
                            <i class="fas fa-times"></i>
                        </button>` : ''
                    }
                </td>
            </tr>
        `).join('');
    }

    async viewReport(reportId) {
        try {
            const report = await this.apiCall('GET', `/reports/${reportId}`);
            
            this.showModal('Report Details', `
                <div class="report-details">
                    <h4>Report Information</h4>
                    <p><strong>Report ID:</strong> ${report.data.id}</p>
                    <p><strong>Reason:</strong> ${report.data.reason}</p>
                    <p><strong>Description:</strong> ${report.data.description}</p>
                    <p><strong>Status:</strong> ${report.data.status}</p>
                    <p><strong>Created:</strong> ${this.formatDate(report.data.created_at)}</p>
                    
                    <h4 class="mt-4">Reporter Information</h4>
                    <p><strong>Reporter ID:</strong> ${report.data.reporter_id}</p>
                    
                    <h4 class="mt-4">Reported User Information</h4>
                    <p><strong>User ID:</strong> ${report.data.reported_user_id}</p>
                </div>
            `, `
                <button class="btn btn-success" onclick="adminPanel.resolveReport('${reportId}')">Resolve</button>
                <button class="btn btn-danger" onclick="adminPanel.dismissReport('${reportId}')">Dismiss</button>
            `);
        } catch (error) {
            this.showNotification('Failed to load report details: ' + error.message, 'error');
        }
    }

    async resolveReport(reportId) {
        try {
            await this.apiCall('POST', `/reports/${reportId}/resolve`, {
                action: 'resolved',
                comments: 'Report resolved by admin'
            });
            this.showNotification('Report resolved successfully', 'success');
            this.closeModal();
            this.loadReports();
        } catch (error) {
            this.showNotification('Failed to resolve report: ' + error.message, 'error');
        }
    }

    async dismissReport(reportId) {
        try {
            await this.apiCall('POST', `/reports/${reportId}/dismiss`, {
                reason: 'No action required'
            });
            this.showNotification('Report dismissed successfully', 'success');
            this.closeModal();
            this.loadReports();
        } catch (error) {
            this.showNotification('Failed to dismiss report: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Content Management Methods
    // ==============================================

    async loadContent() {
        try {
            await Promise.all([
                this.loadBannedWords(),
                this.loadBannedCountries()
            ]);
        } catch (error) {
            this.showNotification('Failed to load content: ' + error.message, 'error');
        }
    }

    async loadBannedWords() {
        try {
            const response = await this.apiCall('GET', '/content/banned-words');
            this.renderBannedWords(response.data);
        } catch (error) {
            console.error('Failed to load banned words:', error);
        }
    }

    async loadBannedCountries() {
        try {
            const response = await this.apiCall('GET', '/content/banned-countries');
            this.renderBannedCountries(response.data);
        } catch (error) {
            console.error('Failed to load banned countries:', error);
        }
    }

    renderBannedWords(words) {
        const container = document.getElementById('bannedWordsList');
        
        if (!words || words.length === 0) {
            container.innerHTML = '<p>No banned words</p>';
            return;
        }

        container.innerHTML = words.map(word => `
            <div class="word-item">
                <span>${word.word}</span>
                <button class="btn btn-sm btn-danger" onclick="adminPanel.removeBannedWord('${word.id}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `).join('');
    }

    renderBannedCountries(countries) {
        const container = document.getElementById('bannedCountriesList');
        
        if (!countries || countries.length === 0) {
            container.innerHTML = '<p>No banned countries</p>';
            return;
        }

        container.innerHTML = countries.map(country => `
            <div class="country-item">
                <span>${country.name} (${country.code})</span>
                <button class="btn btn-sm btn-danger" onclick="adminPanel.removeBannedCountry('${country.code}')">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `).join('');
    }

    addBannedWord() {
        this.showModal('Add Banned Word', `
            <form id="addWordForm">
                <div class="form-group">
                    <label class="form-label">Word</label>
                    <input type="text" id="newWord" class="form-control" required>
                </div>
            </form>
        `, `
            <button class="btn btn-primary" onclick="adminPanel.saveBannedWord()">Add Word</button>
        `);
    }

    async saveBannedWord() {
        const word = document.getElementById('newWord').value.trim();
        if (!word) return;

        try {
            await this.apiCall('POST', '/content/banned-words', { word });
            this.showNotification('Banned word added successfully', 'success');
            this.closeModal();
            this.loadBannedWords();
        } catch (error) {
            this.showNotification('Failed to add banned word: ' + error.message, 'error');
        }
    }

    async removeBannedWord(wordId) {
        if (!confirm('Remove this banned word?')) return;

        try {
            await this.apiCall('DELETE', `/content/banned-words/${wordId}`);
            this.showNotification('Banned word removed successfully', 'success');
            this.loadBannedWords();
        } catch (error) {
            this.showNotification('Failed to remove banned word: ' + error.message, 'error');
        }
    }

    addBannedCountry() {
        this.showModal('Add Banned Country', `
            <form id="addCountryForm">
                <div class="form-group">
                    <label class="form-label">Country Code</label>
                    <input type="text" id="countryCode" class="form-control" placeholder="US" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Country Name</label>
                    <input type="text" id="countryName" class="form-control" placeholder="United States" required>
                </div>
            </form>
        `, `
            <button class="btn btn-primary" onclick="adminPanel.saveBannedCountry()">Add Country</button>
        `);
    }

    async saveBannedCountry() {
        const code = document.getElementById('countryCode').value.trim();
        const name = document.getElementById('countryName').value.trim();
        if (!code || !name) return;

        try {
            await this.apiCall('POST', '/content/banned-countries', { code, name });
            this.showNotification('Banned country added successfully', 'success');
            this.closeModal();
            this.loadBannedCountries();
        } catch (error) {
            this.showNotification('Failed to add banned country: ' + error.message, 'error');
        }
    }

    async removeBannedCountry(countryCode) {
        if (!confirm('Remove this banned country?')) return;

        try {
            await this.apiCall('DELETE', `/content/banned-countries/${countryCode}`);
            this.showNotification('Banned country removed successfully', 'success');
            this.loadBannedCountries();
        } catch (error) {
            this.showNotification('Failed to remove banned country: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Analytics Methods
    // ==============================================

    async loadAnalytics() {
        try {
            await Promise.all([
                this.updateChatAnalyticsChart(),
                this.updateUserGrowthChart(),
                this.updateRegionDistributionChart(),
                this.updateLanguageChart()
            ]);
        } catch (error) {
            this.showNotification('Failed to load analytics: ' + error.message, 'error');
        }
    }

    async updateChatAnalyticsChart() {
        try {
            const data = await this.apiCall('GET', '/analytics/chat-types');
            
            if (this.charts.chatAnalytics && data.data) {
                this.charts.chatAnalytics.data.datasets[0].data = data.data.values;
                this.charts.chatAnalytics.update();
            }
        } catch (error) {
            console.error('Failed to update chat analytics chart:', error);
        }
    }

    async updateUserGrowthChart() {
        try {
            const data = await this.apiCall('GET', '/analytics/user-growth');
            
            if (this.charts.userGrowth && data.data) {
                this.charts.userGrowth.data.labels = data.data.labels;
                this.charts.userGrowth.data.datasets[0].data = data.data.values;
                this.charts.userGrowth.update();
            }
        } catch (error) {
            console.error('Failed to update user growth chart:', error);
        }
    }

    async updateRegionDistributionChart() {
        // Reuse region chart for distribution
        await this.updateRegionChart();
    }

    async updateLanguageChart() {
        const ctx = document.getElementById('languageChart');
        if (!ctx) return;

        try {
            const data = await this.apiCall('GET', '/analytics/languages');
            
            if (!this.charts.language) {
                this.charts.language = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [
                                '#667eea', '#f093fb', '#4caf50', 
                                '#ff9800', '#f44336', '#2196f3',
                                '#9c27b0', '#607d8b'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    color: 'white'
                                }
                            }
                        }
                    }
                });
            }

            if (data.data) {
                this.charts.language.data.labels = data.data.labels;
                this.charts.language.data.datasets[0].data = data.data.values;
                this.charts.language.update();
            }
        } catch (error) {
            console.error('Failed to update language chart:', error);
        }
    }

    // ==============================================
    // COTURN Server Methods
    // ==============================================

    async loadCoturnServers() {
        try {
            const response = await this.apiCall('GET', '/coturn/servers');
            this.renderCoturnTable(response.data);
        } catch (error) {
            this.showNotification('Failed to load COTURN servers: ' + error.message, 'error');
        }
    }

    renderCoturnTable(servers) {
        const tbody = document.getElementById('coturnTableBody');
        
        if (!servers || servers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No COTURN servers found</td></tr>';
            return;
        }

        tbody.innerHTML = servers.map(server => `
            <tr>
                <td>${server.url}</td>
                <td>${server.region}</td>
                <td>
                    <span class="badge ${server.is_active ? 'badge-success' : 'badge-danger'}">
                        ${server.is_active ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>${server.load || 0}%</td>
                <td>${this.formatDuration(server.uptime)}</td>
                <td>${this.formatDate(server.last_check)}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="adminPanel.testCoturnServer('${server.id}')">
                        <i class="fas fa-play"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="adminPanel.editCoturnServer('${server.id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="adminPanel.deleteCoturnServer('${server.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    addCoturnServer() {
        this.showModal('Add COTURN Server', `
            <form id="addCoturnForm">
                <div class="form-group">
                    <label class="form-label">Server URL</label>
                    <input type="text" id="coturnUrl" class="form-control" placeholder="turn:server.com:3478" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Region</label>
                    <select id="coturnRegion" class="form-control" required>
                        <option value="">Select Region</option>
                        <option value="us-east">US East</option>
                        <option value="us-west">US West</option>
                        <option value="eu-west">EU West</option>
                        <option value="ap-southeast">AP Southeast</option>
                        <option value="ap-northeast">AP Northeast</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" id="coturnUsername" class="form-control" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" id="coturnPassword" class="form-control" required>
                </div>
            </form>
        `, `
            <button class="btn btn-primary" onclick="adminPanel.saveCoturnServer()">Add Server</button>
        `);
    }

    async saveCoturnServer() {
        const url = document.getElementById('coturnUrl').value.trim();
        const region = document.getElementById('coturnRegion').value;
        const username = document.getElementById('coturnUsername').value.trim();
        const password = document.getElementById('coturnPassword').value;

        if (!url || !region || !username || !password) {
            this.showNotification('Please fill all fields', 'warning');
            return;
        }

        try {
            await this.apiCall('POST', '/coturn/servers', {
                url, region, username, password
            });
            this.showNotification('COTURN server added successfully', 'success');
            this.closeModal();
            this.loadCoturnServers();
        } catch (error) {
            this.showNotification('Failed to add COTURN server: ' + error.message, 'error');
        }
    }

    async testCoturnServer(serverId) {
        try {
            const response = await this.apiCall('POST', `/coturn/servers/${serverId}/test`);
            this.showNotification(`Server test ${response.data.success ? 'passed' : 'failed'}`, 
                response.data.success ? 'success' : 'error');
        } catch (error) {
            this.showNotification('Failed to test server: ' + error.message, 'error');
        }
    }

    async deleteCoturnServer(serverId) {
        if (!confirm('Are you sure you want to delete this COTURN server?')) return;

        try {
            await this.apiCall('DELETE', `/coturn/servers/${serverId}`);
            this.showNotification('COTURN server deleted successfully', 'success');
            this.loadCoturnServers();
        } catch (error) {
            this.showNotification('Failed to delete COTURN server: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Settings Methods
    // ==============================================

    async loadSettings() {
        try {
            const [appSettings, moderationSettings] = await Promise.all([
                this.apiCall('GET', '/settings/app'),
                this.apiCall('GET', '/settings/moderation')
            ]);

            this.populateAppSettings(appSettings.data);
            this.populateModerationSettings(moderationSettings.data);
        } catch (error) {
            this.showNotification('Failed to load settings: ' + error.message, 'error');
        }
    }

    populateAppSettings(settings) {
        document.getElementById('appName').value = settings.app_name || '';
        document.getElementById('maxUsers').value = settings.max_users_per_chat || 2;
        document.getElementById('chatTimeout').value = settings.chat_timeout_minutes || 60;
        document.getElementById('minAge').value = settings.minimum_age || 13;
    }

    populateModerationSettings(settings) {
        document.getElementById('autoModeration').checked = settings.auto_moderation || false;
        document.getElementById('profanityFilter').checked = settings.profanity_filter || false;
        document.getElementById('nsfwDetection').checked = settings.nsfw_detection || false;
        document.getElementById('autoBanThreshold').value = settings.auto_ban_threshold || 5;
    }

    async saveAppSettings() {
        const settings = {
            app_name: document.getElementById('appName').value,
            max_users_per_chat: parseInt(document.getElementById('maxUsers').value),
            chat_timeout_minutes: parseInt(document.getElementById('chatTimeout').value),
            minimum_age: parseInt(document.getElementById('minAge').value)
        };

        try {
            await this.apiCall('PUT', '/settings/app', settings);
            this.showNotification('App settings saved successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to save app settings: ' + error.message, 'error');
        }
    }

    async saveModerationSettings() {
        const settings = {
            auto_moderation: document.getElementById('autoModeration').checked,
            profanity_filter: document.getElementById('profanityFilter').checked,
            nsfw_detection: document.getElementById('nsfwDetection').checked,
            auto_ban_threshold: parseInt(document.getElementById('autoBanThreshold').value)
        };

        try {
            await this.apiCall('PUT', '/settings/moderation', settings);
            this.showNotification('Moderation settings saved successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to save moderation settings: ' + error.message, 'error');
        }
    }

    // ==============================================
    // System Methods
    // ==============================================

    async loadSystemInfo() {
        try {
            const [systemInfo, systemHealth, databaseStats] = await Promise.all([
                this.apiCall('GET', '/system/info'),
                this.apiCall('GET', '/system/health'),
                this.apiCall('GET', '/system/database/stats')
            ]);

            this.renderSystemInfo({ ...systemInfo.data, ...systemHealth.data, ...databaseStats.data });
        } catch (error) {
            this.showNotification('Failed to load system info: ' + error.message, 'error');
        }
    }

    renderSystemInfo(info) {
        const container = document.getElementById('systemInfo');
        
        container.innerHTML = `
            <div class="system-info-item">
                <span class="system-info-label">Version</span>
                <span class="system-info-value">${info.version || '1.0.0'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Go Version</span>
                <span class="system-info-value">${info.go_version || 'N/A'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Uptime</span>
                <span class="system-info-value">${info.uptime || 'N/A'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Database Status</span>
                <span class="system-info-value">${info.database || 'Unknown'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Memory Usage</span>
                <span class="system-info-value">${info.memory || 'N/A'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">CPU Usage</span>
                <span class="system-info-value">${info.cpu || 'N/A'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Database Size</span>
                <span class="system-info-value">${info.database_size || 'N/A'}</span>
            </div>
            <div class="system-info-item">
                <span class="system-info-label">Total Collections</span>
                <span class="system-info-value">${info.total_collections || 'N/A'}</span>
            </div>
        `;
    }

    async clearCache() {
        if (!confirm('Are you sure you want to clear the cache?')) return;

        try {
            await this.apiCall('POST', '/system/cache/clear');
            this.showNotification('Cache cleared successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to clear cache: ' + error.message, 'error');
        }
    }

    async cleanupDatabase() {
        if (!confirm('Are you sure you want to cleanup the database?')) return;

        try {
            await this.apiCall('POST', '/system/database/cleanup');
            this.showNotification('Database cleanup completed', 'success');
        } catch (error) {
            this.showNotification('Failed to cleanup database: ' + error.message, 'error');
        }
    }

    async createBackup() {
        try {
            const response = await this.apiCall('POST', '/system/backup');
            this.showNotification('Backup created successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to create backup: ' + error.message, 'error');
        }
    }

    async enableMaintenanceMode() {
        const enabled = confirm('Enable maintenance mode? This will prevent new users from connecting.');
        
        try {
            await this.apiCall('POST', '/system/maintenance', { 
                enabled,
                message: 'System is under maintenance. Please try again later.'
            });
            this.showNotification(`Maintenance mode ${enabled ? 'enabled' : 'disabled'}`, 'info');
        } catch (error) {
            this.showNotification('Failed to update maintenance mode: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Real-time Updates
    // ==============================================

    startRealTimeUpdates() {
        // Update stats every 30 seconds
        this.realTimeInterval = setInterval(async () => {
            if (this.currentSection === 'dashboard') {
                try {
                    const stats = await this.apiCall('GET', '/dashboard/realtime');
                    this.updateHeaderStats(stats.data);
                } catch (error) {
                    console.error('Failed to update real-time stats:', error);
                }
            }
        }, 30000);
    }

    updateHeaderStats(stats) {
        document.getElementById('onlineUsers').textContent = stats.online_users || 0;
        document.getElementById('activeChats').textContent = stats.active_chats || 0;
        document.getElementById('totalUsers').textContent = stats.total_users || 0;
    }

    // ==============================================
    // Utility Methods
    // ==============================================

    formatDate(dateString) {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    }

    formatTime(dateString) {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleTimeString();
    }

    formatDuration(seconds) {
        if (!seconds) return '0s';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    getActivityIcon(type) {
        const icons = {
            user_joined: 'user-plus',
            user_left: 'user-minus',
            chat_started: 'comment',
            chat_ended: 'comment-slash',
            user_banned: 'ban',
            report_submitted: 'flag'
        };
        return icons[type] || 'info-circle';
    }

    getAlertIcon(level) {
        const icons = {
            error: 'exclamation-triangle',
            warning: 'exclamation-circle',
            info: 'info-circle'
        };
        return icons[level] || 'info-circle';
    }

    getStatusBadgeClass(status) {
        const classes = {
            active: 'badge-success',
            ended: 'badge-secondary',
            waiting: 'badge-warning'
        };
        return classes[status] || 'badge-secondary';
    }

    getReportStatusBadgeClass(status) {
        const classes = {
            pending: 'badge-warning',
            resolved: 'badge-success',
            dismissed: 'badge-secondary'
        };
        return classes[status] || 'badge-secondary';
    }

    renderPagination(containerId, meta) {
        const container = document.getElementById(containerId);
        if (!container || !meta) return;

        const { page, total_pages, total } = meta;
        
        container.innerHTML = `
            <div>Showing ${((page - 1) * meta.limit) + 1} to ${Math.min(page * meta.limit, total)} of ${total} entries</div>
            <div class="pagination-controls">
                <button class="btn btn-sm btn-secondary" ${page <= 1 ? 'disabled' : ''} 
                    onclick="adminPanel.loadPage(${page - 1})">Previous</button>
                <span class="pagination-info">Page ${page} of ${total_pages}</span>
                <button class="btn btn-sm btn-secondary" ${page >= total_pages ? 'disabled' : ''} 
                    onclick="adminPanel.loadPage(${page + 1})">Next</button>
            </div>
        `;
    }

    loadPage(page) {
        if (this.currentSection === 'users') {
            this.loadUsers(page);
        } else if (this.currentSection === 'chats') {
            this.loadChats(page);
        } else if (this.currentSection === 'reports') {
            this.loadReports(page);
        }
    }

    // ==============================================
    // Modal Methods
    // ==============================================

    showModal(title, body, footer = null) {
        document.getElementById('modalTitle').textContent = title;
        document.getElementById('modalBody').innerHTML = body;
        
        if (footer) {
            document.getElementById('modalFooter').innerHTML = footer + 
                '<button class="btn btn-secondary" onclick="adminPanel.closeModal()">Close</button>';
        } else {
            document.getElementById('modalFooter').innerHTML = 
                '<button class="btn btn-secondary" onclick="adminPanel.closeModal()">Close</button>';
        }
        
        document.getElementById('genericModal').classList.add('active');
    }

    closeModal() {
        document.getElementById('genericModal').classList.remove('active');
    }

    // ==============================================
    // Notification Methods
    // ==============================================

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
        `;
        
        document.getElementById('notificationContainer').appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        // Hide notification after 5 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 5000);
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            error: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    // ==============================================
    // Global Methods
    // ==============================================

    showAdminMenu() {
        // TODO: Implement admin profile menu
        console.log('Admin menu clicked');
    }

    showBulkActions() {
        this.showModal('Bulk Actions', `
            <div class="bulk-actions">
                <h4>Select Action</h4>
                <div class="form-group">
                    <label class="form-label">Action</label>
                    <select id="bulkAction" class="form-control">
                        <option value="">Select Action</option>
                        <option value="ban">Ban Selected Users</option>
                        <option value="unban">Unban Selected Users</option>
                        <option value="delete">Delete Selected Users</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Reason (optional)</label>
                    <textarea id="bulkReason" class="form-control" rows="3"></textarea>
                </div>
            </div>
        `, `
            <button class="btn btn-primary" onclick="adminPanel.executeBulkAction()">Execute</button>
        `);
    }

    async executeBulkAction() {
        const action = document.getElementById('bulkAction').value;
        const reason = document.getElementById('bulkReason').value;
        
        if (!action) {
            this.showNotification('Please select an action', 'warning');
            return;
        }

        const selectedUsers = Array.from(document.querySelectorAll('.user-checkbox:checked'))
            .map(cb => cb.value);

        if (selectedUsers.length === 0) {
            this.showNotification('Please select users', 'warning');
            return;
        }

        if (!confirm(`Are you sure you want to ${action} ${selectedUsers.length} users?`)) return;

        try {
            await this.apiCall('POST', '/users/bulk-action', {
                action,
                user_ids: selectedUsers,
                reason
            });
            
            this.showNotification(`Bulk ${action} completed successfully`, 'success');
            this.closeModal();
            this.loadUsers();
        } catch (error) {
            this.showNotification(`Failed to execute bulk ${action}: ` + error.message, 'error');
        }
    }
}

// Global functions for onclick handlers
function showAdminMenu() {
    adminPanel.showAdminMenu();
}

function logout() {
    adminPanel.logout();
}

function exportUsers() {
    adminPanel.exportUsers();
}

function showBulkActions() {
    adminPanel.showBulkActions();
}

function refreshChats() {
    adminPanel.refreshChats();
}

function addBannedWord() {
    adminPanel.addBannedWord();
}

function addBannedCountry() {
    adminPanel.addBannedCountry();
}

function addCoturnServer() {
    adminPanel.addCoturnServer();
}

function clearCache() {
    adminPanel.clearCache();
}

function cleanupDatabase() {
    adminPanel.cleanupDatabase();
}

function createBackup() {
    adminPanel.createBackup();
}

function enableMaintenanceMode() {
    adminPanel.enableMaintenanceMode();
}

function closeModal() {
    adminPanel.closeModal();
}

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminPanel = new AdminPanel();
});