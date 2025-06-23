/**
 * Omegle Admin Panel JavaScript
 * Complete functionality for admin dashboard
 */

class AdminPanel {
    constructor() {
        this.baseURL = '/admin/api';
        this.authURL = '/auth/admin';
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
            const response = await this.authCall('GET', '/verify');
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
            const response = await fetch(this.authURL + '/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (response.ok && result.success) {
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

    async logout() {
        try {
            await this.authCall('POST', '/logout');
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            localStorage.removeItem('admin_token');
            this.token = null;
            if (this.realTimeInterval) {
                clearInterval(this.realTimeInterval);
            }
            this.showLogin();
            this.showNotification('Logged out successfully', 'info');
        }
    }

    // ==============================================
    // API Methods
    // ==============================================

    async authCall(method, endpoint, data = null) {
        const url = this.authURL + endpoint;
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
            console.error('Auth API Error:', error);
            if (error.message.includes('unauthorized') || error.message.includes('401')) {
                this.logout();
            }
            throw error;
        }
    }

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
            
            if (!response.ok) {
                if (response.status === 401) {
                    this.logout();
                    throw new Error('Unauthorized access');
                }
                const result = await response.json();
                throw new Error(result.message || `HTTP ${response.status}`);
            }

            const result = await response.json();
            return result;
        } catch (error) {
            console.error('API Error:', error);
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
                const section = e.currentTarget.dataset.section;
                this.navigateToSection(section);
            });
        });

        // Modal close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => this.closeModal());
        });

        // Settings forms
        document.getElementById('appSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveAppSettings();
        });

        document.getElementById('moderationSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveModerationSettings();
        });
    }

    // ==============================================
    // Navigation
    // ==============================================

    navigateToSection(section) {
        // Remove active class from all nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to current link
        document.querySelector(`[data-section="${section}"]`).classList.add('active');

        // Hide all sections
        document.querySelectorAll('.section-content').forEach(content => {
            content.style.display = 'none';
        });

        // Show selected section
        const sectionElement = document.getElementById(section + 'Section');
        if (sectionElement) {
            sectionElement.style.display = 'block';
        }

        this.currentSection = section;

        // Load section data
        this.loadSectionData(section);
    }

    loadSectionData(section) {
        switch (section) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'users':
                this.loadUsers();
                break;
            case 'chats':
                this.loadChats();
                break;
            case 'reports':
                this.loadReports();
                break;
            case 'content':
                this.loadContentManagement();
                break;
            case 'analytics':
                this.loadAnalytics();
                break;
            case 'coturn':
                this.loadCoturnServers();
                break;
            case 'settings':
                this.loadSettings();
                break;
            case 'system':
                this.loadSystemInfo();
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
            const [stats, realtimeStats] = await Promise.all([
                this.apiCall('GET', '/dashboard/stats'),
                this.apiCall('GET', '/dashboard/realtime')
            ]);

            this.updateDashboardStats(stats.data);
            this.updateRealtimeStats(realtimeStats.data);
            this.loadDashboardCharts();
        } catch (error) {
            this.showNotification('Failed to load dashboard: ' + error.message, 'error');
        }
    }

    updateDashboardStats(stats) {
        document.getElementById('totalUsers').textContent = stats.total_users || 0;
        document.getElementById('activeUsers').textContent = stats.active_users || 0;
        document.getElementById('totalChats').textContent = stats.total_chats || 0;
        document.getElementById('activeChats').textContent = stats.active_chats || 0;
        document.getElementById('totalMessages').textContent = stats.total_messages || 0;
        document.getElementById('bannedUsers').textContent = stats.banned_users || 0;
        document.getElementById('reportsToday').textContent = stats.reports_today || 0;
        document.getElementById('avgChatDuration').textContent = (stats.avg_chat_duration || 0) + 'm';
    }

    updateRealtimeStats(stats) {
        document.getElementById('usersOnline').textContent = stats.users_online || 0;
        document.getElementById('queueLength').textContent = stats.queue_length || 0;
        document.getElementById('avgWaitTime').textContent = (stats.avg_wait_time || 0) + 's';
    }

    async loadDashboardCharts() {
        try {
            const [userChart, chatChart, regionChart] = await Promise.all([
                this.apiCall('GET', '/dashboard/chart/users'),
                this.apiCall('GET', '/dashboard/chart/chats'),
                this.apiCall('GET', '/dashboard/chart/regions')
            ]);

            this.updateUserChart(userChart.data);
            this.updateChatChart(chatChart.data);
            this.updateRegionChart(regionChart.data);
        } catch (error) {
            console.error('Failed to load charts:', error);
        }
    }

    // ==============================================
    // User Management Methods
    // ==============================================

    async loadUsers(page = 1, search = '', status = 'all') {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: '20',
                search,
                status
            });

            const response = await this.apiCall('GET', `/users?${params}`);
            this.displayUsers(response.data);
        } catch (error) {
            this.showNotification('Failed to load users: ' + error.message, 'error');
        }
    }

    displayUsers(data) {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <input type="checkbox" class="user-checkbox" value="${user.id}">
                </td>
                <td>
                    <div class="user-info">
                        <strong>${user.username || 'Anonymous'}</strong>
                        <small>${user.email || 'No email'}</small>
                    </div>
                </td>
                <td>
                    <span class="badge ${user.status === 'active' ? 'badge-success' : 
                        user.status === 'banned' ? 'badge-danger' : 'badge-secondary'}">
                        ${user.status}
                    </span>
                </td>
                <td>${user.region || 'Unknown'}</td>
                <td>${new Date(user.created_at).toLocaleDateString()}</td>
                <td>${new Date(user.last_active).toLocaleDateString()}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewUser('${user.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="editUser('${user.id}')">
                            <i class="fas fa-edit"></i>
                        </button>
                        ${user.status !== 'banned' ? 
                            `<button class="btn btn-sm btn-outline-danger" onclick="banUser('${user.id}')">
                                <i class="fas fa-ban"></i>
                            </button>` :
                            `<button class="btn btn-sm btn-outline-success" onclick="unbanUser('${user.id}')">
                                <i class="fas fa-check"></i>
                            </button>`
                        }
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        // Update pagination
        this.updatePagination(data.pagination, 'usersPagination');
    }

    async banUser(userId, reason = '') {
        if (!confirm('Are you sure you want to ban this user?')) return;

        try {
            await this.apiCall('POST', `/users/${userId}/ban`, { reason });
            this.showNotification('User banned successfully', 'success');
            this.loadUsers();
        } catch (error) {
            this.showNotification('Failed to ban user: ' + error.message, 'error');
        }
    }

    async unbanUser(userId) {
        if (!confirm('Are you sure you want to unban this user?')) return;

        try {
            await this.apiCall('DELETE', `/users/${userId}/ban`);
            this.showNotification('User unbanned successfully', 'success');
            this.loadUsers();
        } catch (error) {
            this.showNotification('Failed to unban user: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Chat Management Methods
    // ==============================================

    async loadChats(page = 1, status = 'all') {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: '20',
                status
            });

            const response = await this.apiCall('GET', `/chats?${params}`);
            this.displayChats(response.data);
        } catch (error) {
            this.showNotification('Failed to load chats: ' + error.message, 'error');
        }
    }

    displayChats(data) {
        const tbody = document.getElementById('chatsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.chats.forEach(chat => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${chat.id}</td>
                <td>${chat.participants || 0}</td>
                <td>
                    <span class="badge ${chat.status === 'active' ? 'badge-success' : 'badge-secondary'}">
                        ${chat.status}
                    </span>
                </td>
                <td>${chat.type || 'text'}</td>
                <td>${chat.region || 'Unknown'}</td>
                <td>${new Date(chat.created_at).toLocaleDateString()}</td>
                <td>${chat.duration || '0'}m</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewChat('${chat.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="endChat('${chat.id}')">
                            <i class="fas fa-stop"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        this.updatePagination(data.pagination, 'chatsPagination');
    }

    async endChat(chatId) {
        if (!confirm('Are you sure you want to end this chat?')) return;

        try {
            await this.apiCall('DELETE', `/chats/${chatId}`);
            this.showNotification('Chat ended successfully', 'success');
            this.loadChats();
        } catch (error) {
            this.showNotification('Failed to end chat: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Reports & Moderation Methods
    // ==============================================

    async loadReports(page = 1, status = 'pending') {
        try {
            const params = new URLSearchParams({
                page: page.toString(),
                limit: '20',
                status
            });

            const response = await this.apiCall('GET', `/reports?${params}`);
            this.displayReports(response.data);
        } catch (error) {
            this.showNotification('Failed to load reports: ' + error.message, 'error');
        }
    }

    displayReports(data) {
        const tbody = document.getElementById('reportsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.reports.forEach(report => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${report.id}</td>
                <td>${report.reporter_id || 'Anonymous'}</td>
                <td>${report.reported_user_id || 'Unknown'}</td>
                <td>
                    <span class="badge badge-warning">${report.reason}</span>
                </td>
                <td>
                    <span class="badge ${report.status === 'pending' ? 'badge-warning' : 
                        report.status === 'resolved' ? 'badge-success' : 'badge-danger'}">
                        ${report.status}
                    </span>
                </td>
                <td>${new Date(report.created_at).toLocaleDateString()}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewReport('${report.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${report.status === 'pending' ? `
                            <button class="btn btn-sm btn-outline-success" onclick="approveReport('${report.id}')">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="rejectReport('${report.id}')">
                                <i class="fas fa-times"></i>
                            </button>
                        ` : ''}
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        this.updatePagination(data.pagination, 'reportsPagination');
    }

    async approveReport(reportId) {
        try {
            await this.apiCall('POST', `/reports/${reportId}/approve`);
            this.showNotification('Report approved successfully', 'success');
            this.loadReports();
        } catch (error) {
            this.showNotification('Failed to approve report: ' + error.message, 'error');
        }
    }

    async rejectReport(reportId) {
        try {
            await this.apiCall('POST', `/reports/${reportId}/reject`);
            this.showNotification('Report rejected successfully', 'success');
            this.loadReports();
        } catch (error) {
            this.showNotification('Failed to reject report: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Content Management Methods
    // ==============================================

    async loadContentManagement() {
        try {
            const [bannedWords, bannedCountries] = await Promise.all([
                this.apiCall('GET', '/content/banned-words'),
                this.apiCall('GET', '/content/banned-countries')
            ]);

            this.displayBannedWords(bannedWords.data);
            this.displayBannedCountries(bannedCountries.data);
        } catch (error) {
            this.showNotification('Failed to load content management: ' + error.message, 'error');
        }
    }

    displayBannedWords(words) {
        const container = document.getElementById('bannedWordsList');
        if (!container) return;

        container.innerHTML = words.map(word => `
            <div class="banned-item">
                <span>${word.word}</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeBannedWord('${word.id}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    }

    displayBannedCountries(countries) {
        const container = document.getElementById('bannedCountriesList');
        if (!container) return;

        container.innerHTML = countries.map(country => `
            <div class="banned-item">
                <span>${country.name} (${country.code})</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeBannedCountry('${country.code}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    }

    async addBannedWord() {
        const word = document.getElementById('newBannedWord').value.trim();
        if (!word) return;

        try {
            await this.apiCall('POST', '/content/banned-words', { word });
            this.showNotification('Banned word added successfully', 'success');
            document.getElementById('newBannedWord').value = '';
            this.loadContentManagement();
        } catch (error) {
            this.showNotification('Failed to add banned word: ' + error.message, 'error');
        }
    }

    async removeBannedWord(wordId) {
        try {
            await this.apiCall('DELETE', `/content/banned-words/${wordId}`);
            this.showNotification('Banned word removed successfully', 'success');
            this.loadContentManagement();
        } catch (error) {
            this.showNotification('Failed to remove banned word: ' + error.message, 'error');
        }
    }

    async addBannedCountry() {
        const code = document.getElementById('newBannedCountry').value.trim();
        if (!code) return;

        try {
            await this.apiCall('POST', '/content/banned-countries', { code });
            this.showNotification('Banned country added successfully', 'success');
            document.getElementById('newBannedCountry').value = '';
            this.loadContentManagement();
        } catch (error) {
            this.showNotification('Failed to add banned country: ' + error.message, 'error');
        }
    }

    async removeBannedCountry(code) {
        try {
            await this.apiCall('DELETE', `/content/banned-countries/${code}`);
            this.showNotification('Banned country removed successfully', 'success');
            this.loadContentManagement();
        } catch (error) {
            this.showNotification('Failed to remove banned country: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Analytics Methods
    // ==============================================

    async loadAnalytics() {
        try {
            const analytics = await this.apiCall('GET', '/analytics/overview');
            this.displayAnalytics(analytics.data);
        } catch (error) {
            this.showNotification('Failed to load analytics: ' + error.message, 'error');
        }
    }

    displayAnalytics(data) {
        // Implementation for analytics display
        console.log('Analytics data:', data);
    }

    // ==============================================
    // COTURN Server Methods
    // ==============================================

    async loadCoturnServers() {
        try {
            const response = await this.apiCall('GET', '/coturn/servers');
            this.displayCoturnServers(response.data);
        } catch (error) {
            this.showNotification('Failed to load COTURN servers: ' + error.message, 'error');
        }
    }

    displayCoturnServers(servers) {
        const tbody = document.getElementById('coturnServersTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        servers.forEach(server => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${server.id}</td>
                <td>${server.url}</td>
                <td>${server.region}</td>
                <td>
                    <span class="badge ${server.status === 'healthy' ? 'badge-success' : 'badge-danger'}">
                        ${server.status}
                    </span>
                </td>
                <td>${server.load || 0}%</td>
                <td>${new Date(server.last_check).toLocaleString()}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="testCoturnServer('${server.id}')">
                            <i class="fas fa-check"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="removeCoturnServer('${server.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async addCoturnServer() {
        const url = document.getElementById('coturnUrl').value.trim();
        const region = document.getElementById('coturnRegion').value.trim();
        const username = document.getElementById('coturnUsername').value.trim();
        const password = document.getElementById('coturnPassword').value.trim();

        if (!url || !region) {
            this.showNotification('Please fill in all required fields', 'warning');
            return;
        }

        try {
            await this.apiCall('POST', '/coturn/servers', {
                url,
                region,
                username,
                password
            });
            this.showNotification('COTURN server added successfully', 'success');
            this.clearCoturnForm();
            this.loadCoturnServers();
        } catch (error) {
            this.showNotification('Failed to add COTURN server: ' + error.message, 'error');
        }
    }

    clearCoturnForm() {
        document.getElementById('coturnUrl').value = '';
        document.getElementById('coturnRegion').value = '';
        document.getElementById('coturnUsername').value = '';
        document.getElementById('coturnPassword').value = '';
    }

    async testCoturnServer(serverId) {
        try {
            const response = await this.apiCall('POST', `/coturn/servers/${serverId}/test`);
            this.showNotification('Server test completed: ' + response.data.result, 
                response.data.healthy ? 'success' : 'warning');
            this.loadCoturnServers();
        } catch (error) {
            this.showNotification('Failed to test server: ' + error.message, 'error');
        }
    }

    async removeCoturnServer(serverId) {
        if (!confirm('Are you sure you want to remove this COTURN server?')) return;

        try {
            await this.apiCall('DELETE', `/coturn/servers/${serverId}`);
            this.showNotification('COTURN server removed successfully', 'success');
            this.loadCoturnServers();
        } catch (error) {
            this.showNotification('Failed to remove COTURN server: ' + error.message, 'error');
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

            this.displayAppSettings(appSettings.data);
            this.displayModerationSettings(moderationSettings.data);
        } catch (error) {
            this.showNotification('Failed to load settings: ' + error.message, 'error');
        }
    }

    displayAppSettings(settings) {
        document.getElementById('appName').value = settings.app_name || '';
        document.getElementById('maxUsers').value = settings.max_users || '';
        document.getElementById('chatTimeout').value = settings.chat_timeout || '';
        document.getElementById('minAge').value = settings.min_age || '';
    }

    displayModerationSettings(settings) {
        document.getElementById('autoModeration').checked = settings.auto_moderation || false;
        document.getElementById('profanityFilter').checked = settings.profanity_filter || false;
        document.getElementById('ageVerification').checked = settings.age_verification || false;
    }

    async saveAppSettings() {
        const settings = {
            app_name: document.getElementById('appName').value,
            max_users: parseInt(document.getElementById('maxUsers').value),
            chat_timeout: parseInt(document.getElementById('chatTimeout').value),
            min_age: parseInt(document.getElementById('minAge').value)
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
            age_verification: document.getElementById('ageVerification').checked
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
            const systemInfo = await this.apiCall('GET', '/system/info');
            this.displaySystemInfo(systemInfo.data);
        } catch (error) {
            this.showNotification('Failed to load system info: ' + error.message, 'error');
        }
    }

    displaySystemInfo(info) {
        document.getElementById('systemUptime').textContent = info.uptime || '0';
        document.getElementById('memoryUsage').textContent = info.memory_usage || '0%';
        document.getElementById('cpuUsage').textContent = info.cpu_usage || '0%';
        document.getElementById('diskUsage').textContent = info.disk_usage || '0%';
        document.getElementById('dbConnections').textContent = info.db_connections || '0';
        document.getElementById('activeWebsockets').textContent = info.active_websockets || '0';
    }

    async clearCache() {
        if (!confirm('Are you sure you want to clear the cache?')) return;

        try {
            await this.apiCall('POST', '/system/clear-cache');
            this.showNotification('Cache cleared successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to clear cache: ' + error.message, 'error');
        }
    }

    async cleanupDatabase() {
        if (!confirm('Are you sure you want to cleanup the database?')) return;

        try {
            await this.apiCall('POST', '/system/cleanup-database');
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
        if (!confirm('Are you sure you want to enable maintenance mode?')) return;

        try {
            await this.apiCall('POST', '/system/maintenance', { enabled: true });
            this.showNotification('Maintenance mode enabled', 'info');
        } catch (error) {
            this.showNotification('Failed to enable maintenance mode: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Utility Methods
    // ==============================================

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close">&times;</button>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);

        // Close button functionality
        notification.querySelector('.notification-close').addEventListener('click', () => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        });
    }

    getNotificationIcon(type) {
        switch (type) {
            case 'success': return 'check-circle';
            case 'error': return 'exclamation-circle';
            case 'warning': return 'exclamation-triangle';
            case 'info': return 'info-circle';
            default: return 'info-circle';
        }
    }

    updatePagination(pagination, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const { current_page, total_pages, total_items } = pagination;

        container.innerHTML = `
            <div class="pagination-info">
                Showing page ${current_page} of ${total_pages} (${total_items} total)
            </div>
            <div class="pagination-buttons">
                <button class="btn btn-sm btn-outline-primary" 
                        ${current_page <= 1 ? 'disabled' : ''} 
                        onclick="adminPanel.loadCurrentSection(${current_page - 1})">
                    Previous
                </button>
                <button class="btn btn-sm btn-outline-primary" 
                        ${current_page >= total_pages ? 'disabled' : ''} 
                        onclick="adminPanel.loadCurrentSection(${current_page + 1})">
                    Next
                </button>
            </div>
        `;
    }

    loadCurrentSection(page = 1) {
        switch (this.currentSection) {
            case 'users':
                this.loadUsers(page);
                break;
            case 'chats':
                this.loadChats(page);
                break;
            case 'reports':
                this.loadReports(page);
                break;
        }
    }

    closeModal() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }

    showModal(modalId) {
        document.getElementById(modalId).style.display = 'flex';
    }

    // ==============================================
    // Chart Methods
    // ==============================================

    initializeCharts() {
        // Initialize chart containers if they exist
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js not loaded');
            return;
        }

        // Will be implemented when chart containers are available
    }

    updateUserChart(data) {
        // Implementation for user chart
        console.log('User chart data:', data);
    }

    updateChatChart(data) {
        // Implementation for chat chart
        console.log('Chat chart data:', data);
    }

    updateRegionChart(data) {
        // Implementation for region chart
        console.log('Region chart data:', data);
    }

    // ==============================================
    // Real-time Updates
    // ==============================================

    startRealTimeUpdates() {
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
        }

        this.realTimeInterval = setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboard();
            }
        }, 30000); // Update every 30 seconds
    }

    stopRealTimeUpdates() {
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
            this.realTimeInterval = null;
        }
    }

    // ==============================================
    // Export Methods
    // ==============================================

    async exportUsers() {
        try {
            const response = await this.apiCall('GET', '/users/export');
            
            // Create download link
            const blob = new Blob([JSON.stringify(response.data, null, 2)], 
                { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `users_export_${new Date().getTime()}.json`;
            a.click();
            
            window.URL.revokeObjectURL(url);
            this.showNotification('Users exported successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to export users: ' + error.message, 'error');
        }
    }

    // ==============================================
    // Bulk Actions
    // ==============================================

    showBulkActions() {
        this.showModal('bulkActionsModal');
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
function viewUser(userId) {
    console.log('View user:', userId);
}

function editUser(userId) {
    console.log('Edit user:', userId);
}

function banUser(userId) {
    adminPanel.banUser(userId);
}

function unbanUser(userId) {
    adminPanel.unbanUser(userId);
}

function viewChat(chatId) {
    console.log('View chat:', chatId);
}

function endChat(chatId) {
    adminPanel.endChat(chatId);
}

function viewReport(reportId) {
    console.log('View report:', reportId);
}

function approveReport(reportId) {
    adminPanel.approveReport(reportId);
}

function rejectReport(reportId) {
    adminPanel.rejectReport(reportId);
}

function removeBannedWord(wordId) {
    adminPanel.removeBannedWord(wordId);
}

function removeBannedCountry(code) {
    adminPanel.removeBannedCountry(code);
}

function testCoturnServer(serverId) {
    adminPanel.testCoturnServer(serverId);
}

function removeCoturnServer(serverId) {
    adminPanel.removeCoturnServer(serverId);
}

function showAdminMenu() {
    console.log('Show admin menu');
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
    adminPanel.loadChats();
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

function executeBulkAction() {
    adminPanel.executeBulkAction();
}

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminPanel = new AdminPanel();
});