/**
 * Omegle Admin Panel JavaScript - COMPLETE ROBUST VERSION
 * Handles all DOM element access safely with proper error handling
 */

class AdminPanel {
    constructor() {
        this.baseURL = '/admin/api';
        this.authURL = '/admin/api/auth';
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
    // SAFE DOM HELPERS
    // ==============================================

    // Safe element getter - returns null if not found
    safeGetElement(id) {
        const element = document.getElementById(id);
        if (!element) {
            console.warn(`Element with ID '${id}' not found in DOM`);
        }
        return element;
    }

    // Safe text content update
    safeUpdateText(id, value) {
        const element = this.safeGetElement(id);
        if (element) {
            element.textContent = value;
            console.log(`Updated ${id}:`, value);
            return true;
        }
        return false;
    }

    // Safe innerHTML update
    safeUpdateHTML(id, html) {
        const element = this.safeGetElement(id);
        if (element) {
            element.innerHTML = html;
            return true;
        }
        return false;
    }

    // Safe element display toggle
    safeToggleDisplay(id, display = 'block') {
        const element = this.safeGetElement(id);
        if (element) {
            element.style.display = element.style.display === 'none' ? display : 'none';
            return true;
        }
        return false;
    }

    // Safe element show/hide
    safeShow(id, display = 'block') {
        const element = this.safeGetElement(id);
        if (element) {
            element.style.display = display;
            return true;
        }
        return false;
    }

    safeHide(id) {
        const element = this.safeGetElement(id);
        if (element) {
            element.style.display = 'none';
            return true;
        }
        return false;
    }

    // Safe class manipulation
    safeAddClass(id, className) {
        const element = this.safeGetElement(id);
        if (element) {
            element.classList.add(className);
            return true;
        }
        return false;
    }

    safeRemoveClass(id, className) {
        const element = this.safeGetElement(id);
        if (element) {
            element.classList.remove(className);
            return true;
        }
        return false;
    }

    // ==============================================
    // EVENT LISTENERS
    // ==============================================

    setupEventListeners() {
        // Login form
        const loginForm = this.safeGetElement('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = this.safeGetElement('username')?.value || '';
                const password = this.safeGetElement('password')?.value || '';
                if (username && password) {
                    this.login(username, password);
                }
            });
        }

        // Navigation links
        document.querySelectorAll('[data-section]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = e.currentTarget.getAttribute('data-section');
                if (section) {
                    this.navigateToSection(section);
                }
            });
        });

        // Sidebar toggle
        const sidebarToggle = this.safeGetElement('sidebarToggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => this.toggleSidebar());
        }

        // Settings forms
        const appSettingsForm = this.safeGetElement('appSettingsForm');
        if (appSettingsForm) {
            appSettingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveAppSettings();
            });
        }

        const moderationSettingsForm = this.safeGetElement('moderationSettingsForm');
        if (moderationSettingsForm) {
            moderationSettingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveModerationSettings();
            });
        }
    }

    // ==============================================
    // AUTHENTICATION METHODS
    // ==============================================

    checkAuthentication() {
        if (!this.token) {
            this.showLogin();
            return;
        }

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
            console.warn('Token verification failed:', error.message);
            return false;
        }
    }

    showLogin() {
        this.safeHide('loadingScreen');
        this.safeShow('loginModal', 'flex');
        this.safeHide('adminContainer');
    }

    showAdminPanel() {
        this.safeHide('loadingScreen');
        this.safeHide('loginModal');
        this.safeShow('adminContainer', 'flex');
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
            if (this.token) {
                await this.authCall('POST', '/logout');
            }
        } catch (error) {
            console.warn('Logout API call failed:', error.message);
        } finally {
            localStorage.removeItem('admin_token');
            this.token = null;
            this.stopRealTimeUpdates();
            this.showLogin();
            this.showNotification('Logged out successfully', 'info');
        }
    }

    // ==============================================
    // API METHODS
    // ==============================================

    async apiCall(method, endpoint, data = null) {
        try {
            const headers = {
                'Content-Type': 'application/json',
            };
            
            if (this.token) {
                headers['Authorization'] = `Bearer ${this.token}`;
            }

            const options = {
                method,
                headers
            };

            if (data && (method === 'POST' || method === 'PUT')) {
                options.body = JSON.stringify(data);
            }

            console.log(`API Call: ${method} ${this.baseURL + endpoint}`);
            const response = await fetch(this.baseURL + endpoint, options);
            
            if (response.status === 401) {
                console.warn('Authentication expired');
                localStorage.removeItem('admin_token');
                this.token = null;
                this.showLogin();
                throw new Error('Authentication expired');
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`API Response:`, result);
            return result;
        } catch (error) {
            console.error('API call error:', error);
            throw error;
        }
    }

    async authCall(method, endpoint, data = null) {
        try {
            const headers = {
                'Content-Type': 'application/json',
            };
            
            if (this.token && (endpoint === '/verify' || endpoint === '/logout')) {
                headers['Authorization'] = `Bearer ${this.token}`;
            }

            const options = {
                method,
                headers
            };

            if (data) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(this.authURL + endpoint, options);
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.message || 'Auth call failed');
            }

            return result;
        } catch (error) {
            console.error('Auth call error:', error);
            throw error;
        }
    }

    // ==============================================
    // NAVIGATION
    // ==============================================

    navigateToSection(section) {
        // Remove active class from all nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to current link
        const currentLink = document.querySelector(`[data-section="${section}"]`);
        if (currentLink) {
            currentLink.classList.add('active');
        }

        // Hide all sections
        document.querySelectorAll('.section-content').forEach(content => {
            content.style.display = 'none';
        });

        // Show selected section
        this.safeShow(section + 'Section');

        this.currentSection = section;
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
        const sidebar = this.safeGetElement('sidebar');
        const mainContent = this.safeGetElement('mainContent');
        
        if (sidebar) sidebar.classList.toggle('collapsed');
        if (mainContent) mainContent.classList.toggle('expanded');
    }

    // ==============================================
    // DASHBOARD METHODS
    // ==============================================

    async loadDashboard() {
        try {
            console.log('Loading dashboard...');
            
            const statsPromise = this.apiCall('GET', '/dashboard/stats').catch(err => {
                console.warn('Stats endpoint failed:', err.message);
                return { data: {} };
            });
            
            const realtimePromise = this.apiCall('GET', '/dashboard/realtime').catch(err => {
                console.warn('Realtime endpoint failed:', err.message);
                return { data: {} };
            });

            const [stats, realtimeStats] = await Promise.all([statsPromise, realtimePromise]);

            this.updateDashboardStats(stats.data || {});
            this.updateRealtimeStats(realtimeStats.data || {});
            
            this.loadDashboardCharts().catch(err => {
                console.warn('Charts failed to load:', err.message);
            });
            
            console.log('Dashboard loaded successfully');
        } catch (error) {
            console.error('Dashboard loading error:', error);
            this.showNotification('Failed to load dashboard: ' + error.message, 'error');
        }
    }

    updateDashboardStats(stats) {
        console.log('Updating dashboard stats:', stats);
        
        // Update all stats safely with flexible field mapping
        this.safeUpdateText('totalUsers', stats.total_users || 0);
        this.safeUpdateText('activeUsers', stats.active_users || stats.online_users || 0);
        this.safeUpdateText('totalChats', stats.total_chats || 0);
        this.safeUpdateText('activeChats', stats.active_chats || 0);
        this.safeUpdateText('totalMessages', stats.total_messages || 0);
        this.safeUpdateText('bannedUsers', stats.banned_users || 0);
        this.safeUpdateText('reportsToday', stats.reports_today || stats.reports_count || 0);
        this.safeUpdateText('avgChatDuration', (stats.avg_chat_duration || stats.avg_chat_time || 0) + 'm');
    }

    updateRealtimeStats(stats) {
        console.log('Updating realtime stats:', stats);
        
        this.safeUpdateText('usersOnline', stats.users_online || stats.online_users || 0);
        this.safeUpdateText('queueLength', stats.queue_length || stats.queue_size || 0);
        this.safeUpdateText('avgWaitTime', (stats.avg_wait_time || 0) + 's');
    }

    async loadDashboardCharts() {
        try {
            const [userChart, chatChart, regionChart] = await Promise.all([
                this.apiCall('GET', '/dashboard/chart/users').catch(() => ({ data: {} })),
                this.apiCall('GET', '/dashboard/chart/chats').catch(() => ({ data: {} })),
                this.apiCall('GET', '/dashboard/chart/regions').catch(() => ({ data: {} }))
            ]);

            this.updateUserChart(userChart.data);
            this.updateChatChart(chatChart.data);
            this.updateRegionChart(regionChart.data);
        } catch (error) {
            console.error('Failed to load charts:', error);
        }
    }

    // ==============================================
    // USER MANAGEMENT METHODS
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
        if (!data || !data.users) {
            console.warn('No users data received');
            return;
        }

        const tbody = this.safeGetElement('usersTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <input type="checkbox" class="user-checkbox" value="${user.id || ''}">
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
                        ${user.status || 'unknown'}
                    </span>
                </td>
                <td>${user.region || 'Unknown'}</td>
                <td>${user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}</td>
                <td>${user.last_active ? new Date(user.last_active).toLocaleDateString() : 'N/A'}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewUser('${user.id || ''}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-warning" onclick="editUser('${user.id || ''}')">
                            <i class="fas fa-edit"></i>
                        </button>
                        ${user.status !== 'banned' ? 
                            `<button class="btn btn-sm btn-outline-danger" onclick="banUser('${user.id || ''}')">
                                <i class="fas fa-ban"></i>
                            </button>` : 
                            `<button class="btn btn-sm btn-outline-success" onclick="unbanUser('${user.id || ''}')">
                                <i class="fas fa-check"></i>
                            </button>`
                        }
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        // Update pagination
        this.updatePagination('usersPagination', data.meta || {});
    }

    // ==============================================
    // CHAT MANAGEMENT METHODS
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
        if (!data || !data.chats) {
            console.warn('No chats data received');
            return;
        }

        const tbody = this.safeGetElement('chatsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.chats.forEach(chat => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${chat.id || ''}</td>
                <td>${chat.participants?.length || 0}</td>
                <td>
                    <span class="badge ${chat.status === 'active' ? 'badge-success' : 'badge-secondary'}">
                        ${chat.status || 'unknown'}
                    </span>
                </td>
                <td>${chat.region || 'Unknown'}</td>
                <td>${chat.duration || '0m'}</td>
                <td>${chat.created_at ? new Date(chat.created_at).toLocaleDateString() : 'N/A'}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewChat('${chat.id || ''}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${chat.status === 'active' ? 
                            `<button class="btn btn-sm btn-outline-danger" onclick="endChat('${chat.id || ''}')">
                                <i class="fas fa-stop"></i>
                            </button>` : ''
                        }
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        this.updatePagination('chatsPagination', data.meta || {});
    }

    // ==============================================
    // REPORTS MANAGEMENT
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
        if (!data || !data.reports) {
            console.warn('No reports data received');
            return;
        }

        const tbody = this.safeGetElement('reportsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        data.reports.forEach(report => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${report.id || ''}</td>
                <td>${report.type || 'Unknown'}</td>
                <td>${report.reported_user || 'Unknown'}</td>
                <td>${report.reason || 'No reason'}</td>
                <td>
                    <span class="badge ${report.status === 'pending' ? 'badge-warning' : 
                        report.status === 'resolved' ? 'badge-success' : 'badge-secondary'}">
                        ${report.status || 'unknown'}
                    </span>
                </td>
                <td>${report.created_at ? new Date(report.created_at).toLocaleDateString() : 'N/A'}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="viewReport('${report.id || ''}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        ${report.status === 'pending' ? 
                            `<button class="btn btn-sm btn-outline-success" onclick="approveReport('${report.id || ''}')">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="rejectReport('${report.id || ''}')">
                                <i class="fas fa-times"></i>
                            </button>` : ''
                        }
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });

        this.updatePagination('reportsPagination', data.meta || {});
    }

    // ==============================================
    // SETTINGS METHODS
    // ==============================================

    async loadSettings() {
        try {
            const [appSettings, moderationSettings] = await Promise.all([
                this.apiCall('GET', '/settings/app').catch(() => ({ data: {} })),
                this.apiCall('GET', '/settings/moderation').catch(() => ({ data: {} }))
            ]);

            this.displayAppSettings(appSettings.data || {});
            this.displayModerationSettings(moderationSettings.data || {});
        } catch (error) {
            this.showNotification('Failed to load settings: ' + error.message, 'error');
        }
    }

    displayAppSettings(settings) {
        this.safeUpdateText('appName', settings.app_name || '');
        this.safeUpdateText('maxUsers', settings.max_users || '');
        this.safeUpdateText('chatTimeout', settings.chat_timeout || '');
        this.safeUpdateText('minAge', settings.min_age || '');
        
        // For input fields
        const appNameInput = this.safeGetElement('appName');
        const maxUsersInput = this.safeGetElement('maxUsers');
        const chatTimeoutInput = this.safeGetElement('chatTimeout');
        const minAgeInput = this.safeGetElement('minAge');
        
        if (appNameInput) appNameInput.value = settings.app_name || '';
        if (maxUsersInput) maxUsersInput.value = settings.max_users || '';
        if (chatTimeoutInput) chatTimeoutInput.value = settings.chat_timeout || '';
        if (minAgeInput) minAgeInput.value = settings.min_age || '';
    }

    displayModerationSettings(settings) {
        const autoModerationInput = this.safeGetElement('autoModeration');
        const profanityFilterInput = this.safeGetElement('profanityFilter');
        const ageVerificationInput = this.safeGetElement('ageVerification');
        
        if (autoModerationInput) autoModerationInput.checked = settings.auto_moderation || false;
        if (profanityFilterInput) profanityFilterInput.checked = settings.profanity_filter || false;
        if (ageVerificationInput) ageVerificationInput.checked = settings.age_verification || false;
    }

    async saveAppSettings() {
        const appNameInput = this.safeGetElement('appName');
        const maxUsersInput = this.safeGetElement('maxUsers');
        const chatTimeoutInput = this.safeGetElement('chatTimeout');
        const minAgeInput = this.safeGetElement('minAge');

        const settings = {
            app_name: appNameInput?.value || '',
            max_users: parseInt(maxUsersInput?.value || '0'),
            chat_timeout: parseInt(chatTimeoutInput?.value || '0'),
            min_age: parseInt(minAgeInput?.value || '0')
        };

        try {
            await this.apiCall('PUT', '/settings/app', settings);
            this.showNotification('App settings saved successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to save app settings: ' + error.message, 'error');
        }
    }

    async saveModerationSettings() {
        const autoModerationInput = this.safeGetElement('autoModeration');
        const profanityFilterInput = this.safeGetElement('profanityFilter');
        const ageVerificationInput = this.safeGetElement('ageVerification');

        const settings = {
            auto_moderation: autoModerationInput?.checked || false,
            profanity_filter: profanityFilterInput?.checked || false,
            age_verification: ageVerificationInput?.checked || false
        };

        try {
            await this.apiCall('PUT', '/settings/moderation', settings);
            this.showNotification('Moderation settings saved successfully', 'success');
        } catch (error) {
            this.showNotification('Failed to save moderation settings: ' + error.message, 'error');
        }
    }

    // ==============================================
    // CONTENT MANAGEMENT
    // ==============================================

    async loadContentManagement() {
        try {
            const [bannedWords, bannedCountries] = await Promise.all([
                this.apiCall('GET', '/content/banned-words').catch(() => ({ data: [] })),
                this.apiCall('GET', '/content/banned-countries').catch(() => ({ data: [] }))
            ]);

            this.displayBannedWords(bannedWords.data || []);
            this.displayBannedCountries(bannedCountries.data || []);
        } catch (error) {
            this.showNotification('Failed to load content management: ' + error.message, 'error');
        }
    }

    displayBannedWords(words) {
        const container = this.safeGetElement('bannedWordsList');
        if (!container) return;

        container.innerHTML = '';
        words.forEach(word => {
            const div = document.createElement('div');
            div.className = 'banned-word-item';
            div.innerHTML = `
                <span>${word.word || ''}</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeBannedWord('${word.id || ''}')">
                    <i class="fas fa-times"></i>
                </button>
            `;
            container.appendChild(div);
        });
    }

    displayBannedCountries(countries) {
        const container = this.safeGetElement('bannedCountriesList');
        if (!container) return;

        container.innerHTML = '';
        countries.forEach(country => {
            const div = document.createElement('div');
            div.className = 'banned-country-item';
            div.innerHTML = `
                <span>${country.name || ''} (${country.code || ''})</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeBannedCountry('${country.code || ''}')">
                    <i class="fas fa-times"></i>
                </button>
            `;
            container.appendChild(div);
        });
    }

    // ==============================================
    // COTURN MANAGEMENT
    // ==============================================

    async loadCoturnServers() {
        try {
            const response = await this.apiCall('GET', '/system/coturn');
            this.displayCoturnServers(response.data || []);
        } catch (error) {
            this.showNotification('Failed to load COTURN servers: ' + error.message, 'error');
        }
    }

    displayCoturnServers(servers) {
        const tbody = this.safeGetElement('coturnTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        servers.forEach(server => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${server.name || ''}</td>
                <td>${server.region || ''}</td>
                <td>${server.url || ''}</td>
                <td>
                    <span class="badge ${server.status === 'active' ? 'badge-success' : 'badge-danger'}">
                        ${server.status || 'unknown'}
                    </span>
                </td>
                <td>${server.last_check ? new Date(server.last_check).toLocaleString() : 'Never'}</td>
                <td>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-primary" onclick="testCoturnServer('${server.id || ''}')">
                            <i class="fas fa-check"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" onclick="removeCoturnServer('${server.id || ''}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // ==============================================
    // ANALYTICS
    // ==============================================

    async loadAnalytics() {
        try {
            const analytics = await this.apiCall('GET', '/analytics/overview').catch(() => ({ data: {} }));
            this.displayAnalytics(analytics.data || {});
        } catch (error) {
            this.showNotification('Failed to load analytics: ' + error.message, 'error');
        }
    }

    displayAnalytics(data) {
        this.safeUpdateText('analyticsUsers', data.total_users || 0);
        this.safeUpdateText('analyticsChats', data.total_chats || 0);
        this.safeUpdateText('analyticsMessages', data.total_messages || 0);
        this.safeUpdateText('analyticsUptime', data.uptime || '0h');
    }

    // ==============================================
    // SYSTEM INFO
    // ==============================================

    async loadSystemInfo() {
        try {
            const systemInfo = await this.apiCall('GET', '/system/info').catch(() => ({ data: {} }));
            this.displaySystemInfo(systemInfo.data || {});
        } catch (error) {
            this.showNotification('Failed to load system info: ' + error.message, 'error');
        }
    }

    displaySystemInfo(info) {
        this.safeUpdateText('systemUptime', info.uptime || '0');
        this.safeUpdateText('memoryUsage', info.memory_usage || '0%');
        this.safeUpdateText('cpuUsage', info.cpu_usage || '0%');
        this.safeUpdateText('diskUsage', info.disk_usage || '0%');
        this.safeUpdateText('dbConnections', info.db_connections || '0');
        this.safeUpdateText('activeWebsockets', info.active_websockets || '0');
    }

    // ==============================================
    // HELPER METHODS
    // ==============================================

    updatePagination(containerId, meta) {
        const container = this.safeGetElement(containerId);
        if (!container || !meta) return;

        const currentPage = meta.page || 1;
        const totalPages = meta.total_pages || 1;

        container.innerHTML = `
            <div class="pagination-info">
                Page ${currentPage} of ${totalPages} (${meta.total || 0} total)
            </div>
            <div class="pagination-controls">
                <button class="btn btn-sm btn-outline-primary" 
                        ${currentPage <= 1 ? 'disabled' : ''} 
                        onclick="adminPanel.loadCurrentSection(${currentPage - 1})">
                    Previous
                </button>
                <button class="btn btn-sm btn-outline-primary" 
                        ${currentPage >= totalPages ? 'disabled' : ''} 
                        onclick="adminPanel.loadCurrentSection(${currentPage + 1})">
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

    // ==============================================
    // REAL-TIME UPDATES
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
    // MODAL AND UI METHODS
    // ==============================================

    closeModal() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.style.display = 'none';
        });
    }

    showModal(modalId) {
        this.safeShow(modalId, 'flex');
    }

    // ==============================================
    // CHART METHODS
    // ==============================================

    initializeCharts() {
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js not loaded');
            return;
        }
        // Charts will be implemented when containers are available
    }

    updateUserChart(data) {
        console.log('User chart data:', data);
        // Implement chart update
    }

    updateChatChart(data) {
        console.log('Chat chart data:', data);
        // Implement chart update
    }

    updateRegionChart(data) {
        console.log('Region chart data:', data);
        // Implement chart update
    }

    // ==============================================
    // NOTIFICATION SYSTEM
    // ==============================================

    showNotification(message, type = 'info') {
        console.log(`Notification [${type}]:`, message);
        
        let notificationContainer = this.safeGetElement('notificationContainer');
        if (!notificationContainer) {
            notificationContainer = document.createElement('div');
            notificationContainer.id = 'notificationContainer';
            notificationContainer.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 400px;
            `;
            document.body.appendChild(notificationContainer);
        }

        const notification = document.createElement('div');
        notification.style.cssText = `
            background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
            color: white;
            padding: 12px 16px;
            border-radius: 4px;
            margin-bottom: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            opacity: 0;
            transition: opacity 0.3s ease;
        `;
        notification.textContent = message;

        notificationContainer.appendChild(notification);

        setTimeout(() => notification.style.opacity = '1', 10);

        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }

    // ==============================================
    // EXPORT METHODS
    // ==============================================

    async exportUsers() {
        try {
            const response = await this.apiCall('GET', '/users/export');
            
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
}

// ==============================================
// GLOBAL FUNCTIONS (for onclick handlers)
// ==============================================

function viewUser(userId) {
    console.log('View user:', userId);
    // Implement user view modal
}

function editUser(userId) {
    console.log('Edit user:', userId);
    // Implement user edit modal
}

function banUser(userId) {
    if (confirm('Are you sure you want to ban this user?')) {
        window.adminPanel.apiCall('POST', `/users/${userId}/ban`)
            .then(() => {
                window.adminPanel.showNotification('User banned successfully', 'success');
                window.adminPanel.loadUsers();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to ban user: ' + error.message, 'error');
            });
    }
}

function unbanUser(userId) {
    if (confirm('Are you sure you want to unban this user?')) {
        window.adminPanel.apiCall('DELETE', `/users/${userId}/ban`)
            .then(() => {
                window.adminPanel.showNotification('User unbanned successfully', 'success');
                window.adminPanel.loadUsers();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to unban user: ' + error.message, 'error');
            });
    }
}

function viewChat(chatId) {
    console.log('View chat:', chatId);
    // Implement chat view modal
}

function endChat(chatId) {
    if (confirm('Are you sure you want to end this chat?')) {
        window.adminPanel.apiCall('POST', `/chats/${chatId}/end`)
            .then(() => {
                window.adminPanel.showNotification('Chat ended successfully', 'success');
                window.adminPanel.loadChats();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to end chat: ' + error.message, 'error');
            });
    }
}

function viewReport(reportId) {
    console.log('View report:', reportId);
    // Implement report view modal
}

function approveReport(reportId) {
    window.adminPanel.apiCall('POST', `/reports/${reportId}/resolve`)
        .then(() => {
            window.adminPanel.showNotification('Report approved successfully', 'success');
            window.adminPanel.loadReports();
        })
        .catch(error => {
            window.adminPanel.showNotification('Failed to approve report: ' + error.message, 'error');
        });
}

function rejectReport(reportId) {
    window.adminPanel.apiCall('POST', `/reports/${reportId}/dismiss`)
        .then(() => {
            window.adminPanel.showNotification('Report rejected successfully', 'success');
            window.adminPanel.loadReports();
        })
        .catch(error => {
            window.adminPanel.showNotification('Failed to reject report: ' + error.message, 'error');
        });
}

function removeBannedWord(wordId) {
    if (confirm('Are you sure you want to remove this banned word?')) {
        window.adminPanel.apiCall('DELETE', `/content/banned-words/${wordId}`)
            .then(() => {
                window.adminPanel.showNotification('Banned word removed successfully', 'success');
                window.adminPanel.loadContentManagement();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to remove banned word: ' + error.message, 'error');
            });
    }
}

function removeBannedCountry(code) {
    if (confirm('Are you sure you want to remove this banned country?')) {
        window.adminPanel.apiCall('DELETE', `/content/banned-countries/${code}`)
            .then(() => {
                window.adminPanel.showNotification('Banned country removed successfully', 'success');
                window.adminPanel.loadContentManagement();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to remove banned country: ' + error.message, 'error');
            });
    }
}

function testCoturnServer(serverId) {
    window.adminPanel.apiCall('POST', `/system/coturn/${serverId}/test`)
        .then(() => {
            window.adminPanel.showNotification('COTURN server test initiated', 'info');
            window.adminPanel.loadCoturnServers();
        })
        .catch(error => {
            window.adminPanel.showNotification('Failed to test COTURN server: ' + error.message, 'error');
        });
}

function removeCoturnServer(serverId) {
    if (confirm('Are you sure you want to remove this COTURN server?')) {
        window.adminPanel.apiCall('DELETE', `/system/coturn/${serverId}`)
            .then(() => {
                window.adminPanel.showNotification('COTURN server removed successfully', 'success');
                window.adminPanel.loadCoturnServers();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to remove COTURN server: ' + error.message, 'error');
            });
    }
}

function logout() {
    window.adminPanel.logout();
}

function exportUsers() {
    window.adminPanel.exportUsers();
}

function showBulkActions() {
    console.log('Show bulk actions');
    // Implement bulk actions modal
}

function refreshChats() {
    window.adminPanel.loadChats();
}

function addBannedWord() {
    const word = prompt('Enter word to ban:');
    if (word) {
        window.adminPanel.apiCall('POST', '/content/banned-words', { word })
            .then(() => {
                window.adminPanel.showNotification('Banned word added successfully', 'success');
                window.adminPanel.loadContentManagement();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to add banned word: ' + error.message, 'error');
            });
    }
}

function addBannedCountry() {
    const code = prompt('Enter country code to ban (e.g., US):');
    if (code) {
        window.adminPanel.apiCall('POST', '/content/banned-countries', { code })
            .then(() => {
                window.adminPanel.showNotification('Banned country added successfully', 'success');
                window.adminPanel.loadContentManagement();
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to add banned country: ' + error.message, 'error');
            });
    }
}

function addCoturnServer() {
    console.log('Add COTURN server');
    // Implement add COTURN server modal
}

function clearCache() {
    if (confirm('Are you sure you want to clear the cache?')) {
        window.adminPanel.apiCall('POST', '/system/cache/clear')
            .then(() => {
                window.adminPanel.showNotification('Cache cleared successfully', 'success');
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to clear cache: ' + error.message, 'error');
            });
    }
}

function cleanupDatabase() {
    if (confirm('Are you sure you want to cleanup the database?')) {
        window.adminPanel.apiCall('POST', '/system/database/cleanup')
            .then(() => {
                window.adminPanel.showNotification('Database cleanup completed successfully', 'success');
            })
            .catch(error => {
                window.adminPanel.showNotification('Failed to cleanup database: ' + error.message, 'error');
            });
    }
}

function createBackup() {
    window.adminPanel.apiCall('POST', '/system/backup')
        .then(() => {
            window.adminPanel.showNotification('Backup created successfully', 'success');
        })
        .catch(error => {
            window.adminPanel.showNotification('Failed to create backup: ' + error.message, 'error');
        });
}

function enableMaintenanceMode() {
    const message = prompt('Enter maintenance message (optional):') || 'System maintenance in progress';
    window.adminPanel.apiCall('POST', '/system/maintenance', { enabled: true, message })
        .then(() => {
            window.adminPanel.showNotification('Maintenance mode enabled', 'info');
        })
        .catch(error => {
            window.adminPanel.showNotification('Failed to enable maintenance mode: ' + error.message, 'error');
        });
}

function closeModal() {
    window.adminPanel.closeModal();
}

function executeBulkAction() {
    console.log('Execute bulk action');
    // Implement bulk action execution
}

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.adminPanel = new AdminPanel();
});