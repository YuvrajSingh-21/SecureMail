import { api } from './api.js';

class ReportService {
    async getThreatStats() {
        return await api.get('/reports/stats/');
    }

    async getTopThreatDomains() {
        return await api.get('/reports/domains/');
    }

    async getWeeklyTrend() {
        return await api.get('/reports/trend/');
    }
}

export const reportService = new ReportService();
