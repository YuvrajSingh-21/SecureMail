import { api } from './api.js';

class RiskService {
    async scanUrl(url) {
        return await api.post('/scan/url/', { url });
    }

    async scanFile(file) {
        // In real app, this would be a multipart/form-data request
        return await api.post('/scan/file/', { filename: file.name });
    }

    async analyzeEmail(emailContent) {
        return await api.post('/scan/email/', { content: emailContent });
    }
}

export const riskService = new RiskService();
