import { api } from './api.js';

class EmailService {
    async getEmails() {
        return await api.get('/emails/');
    }

    async getEmailById(id) {
        return await api.get(`/email/${id}/`);
    }

    async sendEmail(emailData) {
        return await api.post('/emails/send/', emailData);
    }

    async deleteEmail(id) {
        return await api.delete(`/email/${id}/delete/`);
    }

    async updateEmailStatus(id, status) {
        return await api.put(`/email/${id}/status/`, { status });
    }
}

export const emailService = new EmailService();
