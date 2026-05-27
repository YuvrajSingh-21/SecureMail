import { api } from './api.js';

class AuthService {
    async login(email, password) {
        return await api.post('/auth/login', { email, password });
    }

    async register(userData) {
        return await api.post('/auth/register', userData);
    }

    async logout() {
        return await api.post('/auth/logout');
    }

    async getCurrentUser() {
        return await api.get('/auth/user');
    }
}

export const authService = new AuthService();
