/**
 * Base API Service for future backend integration.
 * Currently uses mock data.
 */

const BASE_URL = '/api';

class ApiService {
    async get(endpoint) {
        console.log(`GET ${BASE_URL}${endpoint}`);
        const response = await fetch(`${BASE_URL}${endpoint}`);
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
    }

    async post(endpoint, data) {
        console.log(`POST ${BASE_URL}${endpoint}`, data);
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this._getCookie('csrftoken')
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
    }

    async put(endpoint, data) {
        console.log(`PUT ${BASE_URL}${endpoint}`, data);
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this._getCookie('csrftoken')
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
    }

    async delete(endpoint) {
        console.log(`DELETE ${BASE_URL}${endpoint}`);
        const response = await fetch(`${BASE_URL}${endpoint}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': this._getCookie('csrftoken')
            }
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return { success: true };
    }

    _getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
}

export const api = new ApiService();
