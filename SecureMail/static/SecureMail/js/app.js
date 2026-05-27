/**
 * Main application logic for component loading and common utilities.
 */

export function toggleDarkMode() {
    const html = document.documentElement;
    const body = document.body;
    const currentTheme = html.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);

    if (newTheme === 'dark') {
        body.className = 'h-full overflow-auto dark-mode bg-gray-900';
        html.classList.add('dark');
    } else {
        body.className = 'h-full overflow-auto light-mode bg-slate-50';
        html.classList.remove('dark');
    }

    updateThemeIcon(newTheme === 'dark');
}

export function updateThemeIcon(isDark) {
    const themeIcon = document.querySelector('[data-theme-icon]');
    if (themeIcon) {
        themeIcon.setAttribute('data-lucide', isDark ? 'sun' : 'moon');
        if (window.lucide) {
            window.lucide.createIcons();
        }
    }
}

// Global attachment for reliability
window.toggleDarkMode = toggleDarkMode;
window.updateThemeIcon = updateThemeIcon;

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    
    // Initial icon state
    updateThemeIcon(savedTheme === 'dark');
    
    // Attach listeners to ALL theme toggle buttons
    const themeToggleBtns = document.querySelectorAll('[data-theme-toggle]');
    themeToggleBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            toggleDarkMode();
        });
    });
    
    // Mobile menu toggle
    const menuBtn = document.querySelector('button[data-mobile-menu]');
    if (menuBtn) {
        menuBtn.addEventListener('click', () => {
            const sidebar = document.querySelector('aside');
            if (sidebar) {
                sidebar.classList.toggle('hidden');
                sidebar.classList.toggle('fixed');
                sidebar.classList.toggle('inset-0');
                sidebar.classList.toggle('z-50');
            }
        });
    }

    if (window.lucide) {
        window.lucide.createIcons();
    }
});

export async function loadComponent(id, path) {
    try {
        const response = await fetch(path);
        const html = await response.text();
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = html;
            if (window.lucide) {
                window.lucide.createIcons();
            }
        }
    } catch (error) {
        console.error(`Error loading component from ${path}:`, error);
    }
}
