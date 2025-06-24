// Функция для загрузки компонентов
async function loadComponent(elementId, componentPath) {
    try {
        console.log(`Loading component: ${elementId} from ${componentPath}`);
        const response = await fetch(componentPath);
        console.log(`Response status: ${response.status}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const html = await response.text();
        console.log(`Loaded HTML for ${elementId}:`, html.substring(0, 100) + '...');
        
        const element = document.getElementById(elementId);
        if (!element) {
            throw new Error(`Element with id '${elementId}' not found`);
        }
        
        element.innerHTML = html;
        console.log(`Successfully loaded component: ${elementId}`);
        
        // Если это header, инициализируем навигацию
        if (elementId === 'header') {
            // Ждем немного, чтобы DOM обновился
            setTimeout(() => {
                console.log('Initializing navigation...');
                updateNavigation();
                setupLogoutHandler();
            }, 100);
        }
    } catch (error) {
        console.error(`Error loading component ${componentPath}:`, error);
        // Показываем ошибку на странице
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<div style="color: red; padding: 10px; border: 1px solid red; background: #ffe6e6;">
                <strong>Ошибка загрузки компонента:</strong><br>
                ${error.message}<br>
                <small>Попробуйте обновить страницу</small>
            </div>`;
        }
    }
}

// Функция для инициализации всех компонентов
async function initializeComponents() {
    console.log('Initializing components...');
    try {
        await Promise.all([
            loadComponent('header', '/api/components/header'),
            loadComponent('footer', '/api/components/footer')
        ]);
        console.log('Components initialization completed');
    } catch (error) {
        console.error('Error during components initialization:', error);
    }
}

// Проверка авторизации и обновление навигации
async function updateNavigation() {
    try {
        console.log('Checking authentication status...');
        const response = await fetch('/api/auth/check', {
            credentials: 'include'
        });
        const data = await response.json();
        console.log('Auth check result:', data);
        
        const authLinks = document.getElementById('authLinks');
        const authLinks2 = document.getElementById('authLinks2');
        const profileLink = document.getElementById('profileLink');
        const logoutLink = document.getElementById('logoutLink');
        
        if (data.Success) {
            // Пользователь авторизован
            console.log('User is authenticated, showing profile/logout links');
            if (authLinks) authLinks.style.display = 'none';
            if (authLinks2) authLinks2.style.display = 'none';
            if (profileLink) profileLink.style.display = 'block';
            if (logoutLink) logoutLink.style.display = 'block';
        } else {
            // Пользователь не авторизован
            console.log('User is not authenticated, showing login/register links');
            if (authLinks) authLinks.style.display = 'block';
            if (authLinks2) authLinks2.style.display = 'block';
            if (profileLink) profileLink.style.display = 'none';
            if (logoutLink) logoutLink.style.display = 'none';
        }
    } catch (error) {
        console.error('Error checking auth:', error);
    }
}

// Настройка обработчика выхода
function setupLogoutHandler() {
    console.log('Setting up logout handler...');
    document.addEventListener('click', async (e) => {
        if (e.target.id === 'logoutBtn') {
            e.preventDefault();
            console.log('Logout button clicked');
            
            try {
                const response = await fetch('/logout', {
                    method: 'POST',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    console.log('Logout successful, redirecting to login');
                    window.location.href = '/login';
                } else {
                    console.error('Logout failed:', response.status);
                }
            } catch (error) {
                console.error('Logout error:', error);
            }
        }
    });
}

// Загружаем компоненты при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, starting components initialization');
    // Небольшая задержка для гарантии полной загрузки DOM
    setTimeout(() => {
        initializeComponents();
    }, 50);
}); 