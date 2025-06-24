// Функция для загрузки компонентов
async function loadComponent(elementId, componentPath) {
    try {
        const response = await fetch(componentPath);
        const html = await response.text();
        document.getElementById(elementId).innerHTML = html;
        
        // Если это header, инициализируем навигацию
        if (elementId === 'header') {
            // Ждем немного, чтобы DOM обновился
            setTimeout(() => {
                if (typeof updateNavigation === 'function') {
                    updateNavigation();
                }
            }, 100);
        }
    } catch (error) {
        console.error(`Error loading component ${componentPath}:`, error);
    }
}

// Функция для инициализации всех компонентов
async function initializeComponents() {
    await Promise.all([
        loadComponent('header', '/api/components/header'),
        loadComponent('footer', '/api/components/footer')
    ]);
}

// Загружаем компоненты при загрузке страницы
document.addEventListener('DOMContentLoaded', initializeComponents); 