const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

// Создание/подключение БД
const dbPath = './auth.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Ошибка подключения к БД:', err);
    process.exit(1);
  }
  console.log('Подключение к SQLite успешно');
  
  // Инициализация таблиц
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      uuid TEXT PRIMARY KEY,
      login TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      skin_path TEXT,
      cape_path TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expired DATETIME NOT NULL
    );

    CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      slug TEXT NOT NULL,
      url TEXT,
      content TEXT NOT NULL,
      author_id INTEGER,
      published_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      image TEXT,
      FOREIGN KEY (author_id) REFERENCES users(uuid)
    );
  `, (err) => {
    if (err) console.error('Ошибка создания таблиц:', err);
  });
});

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

// Настройка сессий
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: './'
  }),
  secret: 'minecraft-auth-secret',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false, // set to true if using https
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

// Middleware для логирования запросов
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log('Session:', req.session);
  next();
});

// Настройка загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'public/uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 2 // 2MB limit
  }
});

// Список администраторов
const ADMIN_USERS = ['admin', 'moderator']; // Добавьте сюда логины администраторов

// Middleware для проверки прав администратора
const requireAdmin = async (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ Message: 'Требуется авторизация' });
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT login FROM users WHERE uuid = ?', [req.session.userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user || !ADMIN_USERS.includes(user.login)) {
      return res.status(403).json({ Message: 'Недостаточно прав' });
    }

    next();
  } catch (error) {
    console.error('Error checking admin rights:', error);
    res.status(500).json({ Message: 'Ошибка сервера' });
  }
};

// Регистрация
app.post('/register', async (req, res) => {
  const { Login, Password } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(Password, 10);
    const uuid = crypto.randomUUID();
    
    db.run(
      'INSERT INTO users (uuid, login, password) VALUES (?, ?, ?)',
      [uuid, Login, hashedPassword],
      function(err) {
        if (err) {
          return res.status(500).json({ Message: 'Ошибка регистрации' });
          console.log(error);
        }
        res.json({ Message: 'Успешная регистрация' });
      }
    );
  } catch (error) {
    res.status(500).json({ Message: 'Ошибка сервера' });
    console.log(error);
  }
});

// Авторизация
app.post('/auth', (req, res) => {
  const { Login, Password } = req.body;
  
  db.get(
    'SELECT uuid, password FROM users WHERE login = ?',
    [Login],
    async (err, row) => {
      if (err || !row) {
        return res.status(401).json({ Message: 'Неверные данные' });
      }
      
      const match = await bcrypt.compare(Password, row.password);
      if (match) {
        res.json({
          Login: Login,
          UserUuid: row.uuid,
          Message: 'Успешная авторизация'
        });
      } else {
        res.status(401).json({ Message: 'Неверные данные' });
      }
    }
  );
});

// HTML форма регистрации
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/register.html'));
});

// HTML форма входа
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/login.html'));
});

// Middleware для проверки авторизации на сайте
const requireAuth = (req, res, next) => {
  console.log('Checking auth, session:', req.session);
  if (req.session && req.session.userId) {
    console.log('User is authenticated:', req.session.userId);
    next();
  } else {
    console.log('User is not authenticated');
    res.status(401).json({ Message: 'Требуется авторизация' });
  }
};

// Получение профиля пользователя
app.get('/api/profile', requireAuth, (req, res) => {
  console.log('Getting profile for user:', req.session.userId);
  db.get(
    'SELECT uuid, login, skin_path, cape_path FROM users WHERE uuid = ?',
    [req.session.userId],
    (err, row) => {
      if (err || !row) {
        console.log('Profile not found or error:', err);
        return res.status(404).json({ Message: 'Пользователь не найден' });
      }
      console.log('Profile found:', row);
      res.json(row);
    }
  );
});

// Обновление профиля пользователя
app.post('/api/profile', requireAuth, (req, res) => {
  const { login } = req.body;
  
  // Проверяем, не занят ли логин другим пользователем
  db.get(
    'SELECT uuid FROM users WHERE login = ? AND uuid != ?',
    [login, req.session.userId],
    (err, row) => {
      if (err) {
        console.error('Error checking login:', err);
        return res.status(500).json({ Message: 'Ошибка сервера' });
      }
      
      if (row) {
        return res.status(400).json({ Message: 'Этот логин уже занят' });
      }

      // Обновляем логин
      db.run(
        'UPDATE users SET login = ? WHERE uuid = ?',
        [login, req.session.userId],
        function(err) {
          if (err) {
            console.error('Error updating login:', err);
            return res.status(500).json({ Message: 'Ошибка обновления профиля' });
          }
          res.json({ Message: 'Профиль обновлен' });
        }
      );
    }
  );
});

// Получение скина по нику
app.get('/api/download/skin/:username', (req, res) => {
  const username = req.params.username;
  console.log('Getting skin for user:', username);

  db.get(
    'SELECT skin_path FROM users WHERE login = ?',
    [username],
    (err, row) => {
      if (err || !row || !row.skin_path) {
        console.log('Skin not found or error:', err);
        return res.status(404).send('Скин не найден');
      }

      const skinPath = path.join(__dirname, 'public', row.skin_path);
      if (fs.existsSync(skinPath)) {
        res.sendFile(skinPath);
      } else {
        res.status(404).send('Файл скина не найден');
      }
    }
  );
});

// Получение плаща по нику
app.get('/api/download/cape/:username', (req, res) => {
  const username = req.params.username;
  console.log('Getting cape for user:', username);

  db.get(
    'SELECT cape_path FROM users WHERE login = ?',
    [username],
    (err, row) => {
      if (err || !row || !row.cape_path) {
        console.log('Cape not found or error:', err);
        return res.status(404).send('Плащ не найден');
      }

      const capePath = path.join(__dirname, 'public', row.cape_path);
      if (fs.existsSync(capePath)) {
        res.sendFile(capePath);
      } else {
        res.status(404).send('Файл плаща не найден');
      }
    }
  );
});

// Загрузка скина
app.post('/api/upload/skin', requireAuth, upload.single('skin'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ Message: 'Файл не загружен' });
  }

  const skinPath = '/uploads/' + req.file.filename;
  
  db.run(
    'UPDATE users SET skin_path = ? WHERE uuid = ?',
    [skinPath, req.session.userId],
    function(err) {
      if (err) {
        console.error('Error uploading skin:', err);
        return res.status(500).json({ Message: 'Ошибка загрузки скина' });
      }
      res.json({ 
        Message: 'Скин успешно загружен', 
        path: skinPath,
        downloadUrl: `/api/download/skin/${req.session.userId}`
      });
    }
  );
});

// Загрузка плаща
app.post('/api/upload/cape', requireAuth, upload.single('cape'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ Message: 'Файл не загружен' });
  }

  const capePath = '/uploads/' + req.file.filename;
  
  db.run(
    'UPDATE users SET cape_path = ? WHERE uuid = ?',
    [capePath, req.session.userId],
    function(err) {
      if (err) {
        console.error('Error uploading cape:', err);
        return res.status(500).json({ Message: 'Ошибка загрузки плаща' });
      }
      res.json({ 
        Message: 'Плащ успешно загружен', 
        path: capePath,
        downloadUrl: `/api/download/cape/${req.session.userId}`
      });
    }
  );
});

// Авторизация на сайте
app.post('/login', async (req, res) => {
  const { Login, Password } = req.body;
  console.log('Login attempt for:', Login);
  
  db.get(
    'SELECT uuid, password FROM users WHERE login = ?',
    [Login],
    async (err, row) => {
      if (err || !row) {
        console.log('Login failed: User not found or error:', err);
        return res.status(401).json({ Message: 'Неверные данные' });
      }
      
      const match = await bcrypt.compare(Password, row.password);
      if (match) {
        console.log('Login successful for user:', row.uuid);
        req.session.userId = row.uuid;
        req.session.save((err) => {
          if (err) {
            console.error('Error saving session:', err);
            return res.status(500).json({ Message: 'Ошибка сервера' });
          }
          console.log('Session saved successfully');
          res.json({
            Message: 'Успешная авторизация'
          });
        });
      } else {
        console.log('Login failed: Invalid password');
        res.status(401).json({ Message: 'Неверные данные' });
      }
    }
  );
});

// Выход из аккаунта
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ Message: 'Ошибка выхода' });
    }
    res.json({ Message: 'Успешный выход' });
  });
});

// Страница личного кабинета
app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/profile.html'));
});

// API для новостей
// Получение списка новостей
app.get('/api/v1/integrations/news/list', (req, res) => {
  db.all(`
    SELECT 
      n.id,
      n.title,
      n.description,
      n.slug,
      n.url,
      n.content,
      strftime('%Y-%m-%dT%H:%M:%S+00:00', n.published_at) as published_at,
      n.image,
      u.login as author_name,
      u.uuid as author_id
    FROM news n
    LEFT JOIN users u ON n.author_id = u.uuid
    ORDER BY n.published_at DESC
  `, [], (err, rows) => {
    if (err) {
      console.error('Error fetching news:', err);
      return res.status(500).json({ Message: 'Ошибка получения новостей' });
    }
    var news_list = [];
    var index;
    for (index = 0; index <= rows.length - 1; ++index) {
      var row = rows[index];
      console.log(row.title);
      news_list.push({
        id: row.id,
        title: row.title,
        description: row.description,
        slug: row.slug,
        url: row.url || `https://your-domain.com/news/${row.slug}`,
        content: row.content,
        author: {
          id: 1, // Using a fixed numeric ID for compatibility
          name: row.author_name,
          role: {
            id: 2,
            name: "Админ",
            color: "#e10d11"
          },
          registered: row.published_at
        },
        published_at: row.published_at,
        image: row.image
      });
    }
    res.json(news_list);
  });
});

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Проверка авторизации
app.get('/api/auth/check', (req, res) => {
  if (req.session && req.session.userId) {
    db.get('SELECT login FROM users WHERE uuid = ?', [req.session.userId], (err, row) => {
      if (err || !row) {
        return res.json({ Success: false });
      }
      res.json({ 
        Success: true,
        IsAdmin: ADMIN_USERS.includes(row.login)
      });
    });
  } else {
    res.json({ Success: false });
  }
});

// Добавление новости (только для администраторов)
app.post('/api/news', requireAdmin, (req, res) => {
  const { title, description, content, image } = req.body;
  
  if (!title || !description || !content) {
    return res.status(400).json({ Message: 'Заголовок, описание и содержание обязательны' });
  }

  // Создаем slug из заголовка
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
  
  db.run(
    `INSERT INTO news (
      title, description, slug, content, author_id, image
    ) VALUES (?, ?, ?, ?, ?, ?)`,
    [title, description, slug, content, req.session.userId, image],
    function(err) {
      if (err) {
        console.error('Error adding news:', err);
        return res.status(500).json({ Message: 'Ошибка добавления новости' });
      }
      res.json({ Message: 'Новость успешно добавлена' });
    }
  );
});

// Удаление новости (только для администраторов)
app.delete('/api/news/:id', requireAdmin, (req, res) => {
  const newsId = req.params.id;
  
  db.run(
    'DELETE FROM news WHERE id = ?',
    [newsId],
    function(err) {
      if (err) {
        console.error('Error deleting news:', err);
        return res.status(500).json({ Message: 'Ошибка удаления новости' });
      }
      res.json({ Message: 'Новость успешно удалена' });
    }
  );
});

const PORT = 5013;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});