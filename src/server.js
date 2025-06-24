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
const winston = require('winston');

// Настройка логирования
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Создаем логгер
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss'
        }),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'minecraft-auth' },
    transports: [
        // Лог всех сообщений в combined.log
        new winston.transports.File({
            filename: path.join(logDir, 'combined.log'),
            maxsize: 5 * 1024 * 1024, // 5MB
            maxFiles: 5,
            tailable: true
        }),
        // Лог ошибок в error.log
        new winston.transports.File({
            filename: path.join(logDir, 'error.log'),
            level: 'error',
            maxsize: 5 * 1024 * 1024, // 5MB
            maxFiles: 5,
            tailable: true
        })
    ]
});

// Если не продакшн, то логируем в консоль
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// Создание/подключение БД
const dbPath = './auth.db';
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    logger.error('Ошибка подключения к БД:', err);
    process.exit(1);
  }
  logger.info('Подключение к SQLite успешно');
  
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
    if (err) logger.error('Ошибка создания таблиц:', err);
  });
});

const app = express();
app.use(bodyParser.json());

// Middleware для правильных MIME типов
app.use((req, res, next) => {
  if (req.url.endsWith('.css')) {
    res.setHeader('Content-Type', 'text/css');
    logger.debug('Serving CSS file:', req.url);
  } else if (req.url.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript');
    logger.debug('Serving JS file:', req.url);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

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
  logger.info(`${req.method} ${req.url}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    sessionId: req.sessionID
  });
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
    logger.error('Error checking admin rights:', error);
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
          logger.error('Ошибка регистрации:', err);
          return res.status(500).json({ Message: 'Ошибка регистрации' });
        }
        logger.info('Успешная регистрация пользователя:', { login: Login });
        res.json({ Message: 'Успешная регистрация' });
      }
    );
  } catch (error) {
    logger.error('Ошибка сервера при регистрации:', error);
    res.status(500).json({ Message: 'Ошибка сервера' });
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
  logger.debug('Checking auth, session:', req.session);
  if (req.session && req.session.userId) {
    logger.debug('User is authenticated:', req.session.userId);
    next();
  } else {
    logger.debug('User is not authenticated');
    res.status(401).json({ Message: 'Требуется авторизация' });
  }
};

// Получение профиля пользователя
app.get('/api/profile', requireAuth, (req, res) => {
  logger.debug('Getting profile for user:', req.session.userId);
  
  db.get(
    'SELECT login, skin_path, cape_path FROM users WHERE uuid = ?',
    [req.session.userId],
    (err, row) => {
      if (err || !row) {
        logger.warn('Profile not found or error:', err);
        return res.status(404).json({ Message: 'Профиль не найден' });
      }
      
      logger.debug('Profile found:', row);
      res.json({
        login: row.login,
        skin_path: row.skin_path,
        cape_path: row.cape_path
      });
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
        logger.error('Error checking login:', err);
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
            logger.error('Error updating login:', err);
            return res.status(500).json({ Message: 'Ошибка обновления профиля' });
          }
          logger.info('Login updated successfully:', { userId: req.session.userId, newLogin: login });
          res.json({ Message: 'Профиль обновлен' });
        }
      );
    }
  );
});

// Получение скина по нику
app.get('/api/download/skin/:username', (req, res) => {
  const username = req.params.username;
  logger.debug('Getting skin for user:', username);
  
  db.get(
    'SELECT skin_path FROM users WHERE login = ?',
    [username],
    (err, row) => {
      if (err || !row || !row.skin_path) {
        logger.warn('Skin not found or error:', err);
        return res.status(404).json({ Message: 'Скин не найден' });
      }
      
      const skinPath = path.join(__dirname, 'public', row.skin_path);
      if (fs.existsSync(skinPath)) {
        res.sendFile(skinPath);
      } else {
        res.status(404).json({ Message: 'Файл скина не найден' });
      }
    }
  );
});

// Получение плаща по нику
app.get('/api/download/cape/:username', (req, res) => {
  const username = req.params.username;
  logger.debug('Getting cape for user:', username);
  
  db.get(
    'SELECT cape_path FROM users WHERE login = ?',
    [username],
    (err, row) => {
      if (err || !row || !row.cape_path) {
        logger.warn('Cape not found or error:', err);
        return res.status(404).json({ Message: 'Плащ не найден' });
      }
      
      const capePath = path.join(__dirname, 'public', row.cape_path);
      if (fs.existsSync(capePath)) {
        res.sendFile(capePath);
      } else {
        res.status(404).json({ Message: 'Файл плаща не найден' });
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
        logger.error('Error uploading skin:', err);
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
        logger.error('Error uploading cape:', err);
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
  logger.info('Login attempt for:', Login);
  
  db.get(
    'SELECT uuid, password FROM users WHERE login = ?',
    [Login],
    async (err, row) => {
      if (err || !row) {
        logger.warn('Login failed: User not found or error:', err);
        return res.status(401).json({ Message: 'Неверные данные' });
      }
      
      const match = await bcrypt.compare(Password, row.password);
      if (match) {
        logger.info('Login successful for user:', row.uuid);
        req.session.userId = row.uuid;
        req.session.save((err) => {
          if (err) {
            logger.error('Error saving session:', err);
            return res.status(500).json({ Message: 'Ошибка сервера' });
          }
          logger.debug('Session saved successfully');
          res.json({
            Message: 'Успешная авторизация'
          });
        });
      } else {
        logger.warn('Login failed: Invalid password for user:', Login);
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
      logger.error('Error fetching news:', err);
      return res.status(500).json({ Message: 'Ошибка получения новостей' });
    }
    var news_list = [];
    var index;
    for (index = 0; index <= rows.length - 1; ++index) {
      var row = rows[index];
      logger.debug('Processing news:', row.title);
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

// API для общих компонентов
app.get('/api/components/header', (req, res) => {
  logger.debug('Serving header component');
  const headerPath = path.join(__dirname, 'public/components/header.html');
  
  // Проверяем существование файла
  if (!fs.existsSync(headerPath)) {
    logger.error('Header component file not found:', headerPath);
    return res.status(404).json({ error: 'Header component not found' });
  }
  
  try {
    res.sendFile(headerPath);
    logger.debug('Header component served successfully');
  } catch (error) {
    logger.error('Error serving header component:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/components/footer', (req, res) => {
  logger.debug('Serving footer component');
  const footerPath = path.join(__dirname, 'public/components/footer.html');
  
  // Проверяем существование файла
  if (!fs.existsSync(footerPath)) {
    logger.error('Footer component file not found:', footerPath);
    return res.status(404).json({ error: 'Footer component not found' });
  }
  
  try {
    res.sendFile(footerPath);
    logger.debug('Footer component served successfully');
  } catch (error) {
    logger.error('Error serving footer component:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// API для лаунчера
// Страница загрузки лаунчера
app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/download.html'));
});

// Получение информации о версиях лаунчера (автоматическое определение)
app.get('/api/launcher/versions', (req, res) => {
  try {
    const platforms = ['windows', 'macos', 'linux'];
    const versions = [];
    
    platforms.forEach(platform => {
      const platformPath = path.join(__dirname, `../downloads/${platform}`);
      if (fs.existsSync(platformPath)) {
        const files = fs.readdirSync(platformPath);
        const exeFiles = files.filter(file => file.endsWith('.exe') || file.endsWith('.dmg') || file.endsWith('.AppImage'));
        
        if (exeFiles.length > 0) {
          // Берем первый файл как последнюю версию
          const latestFile = exeFiles[0];
          const filePath = path.join(platformPath, latestFile);
          const stats = fs.statSync(filePath);
          
          // Извлекаем версию из имени файла
          const versionMatch = latestFile.match(/v?(\d+\.\d+\.\d+)/);
          const version = versionMatch ? versionMatch[1] : '1.0.0';
          
          // Вычисляем MD5
          const crypto = require('crypto');
          const fileBuffer = fs.readFileSync(filePath);
          const hashSum = crypto.createHash('md5');
          hashSum.update(fileBuffer);
          const md5 = hashSum.digest('hex');
          
          versions.push({
            version: version,
            platform: platform,
            filename: latestFile,
            size: stats.size,
            md5: md5,
            releaseDate: stats.mtime.toISOString().split('T')[0],
            downloadUrl: `/downloads/${platform}/${latestFile}`,
            isLatest: true
          });
        }
      }
    });
    
    res.json({
      latest: versions.length > 0 ? versions[0].version : '1.0.0',
      versions: versions
    });
  } catch (error) {
    logger.error('Error reading versions:', error);
    res.status(500).json({ Message: 'Ошибка чтения версий' });
  }
});

// Получение единого changelog
app.get('/api/launcher/changelog', (req, res) => {
  try {
    const changelogPath = path.join(__dirname, '../downloads/changelog.md');
    
    if (fs.existsSync(changelogPath)) {
      const changelog = fs.readFileSync(changelogPath, 'utf8');
      res.setHeader('Content-Type', 'text/plain');
      res.send(changelog);
    } else {
      res.status(404).json({ Message: 'Changelog не найден' });
    }
  } catch (error) {
    logger.error('Error reading changelog:', error);
    res.status(500).json({ Message: 'Ошибка чтения changelog' });
  }
});

// Скачивание файла лаунчера
app.get('/downloads/:platform/:filename', (req, res) => {
  try {
    const { platform, filename } = req.params;
    const filePath = path.join(__dirname, `../downloads/${platform}/${filename}`);
    
    if (fs.existsSync(filePath)) {
      // Устанавливаем заголовки для скачивания
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/octet-stream');
      
      // Отправляем файл
      const fileStream = fs.createReadStream(filePath);
      fileStream.pipe(res);
    } else {
      res.status(404).json({ Message: 'Файл не найден' });
    }
  } catch (error) {
    logger.error('Error downloading file:', error);
    res.status(500).json({ Message: 'Ошибка скачивания файла' });
  }
});

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Тестовая страница
app.get('/test', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/test.html'));
});

// Favicon
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/favicon.ico'));
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
        logger.error('Error adding news:', err);
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
        logger.error('Error deleting news:', err);
        return res.status(500).json({ Message: 'Ошибка удаления новости' });
      }
      res.json({ Message: 'Новость успешно удалена' });
    }
  );
});

// API для получения версий лаунчера
app.get('/api/versions', (req, res) => {
  try {
    const platforms = ['windows', 'macos', 'linux'];
    const versions = {};
    
    platforms.forEach(platform => {
      const platformDir = path.join(__dirname, '..', 'downloads', platform);
      if (fs.existsSync(platformDir)) {
        const files = fs.readdirSync(platformDir).filter(file => 
          file.endsWith('.exe') || file.endsWith('.dmg') || file.endsWith('.AppImage') || file.endsWith('.jar')
        );
        
        if (files.length > 0) {
          // Берем первый файл как последнюю версию
          const latestFile = files[0];
          versions[platform] = {
            version: latestFile.replace(/\.[^/.]+$/, ''), // Убираем расширение
            filename: latestFile,
            url: `/api/download/${platform}/${latestFile}`,
            size: fs.statSync(path.join(platformDir, latestFile)).size
          };
        }
      }
    });
    
    res.json(versions);
  } catch (error) {
    logger.error('Error reading versions:', error);
    res.status(500).json({ error: 'Ошибка чтения версий' });
  }
});

// API для получения changelog
app.get('/api/changelog', (req, res) => {
  try {
    const changelogPath = path.join(__dirname, '..', 'downloads', 'changelog.md');
    if (fs.existsSync(changelogPath)) {
      const changelog = fs.readFileSync(changelogPath, 'utf8');
      res.json({ changelog });
    } else {
      res.json({ changelog: '# Changelog\n\nНет информации об изменениях.' });
    }
  } catch (error) {
    logger.error('Error reading changelog:', error);
    res.status(500).json({ error: 'Ошибка чтения changelog' });
  }
});

// API для скачивания файлов
app.get('/api/download/:platform/:filename', (req, res) => {
  try {
    const { platform, filename } = req.params;
    const filePath = path.join(__dirname, '..', 'downloads', platform, filename);
    
    if (fs.existsSync(filePath)) {
      res.download(filePath);
    } else {
      res.status(404).json({ error: 'Файл не найден' });
    }
  } catch (error) {
    logger.error('Error downloading file:', error);
    res.status(500).json({ error: 'Ошибка скачивания' });
  }
});

const PORT = 5013;
app.listen(PORT, () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});