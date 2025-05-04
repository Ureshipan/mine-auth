const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

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
      password TEXT NOT NULL
    );
  `, (err) => {
    if (err) console.error('Ошибка создания таблиц:', err);
  });
});

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

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
        }
        res.json({ Message: 'Успешная регистрация' });
      }
    );
  } catch (error) {
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

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});