const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt'); 
require('dotenv').config(); // Добавляем в начало файла

const connection = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    return;
  }
  console.log('Подключение к базе данных успешно установлено.');
});

// После подключения к MySQL
connection.query(`USE ${process.env.DB_NAME}`, (err) => {
  if (err) {
    console.log('База данных отсутствует. Создание...');
    const initScript = fs.readFileSync('./src/database.sql', 'utf8');
    connection.query(initScript, (err) => {
      if (err) throw err;
      console.log('База данных создана');
    });
  }
});

const app = express();
app.use(bodyParser.json());

app.post('/auth', (req, res) => {
  const { Login, Password } = req.body;
  //console.log('Запрос на авторизацию:', { Login, Password });

  if (!Login || !Password) {
   // console.log('Логин или пароль отсутствуют в запросе');
    return res.status(400).json({ Message: 'Логин и пароль обязательны' });
  }

  const query = 'SELECT uuid, login, password FROM users WHERE LOWER(login) = LOWER(?)';
  connection.query(query, [Login], async (error, results) => {
    if (error) {
      console.error('Ошибка выполнения запроса к базе данных:', error);
      return res.status(500).json({ Message: 'Ошибка на сервере' });
    }

    if (results.length > 0) {
      //console.log('Пользователь найден в базе данных:', results[0]);

      const user = results[0];
      //console.log('Пароль из запроса:', Password);
      //console.log('Пароль из запроса (после trim()):', Password.trim());
      //console.log('Хэшированный пароль из базы:', user.Password);

      const dbPassword = user.password.startsWith('$2y$')
        ? user.password.replace('$2y$', '$2a$')
        : user.password;

      //console.log('Преобразованный хэшированный пароль из базы:', dbPassword);

      try {
        const match = await bcrypt.compare(Password.trim(), dbPassword);
        console.log('Результат сравнения пароля с хэшем:', match);

        if (match) {
          //console.log('Авторизация успешна.');
          return res.json({
            Login: user.login,
            UserUuid: user.uuid,
            Message: 'Успешная авторизация'
          });
        } else {
          //console.log('Пароль не совпадает.');
          return res.status(401).json({ Message: 'Неверный логин или пароль' });
        }
      } catch (bcryptError) {
        console.error('Ошибка при сравнении пароля с хэшем:', bcryptError);
        return res.status(500).json({ Message: 'Ошибка на сервере' });
      }
    } else {
      //console.log('Пользователь с логином не найден:', Login);
      return res.status(404).json({ Message: 'Пользователь не найден' });
    }
  });
});

// Эндпоинт для регистрации
app.post('/register', async (req, res) => {
  const { Login, Password } = req.body;
  if (!Login || !Password) {
    return res.status(400).json({ Message: 'Логин и пароль обязательны' });
  }

  // Хэширование пароля
  const hashedPassword = await bcrypt.hash(Password, 10);
  
  const query = 'INSERT INTO users (uuid, login, password) VALUES (UUID(), ?, ?)';
  connection.query(query, [Login, hashedPassword], (error) => {
    if (error) {
      console.error('Ошибка регистрации:', error);
      return res.status(500).json({ Message: 'Ошибка при регистрации' });
    }
    res.json({ Message: 'Пользователь успешно создан' });
  });
});

// Форма регистрации (доступна по /register в браузере)
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});

