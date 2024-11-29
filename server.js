const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');

const app = express();

// Kreiraj HTTP server koji omogućuje WebSocket povezivanje
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
      origin: '*',  // Omogućava pristup sa svih domena
      methods: ['GET', 'POST'],
      allowedHeaders: ['Content-Type'],
    },
    transports: ['websocket'], // Prilagodite za WebSocket
  });
  

app.use(cors({
  origin: 'http://localhost:3000',  // React aplikacija URL
  methods: ['GET', 'POST'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  credentials: true,  // Omogućuje korištenje kolačića
}));
app.use(bodyParser.json());

// MySQL konfiguracija
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'quiz_app',
});

db.connect((err) => {
  if (err) {
    console.error('Greška pri spajanju na bazu:', err);
  } else {
    console.log('Spojen na MySQL bazu!');
  }
});


// WebSocket logika
io.on('connection', (socket) => {
    console.log('Korisnik povezan: ' + socket.id);
  
    // Kada korisnik uđe u sobu
    socket.on('joinRoom', (roomId) => {
        socket.join(roomId);
        console.log(`Korisnik ${socket.id} pridružen sobi ${roomId}`);
      
        const roomUsers = io.sockets.adapter.rooms.get(roomId);
        const userCount = roomUsers ? roomUsers.size : 0;
        console.log(`Broj korisnika u sobi ${roomId}: ${userCount}`);
      
        if (userCount === 1) {
          socket.emit('roomMessage', `Čekamo protivnika, ljudi u sobi 1/2`);
        } else if (userCount === 2) {
          io.to(roomId).emit('roomMessage', `Korisnik ${socket.id} je ušao. Ljudi u sobi 2/2`);
          console.log('Oba korisnika su u sobi, pokrećemo kviz...');
          setTimeout(() => {
            io.to(roomId).emit('startQuiz');
            console.log('startQuiz događaj poslan sobi', roomId);
          }, 10000);
        }
      });
  
    // Kada korisnik napusti sobu
    socket.on('disconnect', () => {
      console.log('Korisnik isključen: ' + socket.id);
    });
  });
  
  

// Ruta za registraciju
app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'Sva polja su obavezna' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Lozinke se ne podudaraju' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  db.query(query, [username, email, hashedPassword], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Greška pri registraciji' });
    }
    res.status(201).json({ message: 'Korisnik uspješno registriran!' });
  });
});

// Ruta za login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).send('Korisnik nije pronađen.');
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send('Pogrešna lozinka.');
    }

    // Generiraj JWT token
    const token = jwt.sign({ id: user.id }, 'tajni_kljuc', { expiresIn: '1h' });
    res.json({ token, username: user.username });
  });
});

// Ruta za dashboard
app.get('/dashboard', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ message: 'Token nije pronađen' });
  }

  jwt.verify(token, 'tajni_kljuc', (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Neispravan token' });
    }

    const userId = decoded.id;
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: 'Korisnik nije pronađen' });
      }
      const user = results[0];
      res.json({ name: user.username, email: user.email });
    });
  });
});

// Pokrećemo server na portu 5000
server.listen(5000, () => {
  console.log('Server pokrenut na http://localhost:5000');
});

