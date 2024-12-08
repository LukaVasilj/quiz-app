const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { generateRandomQuestionAndAnswer } = require('./questionGenerator');

const app = express();

// Kreiraj HTTP server koji omogućuje WebSocket povezivanje
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
  },
  transports: ['websocket'],
});

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  credentials: true,
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

// Middleware to authenticate user and attach userId and username to socket
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  jwt.verify(token, 'tajni_kljuc', (err, decoded) => {
    if (err) {
      return next(new Error('Authentication error'));
    }
    socket.userId = decoded.id;
    // Fetch username from the database
    const query = 'SELECT username FROM users WHERE id = ?';
    db.query(query, [decoded.id], (err, results) => {
      if (err || results.length === 0) {
        return next(new Error('User not found'));
      }
      socket.username = results[0].username;
      next();
    });
  });
});

// Middleware to authenticate token for HTTP requests
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'tajni_kljuc', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Function to update achievements based on points and quizzes completed
// Function to update achievements based on points and quizzes completed
// Function to update achievements based on points and quizzes completed
const updateAchievements = (userId, points, quizzesCompleted, correctAnswers) => {
  const achievementsQuery = `
    SELECT id, name FROM achievements
  `;
  db.query(achievementsQuery, (err, achievements) => {
    if (err) {
      console.error('Greška pri dohvaćanju achievements:', err);
      return;
    }
    achievements.forEach(achievement => {
      let unlock = false;
      if (achievement.name === 'First Quiz' && quizzesCompleted >= 1) {
        unlock = true;
      } else if (achievement.name === 'High Score' && points >= 80) {
        unlock = true;
      } else if (achievement.name === 'Quiz Master' && quizzesCompleted >= 10) {
        unlock = true;
      } else if (achievement.name === 'Three Correct Answers' && correctAnswers >= 3) {
        unlock = true;
      }
      if (unlock) {
        const updateQuery = `
          INSERT INTO user_achievements (user_id, achievement_id)
          VALUES (?, ?)
          ON DUPLICATE KEY UPDATE user_id = user_id
        `;
        db.query(updateQuery, [userId, achievement.id], (err, result) => {
          if (err) {
            console.error('Greška pri ažuriranju achievements:', err);
          } else {
            console.log(`Achievement ${achievement.name} unlocked for user ${userId}`);
          }
        });
      }
    });
  });
};

// WebSocket logika
// Pohrana korisnika u sobi
let roomUsersData = {}; // Svi podaci o korisnicima po sobama


io.on('connection', (socket) => {
  console.log('Korisnik povezan: ' + socket.id);

  socket.on('joinRoom', (roomId) => {
    const userId = socket.userId;
    const username = socket.username;
    if (!userId || !username) {
      console.error(`UserId or username is undefined for socket ${socket.id}`);
      return;
    }

    socket.join(roomId);
    console.log(`Korisnik ${socket.id} pridružen sobi ${roomId} sa userId ${userId} i username ${username}`);
  
    // Dodaj korisnika u sobu u pohranu ako već nije dodan
    if (!roomUsersData[roomId]) {
      roomUsersData[roomId] = [];
    }
    if (!roomUsersData[roomId].some(user => user.id === socket.id)) {
      roomUsersData[roomId].push({ id: socket.id, userId: userId, username: username, points: 0 });
    }
  
    io.to(roomId).emit('roomUsers', roomUsersData[roomId]);
  
    // Emitiranje poruke svim korisnicima koji su online, a nisu u sobi
    io.to(roomId).emit('userJoinedRoom', `Korisnik ${username} je ušao u sobu ${roomId}`);
  
    // Emitiranje popisa korisnika koji su već u sobi (za korisnike koji nisu u sobi)
    io.to(socket.id).emit('currentRoomUsers', roomUsersData[roomId]);
  
    const roomUsers = io.sockets.adapter.rooms.get(roomId);
    const userCount = roomUsers ? roomUsers.size : 0;
  
    if (userCount === 1) {
      socket.emit('roomMessage', 'Čekamo protivnika, ljudi u sobi 1/2');
    } else if (userCount === 2) {
      console.log('Emitiranje poruke: Korisnik je ušao u sobu');
      io.to(roomId).emit('roomMessage', `Korisnik ${username} je ušao. Ljudi u sobi 2/2`);
      console.log('Oba korisnika su u sobi, pokrećemo kviz...');
  
      // Pokreni kviz
      let room = io.sockets.adapter.rooms.get(roomId);
      room.userAnswers = room.userAnswers || [];
      room.questionCount = 0; // Dodajemo brojač pitanja
      room.usedFacts = []; // Dodajemo polje za praćenje korištenih pitanja
  
      setTimeout(async () => {
        try {
          const { question, correctAnswer } = await generateRandomQuestionAndAnswer(room.usedFacts);
          io.to(roomId).emit('newQuestion', { question, correctAnswer });
  
          // Spremanje točnog odgovora u sobu
          room.correctAnswer = correctAnswer;
          room.userAnswers = []; // Resetiramo odgovore za novu rundu
  
          io.to(roomId).emit('startQuiz');
        } catch (error) {
          console.error('Greška pri generiranju pitanja:', error);
          io.to(roomId).emit('error', 'Došlo je do greške prilikom generiranja pitanja');
        }
      }, 5000);
    }
  });

  socket.on('submitAnswer', (roomId, userAnswer) => {
    const room = io.sockets.adapter.rooms.get(roomId); // Dohvaćanje sobe prema roomId
    if (!room) return;
    
    // Osiguranje da je userAnswers polje
    let userAnswers = room.userAnswers || [];
    
    // Dodavanje korisničkog odgovora u polje
    userAnswers.push({ id: socket.id, answer: userAnswer });
    
    // Spremanje ažuriranih odgovora
    room.userAnswers = userAnswers;
    
    if (userAnswers.length === 2) {
      const correctAnswer = room.correctAnswer;
    
      // Ažuriranje bodova
      userAnswers.forEach(userAnswer => {
        if (userAnswer.answer === correctAnswer) {
          const user = roomUsersData[roomId].find(user => user.id === userAnswer.id);
          if (user) {
            user.points += 1;
          }
        }
      });
    
      room.questionCount = room.questionCount || 0;
      room.questionCount += 1; // Povećavamo brojač pitanja
    
      // Emitiranje rezultata kada oba korisnika odgovore
      io.to(roomId).emit('results', {
        userAnswers: userAnswers, // Osigurajte da je to polje
        correctAnswer,
        roomUsers: roomUsersData[roomId] // Emitovanje ažuriranih bodova
      });
  
      if (room.questionCount >= 3) { // Ako su odgovori na tri pitanja, završavamo kviz
        setTimeout(() => {
          io.to(roomId).emit('quizEnd', roomUsersData[roomId]);
  
          // Ažuriranje bodova u bazi podataka
          roomUsersData[roomId].forEach(user => {
            console.log(`Updating points for userId ${user.userId} with points ${user.points}`);
            const query = 'UPDATE users SET points = points + ? WHERE id = ?';
            db.query(query, [user.points, user.userId], (err, result) => {
              if (err) {
                console.error('Greška pri ažuriranju bodova:', err);
              } else {
                console.log(`Points updated for userId ${user.userId}`);
                // Insert user answers into user_answers table
                const insertAnswersQuery = `
                  INSERT INTO user_answers (user_id, room_id, question_id, answer, correct)
                  VALUES (?, ?, ?, ?, ?)
                `;
                userAnswers.forEach(userAnswer => {
                  db.query(insertAnswersQuery, [user.userId, roomId, userAnswer.question_id, userAnswer.answer, userAnswer.answer === correctAnswer], (err, result) => {
                    if (err) {
                      console.error('Greška pri unosu odgovora korisnika:', err);
                    }
                  });
                });
                // Update achievements based on points and quizzes completed
                const quizzesCompletedQuery = `
                  SELECT COUNT(DISTINCT room_id) AS quizzesCompleted 
                  FROM user_answers 
                  WHERE user_id = ?
                `;
                db.query(quizzesCompletedQuery, [user.userId], (err, results) => {
                  if (err) {
                    console.error('Greška pri dohvaćanju broja završenih kvizova:', err);
                  } else {
                    const quizzesCompleted = results[0].quizzesCompleted;
                    console.log(`User ${user.userId} has completed ${quizzesCompleted} quizzes`);
                    updateAchievements(user.userId, user.points, quizzesCompleted);
                  }
                });
              }
            });
          });
  
          // Resetovanje sobe
          delete roomUsersData[roomId];
        }, 5000); // Dodajemo pauzu od 5 sekundi pre prikazivanja konačnih rezultata
      } else {
        // Postavljanje novog pitanja nakon kratke pauze
        setTimeout(async () => {
          try {
            const { question, correctAnswer } = await generateRandomQuestionAndAnswer(room.usedFacts);
            io.to(roomId).emit('newQuestion', { question, correctAnswer });
    
            // Spremanje novog točnog odgovora
            room.correctAnswer = correctAnswer;
            room.userAnswers = []; // Resetiramo odgovore za novu rundu
          } catch (error) {
            console.error('Greška pri generiranju pitanja:', error);
            io.to(roomId).emit('error', 'Došlo je do greške prilikom generiranja pitanja');
          }
        }, 5000);
      }
    }
  });

  // Handle chat messages
  socket.on('chatMessage', (message) => {
    const userMessage = `Korisnik ${socket.username}: ${message}`;
    io.emit('chatMessage', userMessage); // Broadcast the message to all connected clients
  });
  
  socket.on('disconnect', () => {
    console.log('Korisnik isključen: ' + socket.id);
    // Uklanjanje korisnika iz svih soba
    for (const roomId in roomUsersData) {
      roomUsersData[roomId] = roomUsersData[roomId].filter(user => user.id !== socket.id);
      if (roomUsersData[roomId].length === 0) {
        delete roomUsersData[roomId];
      } else {
        io.to(roomId).emit('roomUsers', roomUsersData[roomId]);
      }
    }
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

    const token = jwt.sign({ id: user.id }, 'tajni_kljuc', { expiresIn: '1h' });
    res.json({ token, username: user.username });
  });
});

// Ruta za dohvaćanje leaderboarda
app.get('/leaderboard', (req, res) => {
  const query = 'SELECT username, points FROM users ORDER BY points DESC LIMIT 10';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Greška pri dohvaćanju leaderboarda:', err);
      return res.status(500).json({ error: 'Greška pri dohvaćanju leaderboarda' });
    }
    res.json(results);
  });
});

// Ruta za dohvaćanje achievements
app.get('/api/achievements', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const query = `
    SELECT a.id, a.name, a.description,
      CASE WHEN ua.user_id IS NOT NULL THEN TRUE ELSE FALSE END AS completed
    FROM achievements a
    LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.user_id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Greška pri dohvaćanju achievements:', err);
      return res.status(500).json({ error: 'Greška pri dohvaćanju achievements' });
    }
    res.json(results);
  });
});

// Pokrećemo server na portu 5000
server.listen(5000, () => {
  console.log('Server pokrenut na http://localhost:5000');
});