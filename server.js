const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
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
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Authorization', 'Content-Type'],
  credentials: true,
}));
app.use(bodyParser.json());


// Postavite direktorij 'uploads' kao statički direktorij
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/icons', express.static(path.join(__dirname, 'icons')));


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
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
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

  console.log('Received token:', token); // Log the token

  if (!token) {
    console.error('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err); // Log token verification error
      return res.status(403).json({ error: 'Token verification failed' });
    }

    req.user = user;
    console.log('Token verified, user:', user); // Log verified user
    next();
  });
};

// Konfiguracija za multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${req.user.id}-${Date.now()}${path.extname(file.originalname)}`);
  },
});

const upload = multer({ storage });

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
      } 
      else if (achievement.name === 'Bronze Champion' && points >= 25) {
        unlock = true;
      
      }else if (achievement.name === 'High Score' && points >= 50) {
        unlock = true;
      } else if (achievement.name === 'Gold' && points >= 100) {
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

    // Update user level based on points
    const level = Math.floor(points / 100) + 1;
    const updateLevelQuery = 'UPDATE users SET level = ? WHERE id = ?';
    db.query(updateLevelQuery, [level, userId], (err, result) => {
      if (err) {
        console.error('Greška pri ažuriranju razine:', err);
      } else {
        console.log(`User ${userId} level updated to ${level}`);
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
      roomUsersData[roomId].push({ id: socket.id, userId: userId, username: username, points: 0, ready: false });
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
      console.log('Oba korisnika su u sobi, čekamo da budu spremni...');
    }
  });

  socket.on('ready', (roomId) => {
    const user = roomUsersData[roomId].find(user => user.id === socket.id);
    if (user) {
      user.ready = true;
      io.to(roomId).emit('roomUsers', roomUsersData[roomId]);

      // Check if both users are ready
      const allReady = roomUsersData[roomId].every(user => user.ready);
      if (allReady) {
        console.log('Oba korisnika su spremna, pokrećemo kviz...');
        startQuiz(roomId);
      }
    }
  });

  const startQuiz = (roomId) => {
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
  };

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
    
    // Fetch current points from the database
    const fetchPointsQuery = 'SELECT points FROM users WHERE id = ?';
    db.query(fetchPointsQuery, [user.userId], (err, results) => {
      if (err) {
        console.error('Greška pri dohvaćanju trenutnih bodova:', err);
      } else {
        const currentPoints = results[0].points;
        const newTotalPoints = currentPoints + user.points;

        // Update points in the database
        const updatePointsQuery = 'UPDATE users SET points = ? WHERE id = ?';
        db.query(updatePointsQuery, [newTotalPoints, user.userId], (err, result) => {
          if (err) {
            console.error('Greška pri ažuriranju bodova:', err);
          } else {
            console.log(`Points updated for userId ${user.userId}`);
            
            // Fetch updated points to calculate level
            db.query(fetchPointsQuery, [user.userId], (err, results) => {
              if (err) {
                console.error('Greška pri dohvaćanju ažuriranih bodova:', err);
              } else {
                const updatedPoints = results[0].points;
                const newLevel = Math.floor(updatedPoints / 10) + 1;

                // Update level in the database
                const updateLevelQuery = 'UPDATE users SET level = ? WHERE id = ?';
                db.query(updateLevelQuery, [newLevel, user.userId], (err, result) => {
                  if (err) {
                    console.error('Greška pri ažuriranju razine:', err);
                  } else {
                    console.log(`Level updated for userId ${user.userId}`);
                    
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
                        updateAchievements(user.userId, updatedPoints, quizzesCompleted);
                      }
                    });
                  }
                });
              }
            });
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

    const token = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
    console.log('Generated token:', token); // Log the generated token
    res.json({ token, username: user.username });
  });
});

// Ruta za dohvaćanje leaderboarda
app.get('/leaderboard', (req, res) => {
  const query = 'SELECT username, points, profile_picture FROM users ORDER BY points DESC LIMIT 10';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Greška pri dohvaćanju leaderboarda:', err);
      return res.status(500).json({ error: 'Greška pri dohvaćanju leaderboarda' });
    }

    // Calculate level based on points
    const players = results.map(player => {
      const level = Math.floor(player.points / 10) + 1;
      return { ...player, level };
    });

    res.json(players);
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



// Ruta za dohvaćanje prijatelja
app.get('/friends', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query('SELECT u.id, u.username, u.profile_picture FROM friends f JOIN users u ON (f.friend_id = u.id OR f.user_id = u.id) WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = "accepted" AND u.id != ?', [userId, userId, userId], (err, results) => {
    if (err) {
      console.error('Error fetching friends:', err);
      return res.status(500).send('Error fetching friends');
    }
    console.log('Friends fetched:', results); // Debug log
    res.status(200).json(results);
  });
});

// Ruta za dodavanje prijatelja
app.post('/add-friend', authenticateToken, (req, res) => {
  const { friendUsername } = req.body;
  const userId = req.user.id;

  // Pronađi ID korisnika na temelju korisničkog imena
  db.query('SELECT id FROM users WHERE username = ?', [friendUsername], (err, results) => {
    if (err) return res.status(500).send('Error finding user');
    if (results.length === 0) return res.status(404).send('User not found');

    const friendId = results[0].id;

    // Provjeri postoji li već zahtjev za prijateljstvo
    db.query('SELECT * FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', [userId, friendId, friendId, userId], (err, results) => {
      if (err) return res.status(500).send('Error checking existing friend request');
      if (results.length > 0) return res.status(400).send('Friend request already sent or already friends');

      // Unesi zahtjev za prijateljstvo u bazu podataka
      db.query('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, "pending")', [userId, friendId], (err, result) => {
        if (err) return res.status(500).send('Error adding friend');
        res.status(200).send('Friend request sent');
      });
    });
  });
});

// Ruta za prihvaćanje zahtjeva za prijateljstvo
app.post('/accept-friend', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.id;

  // Ažuriraj status prijateljstva na "accepted" za oba korisnika
  db.query('UPDATE friends SET status = "accepted" WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', [friendId, userId, userId, friendId], (err, result) => {
    if (err) return res.status(500).send('Error accepting friend request');
    res.status(200).send('Friend request accepted');
  });
});


// Ruta za dohvaćanje zahtjeva za prijateljstvo
app.get('/friend-requests', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.query('SELECT u.id, u.username, u.profile_picture FROM friends f JOIN users u ON f.user_id = u.id WHERE f.friend_id = ? AND f.status = "pending"', [userId], (err, results) => {
    if (err) return res.status(500).send('Error fetching friend requests');
    res.status(200).json(results);
  });
});


// Ruta za pretragu korisnika
app.get('/search-users', authenticateToken, (req, res) => {
  const searchTerm = req.query.q;

  db.query('SELECT id, username, profile_picture FROM users WHERE username LIKE ?', [`${searchTerm}%`], (err, results) => {
    if (err) return res.status(500).send('Error searching users');
    res.status(200).json(results);
  });
});



// Ruta za brisanje prijatelja
app.delete('/delete-friend', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.id;

  db.query('DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', [userId, friendId, friendId, userId], (err, result) => {
    if (err) return res.status(500).send('Error deleting friend');
    res.status(200).send('Friend deleted');
  });
});

// Ruta za odbijanje zahtjeva za prijateljstvo
app.post('/decline-friend', authenticateToken, (req, res) => {
  const { friendId } = req.body;
  const userId = req.user.id;

  db.query('DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = "pending"', [friendId, userId], (err, result) => {
    if (err) return res.status(500).send('Error declining friend request');
    res.status(200).send('Friend request declined');
  });
});


// Ruta za promjenu lozinke
app.post('/change-password', authenticateToken, async (req, res) => {
  const { password } = req.body;
  const userId = req.user.id;

  if (!password) {
    return res.status(400).json({ message: 'Password is required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = 'UPDATE users SET password = ? WHERE id = ?';
  db.query(query, [hashedPassword, userId], (err, result) => {
    if (err) {
      console.error('Error updating password:', err);
      return res.status(500).json({ message: 'Error updating password' });
    }
    res.json({ message: 'Password updated successfully' });
  });
});

// Ruta za učitavanje profilne slike
app.post('/upload-profile-picture', authenticateToken, upload.single('profilePicture'), (req, res) => {
  const profilePicturePath = `/uploads/${req.file.filename}`;
  const userId = req.user.id;

  const query = 'UPDATE users SET profile_picture = ? WHERE id = ?';
  db.query(query, [profilePicturePath, userId], (err, result) => {
    if (err) {
      console.error('Error updating profile picture:', err);
      return res.status(500).json({ message: 'Error updating profile picture' });
    }
    res.json({ profile_picture: profilePicturePath });
  });
});

// Ruta za dohvaćanje profila
app.get('/api/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const query = `
    SELECT username, email, profile_picture, level, points
    FROM users
    WHERE id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching profile:', err);
      return res.status(500).json({ error: 'Error fetching profile' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = results[0];
    const achievementsQuery = `
      SELECT a.id, a.name, a.icon
      FROM achievements a
      JOIN user_achievements ua ON a.id = ua.achievement_id
      WHERE ua.user_id = ?
    `;
    db.query(achievementsQuery, [userId], (err, achievements) => {
      if (err) {
        console.error('Error fetching achievements:', err);
        return res.status(500).json({ error: 'Error fetching achievements' });
      }
      user.achievements = achievements;
      res.json(user);
    });
  });
});

// Ruta za dohvaćanje profila prijatelja
app.get('/api/profile/:friendId', authenticateToken, (req, res) => {
  const friendId = req.params.friendId;
  const query = `
    SELECT username, email, profile_picture, level, points
    FROM users
    WHERE id = ?
  `;
  db.query(query, [friendId], (err, results) => {
    if (err) {
      console.error('Error fetching profile:', err);
      return res.status(500).json({ error: 'Error fetching profile' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = results[0];
    const achievementsQuery = `
      SELECT a.id, a.icon
      FROM achievements a
      JOIN user_achievements ua ON a.id = ua.achievement_id
      WHERE ua.user_id = ?
    `;
    db.query(achievementsQuery, [friendId], (err, achievements) => {
      if (err) {
        console.error('Error fetching achievements:', err);
        return res.status(500).json({ error: 'Error fetching achievements' });
      }
      user.achievements = achievements;
      res.json(user);
    });
  });
});

// Pokrećemo server na portu 5000
server.listen(5000, () => {
  console.log('Server pokrenut na http://localhost:5000');
});