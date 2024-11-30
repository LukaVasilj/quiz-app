const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const http = require('http');
const socketIo = require('socket.io');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs'); // Added bcrypt import
const jwt = require('jsonwebtoken'); // Added jwt import
require('dotenv').config();  // Učitaj environment varijable

const apiKey = process.env.HF_API_KEY;

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

// Funkcija za generiranje fallback pitanja
function getFallbackQuestion() {
  const fallbackQuestions = [
    { question: "What is the capital of France?", correctAnswer: "Paris" },
    { question: "What is the capital of Germany?", correctAnswer: "Berlin" },
    { question: "What is the largest planet in our solar system?", correctAnswer: "Jupiter" },
    { question: "Who developed the theory of relativity?", correctAnswer: "Albert Einstein" },
    { question: "In which year did the first moon landing occur?", correctAnswer: "1969" },
  ];

  return fallbackQuestions[Math.floor(Math.random() * fallbackQuestions.length)];
}

// Funkcija za generiranje nasumičnog pitanja i odgovora
async function generateRandomQuestionAndAnswer() {
  const randomFacts = [
      { fact: "Water boils at 100 degrees Celsius.", category: "Science", answer: "100" },
      { fact: "The human body has 206 bones.", category: "Biology", answer: "206" },
      { fact: "Mount Everest is the tallest mountain in the world.", category: "Geography", answer: "Mount Everest" },
      { fact: "The longest river in the world is the Nile.", category: "Geography", answer: "Nile" },
      { fact: "The first manned moon landing occurred in 1969.", category: "History", answer: "1969" },
      { fact: "Albert Einstein developed the theory of relativity.", category: "Science", answer: "Albert Einstein" },
      { fact: "Shakespeare wrote Hamlet.", category: "Literature", answer: "Hamlet" },
      { fact: "The capital of Australia is Canberra.", category: "Geography", answer: "Canberra" },
      { fact: "The speed of light is approximately 299,792 kilometers per second.", category: "Physics", answer: "299,792" },
      { fact: "The first computer was invented by Charles Babbage.", category: "Technology", answer: "Charles Babbage" }
  ];

  const randomFact = randomFacts[Math.floor(Math.random() * randomFacts.length)];

  // Generiranje odgovarajućeg pitanja ovisno o kategoriji
  const inputText = `Create a clear and engaging trivia question based on the following fact: "${randomFact.fact}". 
    Ensure the question is relevant to the fact, but do not directly repeat the fact in the question. 
    Do not use simple "What is the capital of X?" format. The question should focus on understanding the key information or its implication. 
    Ensure the question does not repeat simple phrases like "Who invented...?" or "What is the capital...?"`;



  try {
    const response = await fetch(
      "https://api-inference.huggingface.co/models/google/flan-t5-large",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ inputs: inputText }),
      }
    );

    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    console.log("Hugging Face API response:", result);

    if (result && result[0] && result[0].generated_text) {
      let question = result[0].generated_text.trim();
      
      // Generalizirana provjera pitanja: Provjerava je li pitanje u formatu koji očekujemo
      if (!question.match(/^.*\?$/)) { // Provjerava završava li pitanje sa znakom pitanja
        console.warn("Neispravan format generiranog pitanja:", question);
        return getFallbackQuestion(); // Vratiti fallback pitanje ako nije ispravno
      }

      const correctAnswer = randomFact.answer; // koristi odgovor iz `randomFact`
      return { question, correctAnswer };
    } else {
      console.warn("Greška pri parsiranju. Generirani tekst:", result[0]?.generated_text);
      throw new Error("Ne mogu parsirati pitanje i odgovor iz generiranog teksta.");
    }
  } catch (error) {
    console.error("Greška pri generiranju pitanja:", error);
    return getFallbackQuestion(); // Vratiti fallback pitanje ako dođe do greške
  }
}






// WebSocket logika
io.on('connection', (socket) => {
  console.log('Korisnik povezan: ' + socket.id);

  socket.on('joinRoom', (roomId) => {
    socket.join(roomId);
    console.log(`Korisnik ${socket.id} pridružen sobi ${roomId}`);

    const roomUsers = io.sockets.adapter.rooms.get(roomId);
    const userCount = roomUsers ? roomUsers.size : 0;
    console.log(`Broj korisnika u sobi ${roomId}: ${userCount}`);

    if (userCount === 1) {
      socket.emit('roomMessage', 'Čekamo protivnika, ljudi u sobi 1/2');
    } else if (userCount === 2) {
      io.to(roomId).emit('roomMessage', `Korisnik ${socket.id} je ušao. Ljudi u sobi 2/2`);
      console.log('Oba korisnika su u sobi, pokrećemo kviz...');

      // Dohvatite sobu i inicijalizirajte polje userAnswers
      let room = io.sockets.adapter.rooms.get(roomId);
      room.userAnswers = room.userAnswers || [];

      setTimeout(async () => {
        try {
          const { question, correctAnswer } = await generateRandomQuestionAndAnswer();
          io.to(roomId).emit('newQuestion', { question, correctAnswer });

          // Spremanje točnog odgovora u sobu
          room.correctAnswer = correctAnswer;
          room.userAnswers = []; // Resetiramo odgovore za novu rundu

          io.to(roomId).emit('startQuiz');
        } catch (error) {
          console.error('Greška pri generiranju pitanja:', error);
          io.to(roomId).emit('error', 'Došlo je do greške prilikom generiranja pitanja');
        }
      }, 2000);
    }
  });

  socket.on('submitAnswer', (roomId, userAnswer) => {
    const room = io.sockets.adapter.rooms.get(roomId); // Dohvaćanje sobe prema roomId
    if (!room) return;
  
    // Osiguranje da je userAnswers polje
    let userAnswers = room.userAnswers || [];
  
    // Dodavanje korisničkog odgovora u polje
    userAnswers.push(userAnswer);
  
    // Spremanje ažuriranih odgovora
    room.userAnswers = userAnswers;
  
    if (userAnswers.length === 2) {
      const correctAnswer = room.correctAnswer;
  
      // Emitiranje rezultata kada oba korisnika odgovore
      io.to(roomId).emit('results', {
        userAnswers: userAnswers,  // Osigurajte da je to polje
        correctAnswer,
      });
  
      // Postavljanje novog pitanja nakon kratke pauze
      setTimeout(async () => {
        try {
          const { question, correctAnswer } = await generateRandomQuestionAndAnswer();
          io.to(roomId).emit('newQuestion', { question, correctAnswer });
  
          // Spremanje novog točnog odgovora
          room.correctAnswer = correctAnswer;
          room.userAnswers = []; // Resetiramo odgovore za novu rundu
        } catch (error) {
          console.error('Greška pri generiranju pitanja:', error);
          io.to(roomId).emit('error', 'Došlo je do greške prilikom generiranja pitanja');
        }
      }, 2000);
    }
  });
  
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

    const token = jwt.sign({ id: user.id }, 'tajni_kljuc', { expiresIn: '1h' });
    res.json({ token, username: user.username });
  });
});

// Pokrećemo server na portu 5000
server.listen(5000, () => {
  console.log('Server pokrenut na http://localhost:5000');
});
