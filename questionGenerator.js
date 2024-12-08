const fetch = require('node-fetch');
require('dotenv').config();

const apiKey = process.env.HF_API_KEY;

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
  { fact: "The first computer was invented by Charles Babbage.", category: "Technology", answer: "Charles Babbage" },
  // Dodajte još 100 random facts ovdje
  { fact: "The Great Wall of China is over 13,000 miles long.", category: "History", answer: "Great Wall of China" },
  { fact: "The human brain contains approximately 86 billion neurons.", category: "Biology", answer: "86 billion" },
  { fact: "The Eiffel Tower is located in Paris, France.", category: "Geography", answer: "Paris" },
  { fact: "The speed of sound is approximately 343 meters per second.", category: "Physics", answer: "343" },
  { fact: "The Amazon Rainforest produces 20% of the world's oxygen.", category: "Geography", answer: "Amazon" },
  { fact: "The Mona Lisa was painted by Leonardo da Vinci.", category: "Art", answer: "Leonardo da Vinci" },
  { fact: "The largest desert in the world is the Sahara Desert.", category: "Geography", answer: "Sahara" },
  { fact: "The Pythagorean theorem is a fundamental relation in Euclidean geometry.", category: "Mathematics", answer: "Pythagorean theorem" },
  { fact: "The chemical symbol for gold is Au.", category: "Chemistry", answer: "Au" },
  { fact: "The first successful airplane flight was made by the Wright brothers.", category: "History", answer: "Wright brothers" },
  // Dodajte još 90 random facts ovdje
];

async function generateRandomQuestionAndAnswer(usedFacts) {
  let availableFacts = randomFacts.filter(fact => !usedFacts.includes(fact.fact));
  if (availableFacts.length === 0) {
    availableFacts = randomFacts;
    usedFacts = [];
  }

  const randomFact = availableFacts[Math.floor(Math.random() * availableFacts.length)];
  usedFacts.push(randomFact.fact);

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

      if (!question.match(/^.*\?$/)) {
        console.warn("Neispravan format generiranog pitanja:", question);
        return getFallbackQuestion();
      }

      const correctAnswer = randomFact.answer;
      return { question, correctAnswer, usedFacts };
    } else {
      console.warn("Greška pri parsiranju. Generirani tekst:", result[0]?.generated_text);
      throw new Error("Ne mogu parsirati pitanje i odgovor iz generiranog teksta.");
    }
  } catch (error) {
    console.error("Greška pri generiranju pitanja:", error);
    return getFallbackQuestion();
  }
}

function getFallbackQuestion() {
  const fallbackQuestions = [
    { question: "What is the capital of France?", correctAnswer: "Paris" },
    
  ];

  return fallbackQuestions[Math.floor(Math.random() * fallbackQuestions.length)];
}

module.exports = { generateRandomQuestionAndAnswer };