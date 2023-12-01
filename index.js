const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Tentativa de conectar ao MongoDB - Não possuo tanto conhecimento em banco de dados, mas pretendo aprimorar.
mongoose.connect("mongodb://localhost:27017/auth-api", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Definindo o modelo de usuário
const User = mongoose.model("User", {
  username: String,
  password: String,
});

// Rota de cadastro
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Verificação se o usuário já existe
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ mensagem: "Usuário já existe" });
    }

    // Hash da senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Criar novo usuário
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ mensagem: "Usuário cadastrado com sucesso" });
  } catch (error) {
    res.status(500).json({ mensagem: "Erro interno do servidor" });
  }
});

// Rota de autenticação
app.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Verificar se o usuário existe
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ mensagem: "Credenciais inválidas" });
    }

    // Verificar a senha
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ mensagem: "Credenciais inválidas" });
    }

    // Gerar token de autenticação
    const token = jwt.sign({ username: user.username }, "secreto", {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    res.status(500).json({ mensagem: "Erro interno do servidor" });
  }
});

// Rota protegida
app.get("/user", (req, res) => {
  // Verificar a presença do token
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ mensagem: "Token não fornecido" });
  }

  // Verificar e decodificar o token
  jwt.verify(token, "secreto", (err, decoded) => {
    if (err) {
      return res.status(401).json({ mensagem: "Token inválido" });
    }

    // Retornar informações do usuário
    res.json({ username: decoded.username });
  });
});

// Rota não encontrada
app.use((req, res) => {
  res.status(404).json({ mensagem: "Endpoint não encontrado" });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
