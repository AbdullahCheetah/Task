const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = "123456789";

app.use(express.json());

let users = []; 
let tasks = [];

const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearerToken = bearerHeader.split(' ')[1];
    jwt.verify(bearerToken, SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.userId = decoded.id;
      next();
    });
  } else {
    res.sendStatus(403);
  }
};

app.post('/users/signup', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = {
      id: users.length + 1,
      username: req.body.username,
      password: hashedPassword,
    };
    users.push(newUser);
    res.status(201).send({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post('/users/login', async (req, res) => {
  const user = users.find(user => user.username === req.body.username);
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).send({ message: 'Logged in successfully', token });
  } else {
    res.status(400).send({ message: 'Authentication failed' });
  }
});

app.post('/tasks', verifyToken, (req, res) => {
  const newTask = {
    id: tasks.length + 1,
    ...req.body,
    userId: req.userId,
  };
  tasks.push(newTask);
  res.status(201).send(newTask);
});

app.get('/tasks', verifyToken, (req, res) => {
  const userTasks = tasks.filter(task => task.userId === req.userId);
  res.status(200).send(userTasks);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
