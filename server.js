
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());


const users = [];

// Register a new user
app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { username: req.body.username, email: req.body.email, password: hashedPassword };
        users.push(user);
        res.status(201).send("User registered successfully!");
    } catch {
        res.status(500).send("An error occurred while registering the user.");
    }
});

// Login
app.post('/login', async (req, res) => {
    const user = users.find(user => user.username === req.body.username);
    if (user == null) {
        return res.status(400).send('User not found');
    }
    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const token = jwt.sign({ username: user.username }, 'secretkey');
            res.json({ token: token });
        } else {
            res.status(401).send('Incorrect password');
        }
    } catch {
        res.status(500).send('An error occurred while logging in');
    }
});

// Get user information
app.get('/user', authenticateToken, (req, res) => {
    res.json(users.find(user => user.username === req.user.username));
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

//Get all users
app.get('/users', (req, res) => {
  const usernames = users.map(user => user.username);
  res.json(usernames);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
