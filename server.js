const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/auth-system', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true // This line is deprecated, it's handled internally by Mongoose now
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Failed to connect to MongoDB', err);
});

const secret = 'mysecret';

// Signup
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).send('User created');
    } catch (err) {
        res.status(400).send('Error: ' + err.message);
    }
});

// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('User not found');
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');
        
        const token = jwt.sign({ id: user._id }, secret, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (err) {
        res.status(400).send('Error: ' + err.message);
    }
});

// Middleware
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Unauthorized: No token provided');
    
    try {
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send('Unauthorized: Invalid token');
    }
};

// Protected Route
app.get('/protected', auth, (req, res) => {
    res.status(200).send('This is a protected route');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
