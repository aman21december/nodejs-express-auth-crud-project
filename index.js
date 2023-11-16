const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('./models/user');
const Item = require('./models/item');
const app = express();
app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/mydb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Authentication: Register
app.post('/register', [
  check('username').isLength({ min: 5 }),
  check('email').isEmail(),
  check('password').isLength({ min: 5 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password, isAdmin } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  if(isAdmin===true){
     user = new User({ username, email, password: hashedPassword, role:"admin" });
     await user.save();
  }
  else{
    user = new User({ username, email, password: hashedPassword});
    await user.save();
  }
  
  res.status(201).send('User registered.');
});



// Authentication: Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).send('Invalid email or password.');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).send('Invalid email or password.');
  }

  const token = jwt.sign({ userId: user._id, role: user.role }, 'secret-key', { expiresIn: '1h' });
  res.json({ token });
});


function authenticateUser(req, res, next) {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).send('Access denied. No token provided.');
  }

  try {
    const decoded = jwt.verify(token, 'secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).send('Invalid token.');
  }
}

// Authorization middleware
function authorizeAdmin(req, res, next) {
  if (req.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied. Admin rights required.');
  }
}

 // CRUD operations for items
    app.get('/items', authenticateUser, async (req, res) => {
    const items = await Item.find();
    res.json(items);
  });
  
    app.post('/items', authenticateUser, authorizeAdmin, async (req, res) => {
    const { name, description } = req.body;
    const item = new Item({ name, description });
    await item.save();
    res.status(201).json(item);
  });
  
    app.put('/items/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const { name, description } = req.body;
    const item = await Item.findByIdAndUpdate(id, { name, description }, { new: true });
    if (!item) {
      return res.status(404).send('Item not found.');
    }
    res.json(item);
  });
  
  app.delete('/items/:id', authenticateUser, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const item = await Item.findByIdAndRemove(id);
    if (!item) {
      return res.status(404).send('Item not found.');
    }
    res.send('Item deleted.');
  });

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});