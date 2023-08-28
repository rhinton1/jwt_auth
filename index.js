const express = require('express');
const bcrypt = require('bcryptjs');
const auth = require('./auth');

const app = express();
const users = [];

app.use(express.json());

app.get('/api/users', auth.verifyToken, async (req,res) => {
  res.json(users);
});

app.post('/api/register', async (req,res) => {
  const user = req.body;
  if (!user.email || !user.password) {
    return res.status(400).send('Username and password are requied.');
  }

  const hash = await bcrypt.hash(user.password, 10);
  user.password = hash;
  users.push(user);
  return res.status(200).send(`The following user was registered: ${JSON.stringify(user)}`);
});

app.post('/api/login', async (req, res) => {
  const user = req.body;
  const foundUser = users.find((user) => user.email === req.body.email);

  if(!foundUser) {
    return res.status(400).send('Invalid email or password');
  }

  const isPasswordValid = await bcrypt.compare(user.password, foundUser.password);
  if (!isPasswordValid) {
    return res.status(400).send('Invalid email or password');
  }

  const token = auth.generateToken(user);
  res.setHeader('Authorization', `Bearer ${token}`).status(200).send(`Login was successful with the following Token: ${token}`);
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});