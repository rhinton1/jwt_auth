const jwt = require('jsonwebtoken');
require('dotenv').config();

const generateToken = (data) => {
  const token = jwt.sign({ data }, process.env.JWT_SECRET, {
    expiresIn: "5m",
  });
  return token;
}

const regenerateToken = (token) => {
  const decoded = jwt.decode(token);
  return generateToken(decoded.data);
}

const verifyToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).send('Unauthorized request');
  }
  
  const token = req.headers['authorization'].split(' ')[1];
  
  if (!token) {
    return res.status(401).send('Access Denied. Missing Token.');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.body = decoded;
  } catch (error) {
    if(error.name !== 'TokenExpiredError') {
      return res.status(401).send('Invalid token.');
    } else {
      return res.status(401).send('Token has expired.');
    }
  }

  return next();
}

exports.verifyToken = verifyToken;
exports.generateToken = generateToken;