// index.js
const express = require('express');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const app = express();
app.use(express.json());

// In-memory storage (replace with database for persistence)
const users = {};
const challenges = {};

// Registration Endpoints
app.post('/register/start', (req, res) => {
  const username = req.body.username;
  const options = generateRegistrationOptions({
    rpName: 'My Personal Journal',
    rpID: process.env.DOMAIN, // Your HTTPS domain
    userID: username,
    userName: username,
    attestationType: 'none'
  });
  
  challenges[username] = options.challenge;
  res.json(options);
});

app.post('/register/finish', async (req, res) => {
  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: challenges[req.body.username],
    expectedOrigin: `https://${process.env.DOMAIN}`,
    expectedRPID: process.env.DOMAIN
  });
  
  if (verification.verified) {
    users[req.body.username] = verification.registrationInfo;
  }
  res.json({ verified: verification.verified });
});

// Login Endpoints
app.post('/login/start', (req, res) => {
  const options = generateAuthenticationOptions({
    allowCredentials: [{
      id: users[req.body.username]?.credentialID,
      type: 'public-key',
      transports: ['internal']
    }]
  });
  
  challenges[req.body.username] = options.challenge;
  res.json(options);
});

app.post('/login/finish', async (req, res) => {
  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: challenges[req.body.username],
    expectedOrigin: `https://${process.env.DOMAIN}`,
    expectedRPID: process.env.DOMAIN,
    requireUserVerification: true
  });
  
  res.json({ verified: verification.verified });
});

app.listen(3000, () => console.log('Server running on port 3000'));
