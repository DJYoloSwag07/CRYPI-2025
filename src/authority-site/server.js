// server.js
const express = require('express');
const { spawn } = require('child_process');
const fetch = require('node-fetch');      // npm install node-fetch@2
const app = express();
app.use(express.json());
const PORT = 3000;

// New endpoint: register & push the commitment
app.post('/register', async (req, res) => {
  const { dob, license, nonce, expiration, first_name, last_name } = req.body;

  // 1) Spawn the CLI to compute the commitment
  const args = [
    'commit',
    '--dob',        dob.toString(),
    '--license',    license.toString(),
    '--nonce',      nonce.toString(),
    '--expiration', expiration.toString(),
    '--first-name', first_name,
    '--last-name',  last_name
  ];
  const cli = spawn('identity', args);

  let stdout = '', stderr = '';
  cli.stdout.on('data', d => stdout += d);
  cli.stderr.on('data', d => stderr += d);

  cli.on('close', async code => {
    if (code !== 0) {
      console.error('identity commit failed:', stderr);
      return res.status(500).json({ error: stderr.trim() });
    }

    const commitment = stdout.trim();
    console.log('Computed commitment:', commitment);

    // 2) Push to the public database
    try {
      const resp = await fetch(`http://localhost:8000/${commitment}`, {
        method: 'PUT'
      });
      if (!resp.ok) throw new Error(`DB push failed: ${resp.status}`);
      console.log('Pushed to public DB');
      res.json({ commitment });
    } catch (err) {
      console.error(err);
      res.status(502).json({ error: err.message });
    }
  });
});

app.use(express.static('public'));
app.listen(PORT, () => {
  console.log(`Authority site listening on http://localhost:${PORT}`);
});
