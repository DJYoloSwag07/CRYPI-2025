const express = require('express');
const { spawn } = require('child_process');
const app = express();
const port = 3000;

// Serve static front-end
app.use(express.static('public'));

app.get('/verify', (req, res) => {
  // Reconstruct the full URL with query
  const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
  // Invoke the identity CLI:
  const cli = spawn('identity', [fullUrl]);

  let output = '';
  let error  = '';
  cli.stdout.on('data', data => output += data);
  cli.stderr.on('data', data => error  += data);

  cli.on('close', code => {
    if (code !== 0) {
      return res.status(400).send(`<pre>Verification failed:\n${error}</pre>`);
    }
    let result;
    try {
      result = JSON.parse(output);
    } catch (e) {
      return res.status(500).send('Invalid JSON from identity CLI');
    }
    if (!result.verified) {
      return res.send('<h1>Proof invalid!</h1>');
    }
    // Build a list of validated claims
    const items = Object.entries(result.validated)
      .map(([k,v]) => `<li>${k.replace('_',' ')} = ${v}</li>`)
      .join('');
    res.send(`
      <h1>✅ Identity validated</h1>
      <ul>${items}</ul>
    `);
  });
});

app.listen(port, () => {
  console.log(`Demo listening at http://localhost:${port}`);
});
