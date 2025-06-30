const express = require('express');
const { spawn }  = require('child_process');
const fetch      = require('node-fetch');
const app         = express();
const port        = 3000;

app.use(express.static('public'));

app.get('/verify', async (req, res) => {
  const commitment = req.query.commitment;
  if (!commitment) {
    return res
      .status(400)
      .send('<h1>❌ Missing commitment in query</h1>');
  }

  // 1) Check public DB
  try {
    const dbRes = await fetch(`http://localhost:8000/${commitment}`);
    if (!dbRes.ok) {
      // 404 or other error → commitment not registered
      return res
        .status(400)
        .send(`<h1>❌ Commitment not found in public database</h1>`);
    }
  } catch (e) {
    return res
      .status(502)
      .send(`<h1>⚠️ Error contacting public DB</h1><pre>${e.message}</pre>`);
  }


  // reconstruct full callback URL
  const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;

  // call the identity CLI
  const cli = spawn('identity', ['verify', fullUrl]);
  let out = '', err = '';

  cli.stdout.on('data', d => out += d);
  cli.stderr.on('data', d => err += d);

  cli.on('close', code => {
    if (code !== 0) {
      return res
        .status(400)
        .send(`<h1>❌ Verification failed</h1><pre>${err}</pre>`);
    }

    let result;
    try {
      result = JSON.parse(out);
    } catch (e) {
      return res.status(500).send('<h1>Invalid JSON from identity CLI</h1>');
    }

    if (!result.verified) {
      return res.send('<h1>❌ Proof invalid!</h1>');
    }

    // Map each key → user-friendly label
    const labels = {
      first_name: 'First name',
      last_name:  'Last name',
      license:    'License number',
      dob_before: 'Date of birth before',
      dob_after:  'Date of birth after',
      dob_equal:  'Date of birth exactly'
    };

    // Turn days-since-CE back into YYYY-MM-DD
    const humanDate = days => {
      const ms = (days - 719163) * 86400000;
      return new Date(ms).toISOString().slice(0,10);
    };

    const items = Object.entries(result.validated)
      .map(([key, val]) => {
        let display = val;
        if (['dob_before','dob_after','dob_equal'].includes(key)) {
          display = humanDate(val);
        }
        return `<li><strong>${labels[key]}:</strong> ${display}</li>`;
      })
      .join('\n');

    res.send(`
      <h1>✅ Identity validated</h1>
      <ul style="font-size:1.1rem; line-height:1.4;">
        ${items}
      </ul>
      <p><a href="/">← Back</a></p>
    `);
  });
});

app.listen(port, () => {
  console.log(`Demo listening at http://localhost:${port}`);
});
