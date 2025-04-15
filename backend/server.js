import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = 3001;
app.use(cors());
app.use(express.json());

const __dirname = path.dirname(fileURLToPath(import.meta.url));


let lastSimInputs = {
  numCandidates: 0,
  maxVoters: 0,
  numVotes: 0
};

app.post('/simulate', (req, res) => {
  const { numCandidates, maxVoters, numVotes } = req.body;
  lastSimInputs = { numCandidates, maxVoters, numVotes };

  const input = `${numCandidates}\n${maxVoters}\n${numVotes}\nn\n`;
  console.log('✅ /simulate hit');
  console.log('🟡 Running:', input.replace(/\n/g, '\\n'));

  exec(`echo "${input}" | ./bin/cryptovote`, { cwd: __dirname }, (err, stdout, stderr) => {
    if (err) {
      console.error(' Error executing cryptovote:', err);
      return res.status(500).send({ error: 'Execution failed.' });
    }
    res.send({ output: stdout });
  });
});

app.post('/decrypt', (req, res) => {
  const { index } = req.body;
  const input = `${lastSimInputs.numCandidates}\n${lastSimInputs.maxVoters}\n${lastSimInputs.numVotes}\ny\n${index}\nn\n`;

  console.log('✅ /decrypt hit');
  console.log('🟡 Running:', input.replace(/\n/g, '\\n'));

  exec(`echo "${input}" | ./bin/cryptovote`, { cwd: __dirname }, (err, stdout, stderr) => {
    if (err) {
      console.error(' Error executing cryptovote for decrypt:', err);
      return res.status(500).send({ error: 'Decryption failed.' });
    }

  const lines = stdout.split('\n');
  const start = lines.findIndex(line => line.includes('--- Decrypting Ballot'));
  const piiLine = lines.find(line => line.includes('Decrypted PII:'));
  const weightLine = lines.find(line => line.includes('Decrypted Plaintext Vote Weight'));

const cleanOutput = (start !== -1 && piiLine && weightLine)
  ? [`${lines[start]}`, piiLine, weightLine].join('\n')
  : ' Could not extract ballot decryption info.';

    res.send({ output: cleanOutput });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Backend running at http://localhost:${PORT}`);
});
