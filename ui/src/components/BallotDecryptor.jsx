import { useState } from 'react';
import axios from 'axios';

function BallotDecryptor({ numVotes }) {
  const [index, setIndex] = useState('');
  const [decryptedOutput, setDecryptedOutput] = useState('');
  const [error, setError] = useState('');

  const handleDecrypt = async () => {
    if (index === '' || isNaN(index)) {
      setError('Please enter a valid index.');
      setDecryptedOutput('');
      return;
    }

    try {
      const res = await axios.post('http://localhost:3001/decrypt', { index });
      const output = res.data.output;

      if (output.includes('Decrypted PII') && output.includes('Vote Weight')) {
        setDecryptedOutput(output);
        setError('');
      } else {
        setError('Failed to decrypt.');
        setDecryptedOutput('');
      }
    } catch (err) {
      setError('Server error while decrypting.');
      setDecryptedOutput('');
      console.error(err);
    }
  };

  return (
    <div className="bg-gray-100 text-black p-6 rounded mt-10">
      <h2 className="text-2xl font-bold mb-4">🔐 Decrypt Specific Ballot</h2>
      <div className="mb-4 flex items-center gap-4">
        <label htmlFor="indexInput">Ballot Index (0 to {numVotes - 1}):</label>
        <input
          type="number"
          id="indexInput"
          value={index}
          min={0}
          max={numVotes - 1}
          onChange={(e) => setIndex(e.target.value)}
          className="border p-2 w-20 rounded"
        />
        <button
          onClick={handleDecrypt}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded"
        >
          Decrypt
        </button>
      </div>
      {error && <p className="text-red-600">{error}</p>}
      {decryptedOutput && (
        <pre className="bg-white p-4 border rounded mt-4 whitespace-pre-wrap">
          {decryptedOutput}
        </pre>
      )}
    </div>
  );
}

export default BallotDecryptor;
