import { useState } from 'react';
import axios from 'axios';
import { FaRegEye, FaRegEyeSlash } from 'react-icons/fa';
import { IoReloadSharp } from 'react-icons/io5';

export default function FullResultsTable({ tallyData, numVotes }) {
  const [index, setIndex] = useState('');
  const [decryptedBallots, setDecryptedBallots] = useState([]);
  const [showAES, setShowAES] = useState(false);
  const [decryptLoading, setDecryptLoading] = useState(false);

  const extractField = (label) => {
    const line = tallyData?.rawOutput?.split('\n').find(line => line.includes(label));
    return line?.split(':')[1]?.trim() || '';
  };

  const getCandidateFields = () => {
    const lines = tallyData?.rawOutput?.split('\n') || [];
    const weights = [];
    const votes = [];

    for (const line of lines) {
      if (/Candidate \d+: Weight =/.test(line)) {
        const match = line.match(/Candidate (\d+): Weight = ([\d]+)/);
        if (match) weights.push([`Candidate ${match[1]} Weight`, match[2]]);
      }
      if (/Candidate \d+: \d+ votes/.test(line)) {
        const match = line.match(/Candidate (\d+): (\d+) votes/);
        if (match) votes.push([`Candidate ${match[1]} Votes`, match[2]]);
      }
    }

    return { weights, votes };
  };

  const decodeVoteWeight = (weightBigInt, M, numCandidates) => {
    const decoded = [];
    const base = BigInt(M);
    let weight = BigInt(weightBigInt);

    for (let i = 0; i < numCandidates; i++) {
      const count = weight % base;
      decoded.push(Number(count));
      weight = weight / base;
    }

    return decoded;
  };

  const handleDecrypt = async () => {
    setDecryptLoading(true);
    const ballotIndex = index; // snapshot before reset
    try {
      const res = await axios.post('http://localhost:3001/decrypt', { index: ballotIndex });

      const piiLine = res.data.output.split('\n').find(line => line.includes('Decrypted PII:'));
      const weightLine = res.data.output.split('\n').find(line => line.includes('Decrypted Plaintext Vote Weight'));

      const pii = piiLine?.split(':')[1]?.trim().replace(/"/g, '');
      const rawWeight = weightLine?.split(':')[1]?.trim();

      const numCandidates = parseInt(extractField('Number of Candidates'));
      const maxVoters = parseInt(extractField('Max Expected Voters (k)'));
      const M = maxVoters + 1;

      let decodedVotes = [];
      try {
        const weightBigInt = BigInt(rawWeight);
        decodedVotes = decodeVoteWeight(weightBigInt, M, numCandidates);
      } catch (err) {
        console.error('❌ Failed decoding vote weight:', rawWeight, err);
      }

      setDecryptedBallots(prev => [
        ...prev,
        { index: ballotIndex, pii, rawWeight, decodedVotes },
      ]);

      setIndex('');
    } catch (err) {
      alert('Failed to decrypt ballot');
      console.error(err);
    } finally {
      setDecryptLoading(false);
    }
  };

  const { weights, votes } = getCandidateFields();
  const aesKey = extractField('Generated AES Key');

  return (
    <div className="w-full max-w-6xl mx-auto space-y-10">
      {/* Simulation Table */}
      <div className="overflow-x-auto shadow-md sm:rounded-lg">
        <table className="w-full text-sm text-left text-white bg-gray-900">
          <thead className="text-xs uppercase bg-gray-800 border-b border-gray-700">
            <tr>
              <th className="px-6 py-3">FIELD</th>
              <th className="px-6 py-3">VALUE</th>
            </tr>
          </thead>
          <tbody>
            {[
              [
                'AES Key',
                aesKey ? (
                  <div className="flex items-center space-x-2">
                    <span>
                      {showAES ? aesKey : '••••••••••••••••••••••••••••••••'}
                    </span>
                    <button
                      onClick={() => setShowAES(!showAES)}
                      className="text-blue-400 hover:text-blue-300"
                    >
                      {showAES ? <FaRegEyeSlash /> : <FaRegEye />}
                    </button>
                  </div>
                ) : (
                  'N/A'
                ),
              ],
              ['Candidates', extractField('Number of Candidates')],
              ['Max Voters (k)', extractField('Max Expected Voters (k)')],
              ['Encoding Base (M = k + 1)', extractField('Encoding Base')],
              ['Total Sum', extractField('Decrypted total sum')],
              ...weights,
              ...votes,
              ['Total Votes Decoded', extractField('Total votes decoded')],
            ].map(([label, value], i) => (
              <tr key={i} className="border-b border-gray-700 hover:bg-gray-800">
                <td className="px-6 py-4 font-semibold whitespace-nowrap">{label}</td>
                <td className="px-6 py-4">{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Ballot Decryption Section */}
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white flex items-center">🔐 Decrypt Ballot</h2>
        <div className="flex space-x-3 items-center">
          <input
            type="number"
            min={0}
            max={numVotes - 1}
            value={index}
            onChange={(e) => setIndex(e.target.value)}
            placeholder={`Ballot Index (0 to ${numVotes - 1})`}
            className="border border-gray-500 bg-gray-800 text-white px-4 py-2 rounded w-64 focus:outline-none focus:ring focus:ring-blue-400"
          />
          <button
            onClick={handleDecrypt}
            disabled={decryptLoading}
            className={`${
              decryptLoading
                ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                : 'bg-gray-800 text-white hover:bg-gray-700'
            } border border-gray-600 px-5 py-2.5 rounded-full text-sm font-medium`}
          >
            {decryptLoading ? (
              <div className="flex items-center space-x-2">
                <IoReloadSharp className="animate-spin" />
                <span>Decrypting...</span>
              </div>
            ) : (
              'Decrypt'
            )}
          </button>
        </div>

        {decryptedBallots.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left text-white bg-gray-900 shadow-md sm:rounded-lg mt-4">
              <thead className="text-xs uppercase bg-gray-800 border-b border-gray-700">
                <tr>
                  <th className="px-6 py-3">BALLOT #</th>
                  <th className="px-6 py-3">PII</th>
                  <th className="px-6 py-3">RAW WEIGHT</th>
                  <th className="px-6 py-3">DECODED VOTES</th>
                </tr>
              </thead>
              <tbody>
                {decryptedBallots.map((ballot, i) => (
                  <tr key={i} className="border-b border-gray-700 hover:bg-gray-800">
                    <td className="px-6 py-4">{ballot.index}</td>
                    <td className="px-6 py-4">{ballot.pii}</td>
                    <td className="px-6 py-4">{ballot.rawWeight}</td>
                    <td className="px-6 py-4">
                      {ballot.decodedVotes
                        .map((vote, idx) => ({ idx, vote }))
                        .filter(({ vote }) => vote > 0)
                        .map(({ idx, vote }) => (
                          <div key={idx}>
                            Candidate {idx}: {vote} vote{vote !== 1 ? 's' : ''}
                          </div>
                        ))}
                      {ballot.decodedVotes.every(v => v === 0) && (
                        <div className="text-gray-400 italic">No votes cast</div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
