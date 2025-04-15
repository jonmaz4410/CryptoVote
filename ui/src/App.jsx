import { useState } from 'react';
import axios from 'axios';
import FullResultsTable from './components/FullResultsTable';
import { IoReloadSharp } from 'react-icons/io5';
import { GiCyberEye } from 'react-icons/gi';

function App() {
  const [numCandidates, setNumCandidates] = useState('');
  const [maxVoters, setMaxVoters] = useState('');
  const [numVotes, setNumVotes] = useState('');
  const [tallyData, setTallyData] = useState(null);
  const [loading, setLoading] = useState(false);

  const simulateTally = async () => {
    setLoading(true);
    try {
      const res = await axios.post('http://localhost:3001/simulate', {
        numCandidates,
        maxVoters,
        numVotes,
      });
      setTallyData({ rawOutput: res.data.output });
    } catch (err) {
      console.error('Error simulating tally:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white px-6 py-10">
      <h1 className="text-4xl font-bold text-center mb-12 flex items-center justify-center gap-2">
        <GiCyberEye className="text-lime-600" />
        CryptoVote
      </h1>

      <div className="flex flex-wrap justify-center gap-4 mb-10">
        <input
          type="number"
          className="bg-gray-800 text-white border border-gray-600 rounded px-4 py-2 w-48 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          placeholder="Candidates"
          value={numCandidates}
          onChange={(e) => setNumCandidates(parseInt(e.target.value))}
        />
        <input
          type="number"
          className="bg-gray-800 text-white border border-gray-600 rounded px-4 py-2 w-48 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          placeholder="Max Voters (k)"
          value={maxVoters}
          onChange={(e) => setMaxVoters(parseInt(e.target.value))}
        />
        <input
          type="number"
          className="bg-gray-800 text-white border border-gray-600 rounded px-4 py-2 w-48 focus:outline-none focus:ring-2 focus:ring-emerald-500"
          placeholder="Num Votes"
          value={numVotes}
          onChange={(e) => setNumVotes(parseInt(e.target.value))}
        />
        <button
          className="text-white bg-emerald-600 hover:bg-emerald-700 px-6 py-2 rounded-full font-medium"
          onClick={simulateTally}
        >
          Simulate Vote Tally
        </button>
      </div>

      {loading && (
        <div className="flex items-center justify-center mt-4 text-white text-sm space-x-2">
          <IoReloadSharp className="animate-spin text-lg" />
          <span>Simulating votes, please wait...</span>
        </div>
      )}

      {!loading && tallyData && (
        <FullResultsTable tallyData={tallyData} numVotes={numVotes} />
      )}
    </div>
  );
}

export default App;
