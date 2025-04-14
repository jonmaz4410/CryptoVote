function SetupForm({ numCandidates, setNumCandidates, maxVoters, setMaxVoters, numVotes, setNumVotes }) {
    return (
      <div className="bg-gray-800 p-6 rounded-lg shadow-md mb-8">
        <h2 className="text-xl font-semibold mb-4">Vote Setup</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <input
            type="number"
            placeholder="# of Candidates"
            value={numCandidates}
            onChange={(e) => setNumCandidates(e.target.value)}
            className="p-2 rounded bg-gray-700 text-white"
          />
          <input
            type="number"
            placeholder="Max Voters (k)"
            value={maxVoters}
            onChange={(e) => setMaxVoters(e.target.value)}
            className="p-2 rounded bg-gray-700 text-white"
          />
          <input
            type="number"
            placeholder="# of Votes to Simulate"
            value={numVotes}
            onChange={(e) => setNumVotes(e.target.value)}
            className="p-2 rounded bg-gray-700 text-white"
          />
        </div>
      </div>
    );
  }
  
  export default SetupForm;
  