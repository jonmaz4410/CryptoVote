function TallyResults({ tallyData }) {
    if (!tallyData || !tallyData.rawOutput) return null;
  
    return (
      <div className="bg-gray-800 p-6 rounded-lg shadow-md mb-6">
        <h2 className="text-xl font-semibold mb-4">📊 Simulation Output</h2>
        <pre className="whitespace-pre-wrap text-sm bg-black text-green-300 p-4 rounded">
          {tallyData.rawOutput}
        </pre>
      </div>
    );
  }
  
  export default TallyResults;
  