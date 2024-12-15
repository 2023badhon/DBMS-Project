// Function to search doctors based on their name
async function searchDoctors(query) {
    if (!query.trim()) {
        alert('Please enter a search term.');
        return;
    }

    try {
        const response = await fetch(`http://localhost:5000/api/doctor?query=${query}`);
        const doctors = await response.json();

        const resultsContainer = document.querySelector('.search-results');
        resultsContainer.innerHTML = ''; // Clear previous results

        if (response.ok) {
            if (doctors.length > 0) {
                doctors.forEach((doctor) => {
                    const resultItem = document.createElement('div');
                    resultItem.className = 'result-item'; // Add a class for styling
                    resultItem.innerHTML = `
                        <h3>${doctor.full_name}</h3>
                        <p>Specialization: ${doctor.specialization || 'Not Specified'}</p>
                    `;
                    resultsContainer.appendChild(resultItem);
                });
            } else {
                resultsContainer.innerHTML = '<p>No doctors found.</p>';
            }
        } else {
            alert(doctors.error || 'Failed to fetch doctors.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error fetching doctors.');
    }
}


// Search when the input changes
document.querySelector('#search-doctors').addEventListener('input', (e) => {
    const query = e.target.value;
    if (query) {
        searchDoctors(query);
    }
});

// Search when the "Search" button is clicked
document.querySelector('#search-btn').addEventListener('click', () => {
    const query = document.querySelector('#search-doctors').value;
    if (query) {
        searchDoctors(query);
    }
});
