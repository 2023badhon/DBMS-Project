document.addEventListener('DOMContentLoaded', async () => {
    const doctorSelect = document.querySelector('#doctor-select'); // Select dropdown by its id
    try {
        const response = await fetch('http://localhost:5000/api/doctors'); // Fetch data from backend
        if (!response.ok) {
            throw new Error('Failed to fetch doctors');
        }
        const doctors = await response.json(); // Parse JSON response
        doctors.forEach(doctor => {
            const option = document.createElement('option'); // Create an <option> element
            option.value = doctor.id; // Use doctor's ID as the value
            option.textContent = doctor.full_name; // Display doctor's name
            doctorSelect.appendChild(option); // Append to the dropdown
        });
    } catch (error) {
        console.error('Error:', error); // Log any errors
    }
});
