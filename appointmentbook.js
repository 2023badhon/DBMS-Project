document.addEventListener('DOMContentLoaded', () => {
    const doctorSelect = document.getElementById('doctor-select');
    const specializationSelect = document.getElementById('specialization-select');
    const bookNowButton = document.getElementById('book-now');
    const appointmentForm = document.getElementById('appointment-form');
    const logoutLink = document.getElementById('logout-link'); // Reference to the logout link

    // Fetch doctors from the database
    async function fetchDoctors() {
        try {
            const response = await fetch('http://localhost:5000/api/doctors');
            const doctors = await response.json();
            doctorSelect.innerHTML = '<option value="" disabled selected>Select Doctor</option>';
            doctors.forEach(doctor => {
                const option = document.createElement('option');
                option.value = doctor.id;
                option.textContent = doctor.full_name;
                doctorSelect.appendChild(option);
            });
        } catch (error) {
            console.error('Error fetching doctors:', error);
        }
    }

    // Fetch specializations for the selected doctor
    async function fetchSpecializations(doctorId) {
        try {
            const response = await fetch(`http://localhost:5000/api/doctor-specializations/${doctorId}`);
            const specializations = await response.json();
            specializationSelect.innerHTML = '<option value="" disabled selected>Select Specialization</option>';
            specializations.forEach(spec => {
                const option = document.createElement('option');
                option.value = spec.specialization_name; // Using the name directly
                option.textContent = spec.specialization_name;
                specializationSelect.appendChild(option);
            });
        } catch (error) {
            console.error('Error fetching specializations:', error);
        }
    }

    // Event listener for doctor selection
    doctorSelect.addEventListener('change', (e) => {
        const doctorId = e.target.value;
        if (doctorId) {
            fetchSpecializations(doctorId);
        } else {
            specializationSelect.innerHTML = '<option value="" disabled selected>Select Specialization</option>';
        }
    });

    // Handle form submission
    bookNowButton.addEventListener('click', async () => {
        // Get field values from the form
        const fullName = appointmentForm.querySelector('input[placeholder="Full name"]').value.trim();
        const email = appointmentForm.querySelector('input[placeholder="Email address"]').value.trim();
        const phone = appointmentForm.querySelector('input[placeholder="Enter Phone Number"]').value.trim();
        const date = appointmentForm.querySelector('input[type="date"]').value.trim();
        const doctor = doctorSelect.value;
        const specialization = specializationSelect.value;
        const additionalMessage = appointmentForm.querySelector('textarea').value.trim();

        // Validate all required fields
        if (!fullName || !email || !phone || !date || !doctor || !specialization) {
            alert('Please fill out all required fields.');
            return;
        }

        // Prepare data for submission
        const appointmentData = {
            full_name: fullName,
            email: email,
            phone: phone,
            appointment_date: date,
            doctor,
            specialization,
            additional_message: additionalMessage
        };

        try {
            const response = await fetch('http://localhost:5000/api/book-appointment', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(appointmentData)
            });

            if (response.ok) {
                alert('Appointment booked successfully!');
                appointmentForm.reset();
                window.location.href = 'client-dashboard.html'; // Redirect to dashboard
            } else {
                const error = await response.json();
                alert(`Error: ${error.error}`);
            }
        } catch (error) {
            console.error('Error booking appointment:', error);
            alert('Failed to book appointment. Please try again later.');
        }
    });

    // Initial fetch of doctors
    fetchDoctors();

    // Logout functionality
    logoutLink.addEventListener('click', (e) => {
        e.preventDefault(); // Prevent default anchor behavior

        if (confirm("Are you sure you want to log out?")) {
            // Clear session data
            sessionStorage.clear();
            localStorage.clear();

            // Redirect to login page
            window.location.href = 'index.html'; // Replace with your login page URL
        }
    });
});
