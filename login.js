document.querySelector('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Get form values
    const email = document.querySelector('#email').value;
    const passwords = document.querySelector('#passwords').value;
    const role = document.querySelector('#roles').value; // Get the selected role

    // Validate if role is selected
    if (!role) {
        alert('Please select a role.');
        return;
    }

    try {
        // Send login data to backend
        const response = await fetch('http://localhost:5000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, passwords, role }), // Include role in the request
        });

        const data = await response.json();

        if (response.ok) {
            alert('Login successful!');

            // Save token or user info in local storage or session storage
            localStorage.setItem('token', data.token); // Store JWT token for authenticated requests
            localStorage.setItem('role', role); // Save the user's role for future use

            // Redirect based on user role
            if (role === 'doctor') {
                window.location.href = 'dashboard.html'; // Redirect to doctor's dashboard
            } else if (role === 'client') {
                window.location.href = 'appointmentbook.html'; // Redirect to booking page
            }
        } else {
            alert(data.error); // Show error message from backend
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Something went wrong. Please try again.');
    }
});
