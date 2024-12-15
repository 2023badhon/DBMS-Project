document.querySelector('#signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Get form values
    const full_name = document.querySelector('#full_name').value;
    const email = document.querySelector('#email').value;
    const mobileNumber = document.querySelector('#mobileNumber').value;
    const passwords = document.querySelector('#passwords').value;
    const roles = document.querySelector('#roles').value;

    // Show/hide the specialization field based on role
    const specialization = roles === 'doctor' ? document.querySelector('#specialization').value : null;

    // Send data to backend
    try {
        const response = await fetch('http://localhost:5000/api/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ full_name, email, mobileNumber, passwords, roles, specialization }),
        });

        const data = await response.json();
        if (response.ok) {
            alert(data.message);
            window.location.href = 'login.html'; // Redirect to login page
        } else {
            alert(data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Something went wrong. Please try again.');
    }
});

// Show specialization input when doctor role is selected
document.querySelector('#roles').addEventListener('change', (e) => {
    const specializationDiv = document.getElementById('specialization-div');
    if (e.target.value === 'doctor') {
        specializationDiv.style.display = 'block';
    } else {
        specializationDiv.style.display = 'none';
    }
});
