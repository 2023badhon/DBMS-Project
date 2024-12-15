document.querySelector('#profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const fullName = document.querySelector('#full-name').value;
    const email = document.querySelector('#email').value;
    const phone = document.querySelector('#phone').value;

    // Get token from localStorage (check if token is available)
    const token = localStorage.getItem('token');
    if (!token) {
        alert('You must be logged in to update your profile.');
        return;
    }

    try {
        const response = await fetch('http://localhost:5000/api/client-profile', {
            method: 'PUT', // Assuming a PUT method for updating profile
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Include JWT token if required
            },
            body: JSON.stringify({
                full_name: fullName,
                email: email,
                phone: phone
            })
        });

        const data = await response.json();
        if (response.ok) {
            alert('Profile updated successfully!');
        } else {
            alert(data.error || 'Failed to update profile');
        }
    } catch (error) {
        alert('Something went wrong. Please try again.');
        console.error(error);
    }
});
