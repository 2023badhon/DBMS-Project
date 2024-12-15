document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Please log in to access the dashboard.');
        window.location.href = 'login.html';
        return;
    }

    // Fetch and display appointment stats
    await fetchAppointmentStats(token);

    // Event listeners for "View Details" buttons
    document.querySelectorAll('.view-btn').forEach((btn) => {
        btn.addEventListener('click', async () => {
            const status = btn.getAttribute('data-status');
            await fetchAppointmentsByStatus(status, token);
        });
    });
});

// Fetch appointment stats
async function fetchAppointmentStats(token) {
    try {
        const response = await fetch('http://localhost:5000/api/dashboard-stats', {
            headers: { Authorization: `Bearer ${token}` },
        });

        if (response.ok) {
            const stats = await response.json();
            document.querySelector('.stats-card.yellow .stats-value').textContent = stats.upcoming || 0;
            document.querySelector('.stats-card.green .stats-value').textContent = stats.completed || 0;
            document.querySelector('.stats-card.red .stats-value').textContent = stats.cancelled || 0;
            document.querySelector('.stats-card.blue .stats-value').textContent = stats.total || 0;
        } else {
            alert('Failed to fetch stats.');
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Fetch appointments by status
async function fetchAppointmentsByStatus(status, token) {
    try {
        const endpoint = status === 'all' ? '/api/appointments' : `/api/appointments?status=${status}`;
        const response = await fetch(`http://localhost:5000${endpoint}`, {
            headers: { Authorization: `Bearer ${token}` },
        });

        if (response.ok) {
            const appointments = await response.json();
            displayAppointments(appointments, status);
        } else {
            alert('Failed to fetch appointments.');
        }
    } catch (error) {
        console.error('Error fetching appointments:', error);
    }
}

// Display appointments in the UI
function displayAppointments(appointments, status) {
    const appointmentsList = document.querySelector('.appointments-list');
    appointmentsList.innerHTML = `<h3>Appointments - ${status === 'all' ? 'All' : status}</h3>`;

    if (appointments.length === 0) {
        appointmentsList.innerHTML += '<p>No appointments found for this category.</p>';
        return;
    }

    appointments.forEach((appointment) => {
        const div = document.createElement('div');
        div.classList.add('appointment-item');
        div.innerHTML = `
            <h3>Dr. ${appointment.doctorName} (${appointment.specialization})</h3>
            <p><strong>Date:</strong> ${appointment.date}</p>
            <p><strong>Status:</strong> ${appointment.status}</p>
            <button class="view-details-btn" data-id="${appointment.id}">View Details</button>
        `;
        appointmentsList.appendChild(div);
    });

    addDetailsButtonListeners(); // Add listeners for "View Details"
}

// Add event listeners for "View Details" buttons
function addDetailsButtonListeners() {
    document.querySelectorAll('.view-details-btn').forEach((btn) => {
        btn.addEventListener('click', async (event) => {
            const appointmentId = event.target.getAttribute('data-id');
            console.log(`View Details clicked for appointment ID: ${appointmentId}`);
            await fetchAppointmentDetails(appointmentId);
        });
    });
}

// Fetch appointment details
async function fetchAppointmentDetails(appointmentId) {
    const token = localStorage.getItem('token');
    try {
        const response = await fetch(`http://localhost:5000/api/appointment/${appointmentId}`, {
            headers: {
                Authorization: `Bearer ${localStorage.getItem('token')}`, // Retrieve token from localStorage
            },
        });

        if (response.ok) {
            const details = await response.json();
            alert(`
                Appointment Details:
                Doctor: Dr. ${details.doctorName} (${details.specialization})
                Date: ${details.date}
                Status: ${details.status}
                Additional Message: ${details.additionalMessage}
            `);
        } else {
            const error = await response.json();
            alert(`Error: ${error.error}`);
        }
    } catch (error) {
        console.error('Error fetching appointment details:', error);
        alert('Failed to fetch appointment details.');
    }
}
