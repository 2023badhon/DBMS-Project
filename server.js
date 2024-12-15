// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const path = require('path'); // <-- Add this line to import path module
const db = require('./config'); // Import the db connection from config.js

require('dotenv').config(); // Load environment variables

// Initialize Express app
const app = express();

// Middleware setup
app.use(cors({
    origin: 'http://localhost:5500', // Replace with your frontend URL
}));

app.use(bodyParser.json());

// Define the port for the server
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;

// Test database connection
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
    } else {
        console.log('Connected to MySQL database');
    }
});

// Define routes
app.get('/', (req, res) => {
    res.send('Welcome to the DAMS API!');
});
app.use(express.static(path.join(__dirname, 'frontend')));

// Signup API endpoint
app.post('/api/signup', async (req, res) => {
    const { full_name, email, mobileNumber, passwords, roles, specialization } = req.body;

    // Validate user inputs
    if (!full_name || !email || !mobileNumber || !passwords || !roles) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (roles === 'doctor' && !specialization) {
        return res.status(400).json({ error: 'Specialization is required for doctors' });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if the email already exists
    const checkQuery = `SELECT * FROM users WHERE email = ?`;
    db.query(checkQuery, [email], async (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (result.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(passwords, 10);

        // Add specialization to the `specializations` table if it doesn't exist
        if (roles === 'doctor') {
            const addSpecializationQuery = `
                INSERT INTO specializations (specialization_name)
                SELECT ?
                WHERE NOT EXISTS (SELECT 1 FROM specializations WHERE specialization_name = ?)
            `;
            db.query(addSpecializationQuery, [specialization, specialization], (err) => {
                if (err) {
                    console.error('Failed to add specialization:', err);
                    return res.status(500).json({ error: 'Failed to add specialization' });
                }
            });
        }

        // Insert the new user into the `users` table
        const insertUserQuery = `
            INSERT INTO users (full_name, email, mobileNumber, passwords, roles, specialization)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        db.query(insertUserQuery, [full_name, email, mobileNumber, hashedPassword, roles, specialization || null], (err) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to register user' });
            }

            res.status(201).json({ message: 'Signup successful' });
        });
    });
});


// Login API endpoint
app.post('/api/login', (req, res) => {
    const { email, passwords } = req.body;

    // Validate user inputs
    if (!email || !passwords) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if the user exists in the database
    const checkQuery = `SELECT * FROM users WHERE email = ?`;
    db.query(checkQuery, [email], async (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (result.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = result[0];

        // Check if the password matches
        const isPasswordValid = await bcrypt.compare(passwords, user.passwords);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email, roles: user.roles },
            SECRET_KEY,
            { expiresIn: '1h' } // Token validity
        );

        // Return success message and token
        res.status(200).json({ message: 'Login successful', token });
    });
});

// Protected route example (Optional)
app.get('/api/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        res.status(200).json({ message: 'Protected content accessed', user });
    });
});

// Appointment Booking API endpoint
app.post('/api/book-appointment', (req, res) => {
    const { full_name, email, phone, appointment_date, doctor, specialization, additional_message } = req.body;

    // Validate user inputs
    if (!full_name || !email || !phone || !appointment_date || !doctor || !specialization) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if the client exists in the database
    const clientQuery = `SELECT id FROM users WHERE email = ? AND roles = 'client'`;
    db.query(clientQuery, [email], (err, clientResult) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        let clientId;
        if (clientResult.length === 0) {
            // Insert new client if not already registered
            const insertClientQuery = `
                INSERT INTO users (full_name, email, mobileNumber, passwords, roles)
                VALUES (?, ?, ?, ?, 'client')
            `;
            const tempPassword = bcrypt.hashSync('temporaryPassword123', 10); // Set a temporary password
            db.query(insertClientQuery, [full_name, email, phone, tempPassword], (err, insertResult) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Failed to register client' });
                }
                clientId = insertResult.insertId;
                createAppointment(clientId);
            });
        } else {
            clientId = clientResult[0].id;
            createAppointment(clientId);
        }
    });

    // Function to create the appointment
    function createAppointment(clientId) {
        const appointmentQuery = `
            INSERT INTO appointments (doctor_id, client_id, appointment_date, additional_message, statuses)
            VALUES (?, ?, ?, ?, 'pending')
        `;
        db.query(appointmentQuery, [doctor, clientId, appointment_date, additional_message], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to book appointment' });
            }
            res.status(201).json({ message: 'Appointment booked successfully', appointmentId: result.insertId });
        });
    }
});


// Fetch all doctors API endpoint
app.get('/api/doctors', (req, res) => {
    const query = `SELECT id, full_name FROM users WHERE roles = 'doctor'`;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'No doctors found' });
        }
        res.status(200).json(results); // Send doctors list as JSON
    });
});

// API to fetch specializations for a specific doctor
app.get('/api/doctor-specializations/:doctorId', (req, res) => {
    const doctorId = req.params.doctorId;

    const query = `
        SELECT specialization AS specialization_name
        FROM users
        WHERE id = ? AND roles = 'doctor'
    `;

    db.query(query, [doctorId], (err, results) => {
        if (err) {
            console.error('Error fetching specializations:', err);
            return res.status(500).json({ error: 'Failed to fetch specializations' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'No specializations found for this doctor' });
        }

        res.status(200).json(results);
    });
});


// Middleware to authenticate JWT token
function authenticateJWT(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Get token from Authorization header
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;  // Attach user info to the request object
        next();
    });
}

// Endpoint to update profile
app.put('/api/client-profile', authenticateJWT, (req, res) => {
    const { full_name, email, phone } = req.body;
    const userId = req.user.id;  // Extract the user ID from the decoded JWT token

    // Check if the user is sending valid data
    if (!full_name || !email || !phone) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Update the user's profile in the database
    const query = `
        UPDATE users 
        SET full_name = ?, email = ?, mobileNumber = ? 
        WHERE id = ?
    `;
    db.query(query, [full_name, email, phone, userId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update profile' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'Profile updated successfully' });
    });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from the "Bearer <token>" format

    if (!token) {
        return res.status(401).json({ message: 'Token is missing or invalid.' });
    }

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token is invalid or expired.' });
        }
        req.user = user; // Attach the user information to the request
        next(); // Proceed to the next middleware or route handler
    });
}


//dashboard_stats
app.get('/api/dashboard-stats', authenticateToken, (req, res) => {
    const userId = req.user.id;

    const query = `
        SELECT 
            COUNT(CASE WHEN statuses = 'pending' THEN 1 END) AS upcoming,
            COUNT(CASE WHEN statuses = 'approved' THEN 1 END) AS completed,
            COUNT(CASE WHEN statuses = 'canceled' THEN 1 END) AS cancelled,
            COUNT(*) AS total
        FROM appointments
        WHERE client_id = ?
    `;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch stats.' });
        }
        res.json(results[0]);
    });
});

// Fetch appointments based on status
app.get('/api/appointments', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { status } = req.query;

    let query = `
        SELECT 
            a.id, 
            a.appointment_date AS date, 
            a.statuses AS status,
            u.full_name AS doctorName,
            u.specialization AS specialization
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        WHERE a.client_id = ?`;

    const params = [userId];
    if (status && status !== 'all') {
        query += ' AND a.statuses = ?';
        params.push(status);
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch appointments.' });
        }
        res.json(results);
    });
});
//Appointment ID
app.get('/api/appointment/:id', authenticateToken, (req, res) => {
    const appointmentId = req.params.id;
    const userId = req.user.id;

    const query = `
        SELECT 
            a.id,
            a.appointment_date AS date,
            a.additional_message AS additionalMessage,
            a.statuses AS status,
            u.full_name AS doctorName,
            u.specialization AS specialization
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        WHERE a.id = ? AND a.client_id = ?
    `;

    db.query(query, [appointmentId, userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch appointment details.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'No appointment found or unauthorized access.' });
        }

        res.json(results[0]);
    });
});



// Search doctor by name
app.get('/api/doctor', (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ error: 'Query parameter is required.' });
    }

    const sql = `
        SELECT u.id, u.full_name, u.specialization
        FROM users u
        WHERE u.roles = 'doctor'
        AND (u.full_name LIKE ? OR u.specialization LIKE ?)
    `;

    db.query(sql, [`%${query}%`, `%${query}%`], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch doctors.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'No doctors found.' });
        }

        res.status(200).json(results); // Send the list of doctors as JSON
    });
});

// API to fetch all doctors
app.get('/api/get-doctors', (req, res) => {
    const query = `
        SELECT id, full_name 
        FROM users 
        WHERE roles = 'doctor'
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching doctors:', err);
            res.status(500).json({ error: 'Failed to fetch doctors.' });
        } else {
            res.json(results);
        }
    });
});


// API to fetch filtered appointments report
app.get('/api/get-appointments-report', (req, res) => {
    const { status, doctor_id, dateFrom, dateTo } = req.query;

    let query = `
        SELECT 
            a.id AS id,
            u1.full_name AS patient_name,
            u2.full_name AS doctor_name,
            a.appointment_date,
            a.statuses AS statuses,
            a.additional_message
        FROM appointments a
        JOIN users u1 ON a.client_id = u1.id
        JOIN users u2 ON a.doctor_id = u2.id
        WHERE 1=1
    `;
    const params = [];

    // Apply filters dynamically
    if (status && status !== 'all') {
        query += ' AND a.statuses = ?';
        params.push(status);
    }

    if (doctor_id) { // No 'all' check because frontend might send empty value
        query += ' AND a.doctor_id = ?';
        params.push(doctor_id);
    }

    if (dateFrom) {
        query += ' AND a.appointment_date >= ?';
        params.push(dateFrom);
    }

    if (dateTo) {
        query += ' AND a.appointment_date <= ?';
        params.push(dateTo);
    }

    db.query(query, params, (err, results) => {
        if (err) {
            console.error('Error fetching appointments:', err);
            res.status(500).json({ error: 'Failed to fetch appointments report.' });
        } else {
            res.json(results);
        }
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
