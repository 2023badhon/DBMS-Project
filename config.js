
const mysql = require('mysql2');  // Use mysql2 instead of mysql

const db = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: '*A1b2c3#',
    database: 'damsdb'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database');
});

module.exports = db;