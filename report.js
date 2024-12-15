document.addEventListener('DOMContentLoaded', () => {
    const filterButton = document.getElementById('filterReport');
    const exportButton = document.getElementById('exportReport');
    const statusSelect = document.getElementById('status');
    const doctorSelect = document.getElementById('doctor-select'); // Corrected ID
    const dateFromInput = document.getElementById('dateFrom');
    const dateToInput = document.getElementById('dateTo');
    const reportTable = document.getElementById('appointmentsReportTable').getElementsByTagName('tbody')[0];

    let filteredData = []; // Initialize to store fetched data for export

    // Fetch doctors for the dropdown
    async function fetchDoctors() {
        const response = await fetch('/api/get-doctors');
        const data = await response.json();

        data.forEach(doctor => {
            const option = document.createElement('option');
            option.value = doctor.id;
            option.textContent = doctor.full_name;
            doctorSelect.appendChild(option);
        });
    }

    // Populate the report table
    function populateReportTable(data) {
        reportTable.innerHTML = ''; // Clear any existing rows
    
        filteredData = data; // Update filtered data for CSV export
    
        if (data.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="6" style="text-align: center;">No data found</td>`;
            reportTable.appendChild(row);
            return;
        }
    
        data.forEach(appointment => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${appointment.id}</td>
                <td>${appointment.patient_name}</td>
                <td>${appointment.doctor_name}</td>
                <td>${appointment.appointment_date}</td>
                <td>${appointment.statuses}</td>
                <td>${appointment.additional_message}</td>
            `;
            reportTable.appendChild(row);
        });
    }
    

    // Fetch appointments based on filters
    async function fetchAppointmentsReport() {
        const status = statusSelect.value;
        const doctor_id = doctorSelect.value; // Make sure this gets correct value
        const dateFrom = dateFromInput.value;
        const dateTo = dateToInput.value;
    
        const url = `/api/get-appointments-report?status=${status}&doctor_id=${doctor_id}&dateFrom=${dateFrom}&dateTo=${dateTo}`;
    
        console.log('Fetching with URL:', url); // Debug filter values
    
        try {
            const response = await fetch(url);
            const data = await response.json();
    
            if (response.ok) {
                console.log('Data received:', data); // Debug received data
                populateReportTable(data);
            } else {
                alert('Failed to fetch report: ' + data.error);
            }
        } catch (error) {
            console.error('Error fetching appointments report:', error);
        }
    }
    

    // Export data to CSV
    function exportToCSV(data) {
        if (!data || data.length === 0) {
            alert("No data available to export.");
            return;
        }
    
        const headers = ['Appointment ID', 'Patient Name', 'Doctor Name', 'Appointment Date', 'Status', 'Additional Message'];
        const rows = data.map(appointment => [
            appointment.id,
            appointment.patient_name,
            appointment.doctor_name,
            appointment.appointment_date,
            appointment.status,
            appointment.additional_message
        ]);
    
        const csvContent = [
            headers.join(','),  // Add headers
            ...rows.map(row => row.map(field => `"${field}"`).join(',')) // Escape fields
        ].join('\n');
    
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'appointments_report.csv';
        a.click();
    }
    

    // Event listener for filter button
    filterButton.addEventListener('click', () => {
        fetchAppointmentsReport();
    });

    // Event listener for export button
    exportButton.addEventListener('click', () => {
        exportToCSV(filteredData); // Use the fetched data for CSV export
    });

    // Initial load of doctors
    fetchDoctors();
});
