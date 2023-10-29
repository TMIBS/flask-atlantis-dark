// Use fetch API to get data from the Flask route
fetch('/processassetsjson')
    .then(response => {
        // Check if response is OK (status 200)
        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }
        return response.json(); // Parse JSON data
    })
    .then(data => {
        // Use the data
        displayData(data);
    })
    .catch(error => {
        // Handle errors
        console.error('There has been a problem with your fetch operation:', error);
    });


// Function to display data on the HTML page
function displayData(dataArray) {
    const tableBody = document.getElementById('data-table').getElementsByTagName('tbody')[0];
    
    dataArray.forEach(data => {
        const newRow = tableBody.insertRow();
        
        newRow.innerHTML = `
            <td>${data.address}</td>
            <td>${data.name}</td>
            <td>${data.operating_system}</td>
            <td>${data.malware}</td>
            <td>${data.exploits}</td>
            <td>${data.vulnerabilities}</td>
            <td>${data.risk_score}</td>
        `;
    });
}
