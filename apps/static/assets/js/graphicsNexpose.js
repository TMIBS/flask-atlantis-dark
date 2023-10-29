"use strict";
function getGraphDataRiskxVulnerabilities() {
    fetch('/processassetsjson')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            // Process the data to get the necessary values for your graph
            const graphData = data.map(asset => ({
                x: asset.risk_score,  // Risk Score
                y: asset.vulnerabilities,  // Number of Vulnerabilities
                name: asset.name,
                address: asset.address
            }));

            new Chart(lineChartRiskVulnerarbilites, {
                type: 'scatter',
                data: {
                    datasets: [{
                        label: 'Assets',
                        data: graphData,
                        pointBackgroundColor: 'blue'
                    }]
                },
                options: {
                    plugins: {
                        tooltip: {
                            enabled: true,
                            callbacks: {
                                title: function(tooltipItems) {
                                    if (tooltipItems.length > 0) {
                                        const tooltipItem = tooltipItems[0];
                                        const point = tooltipItem.raw;
                                        return [
                                            `Asset Name: ${point.name}`,
                                            `IP-address: ${point.address}`,
                                            `Risk Score: ${point.x}`,
                                            `Vulnerabilities: ${point.y}`
                                        ];
                                    }
                                    return '';  
                                },
                                label: function() {
                                    return '';
                                }
                            }
                        },
                        legend: {
                            display: false  // This line hides the legend
                        }                            
                    },
                    scales: {
                        y: {
                            type: 'linear',
                            position: 'bottom',
                            title: {
                                display: true,
                                text: 'Vulnerabilities',
                                rotation: 0
                            }
                        },
                        x: {
                            type: 'linear',
                            title: {
                                display: true,
                                text: 'Risk Score'
                            }
                        }
                    }
                    
                }
            });                
        })
        .catch(error => {
            console.error('There has been a problem with your fetch operation:', error);
        });
}

function getGraphDataRiskxInstances() {
    fetch('/processvulnerabilitiesjson')  // Updated URL
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            // Process the data to get the necessary values for your graph
            const graphData2 = data.map(vulnerability => ({
                x: vulnerability.Risk,  // Risk Score
                y: vulnerability.Instances,  // Number of Instances
                title: vulnerability.Title  // Title of the vulnerability
            }));

            new Chart(lineChartRiskInstances, {
                type: 'scatter',
                data: {
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: graphData2,
                        pointBackgroundColor: 'blue'
                    }]
                },
                options: {
                    plugins: {
                        tooltip: {
                            enabled: true,
                            callbacks: {
                                title: function(tooltipItems) {
                                    if (tooltipItems.length > 0) {
                                        const tooltipItem = tooltipItems[0];
                                        const point = tooltipItem.raw;
                                        return [
                                            `Title: ${point.title}`,
                                            `Risk Score: ${point.x}`,
                                            `Instances: ${point.y}`
                                        ];
                                    }
                                    return '';  
                                },
                                label: function() {
                                    return '';
                                }
                            }
                        },
                        legend: {
                            display: false  // This line hides the legend
                        }                            
                    },
                    scales: {
                        y: {
                            type: 'linear',
                            position: 'bottom',
                            title: {
                                display: true,
                                text: 'Instances',
                                rotation: 0
                            }
                        },
                        x: {
                            type: 'linear',
                            title: {
                                display: true,
                                text: 'Risk Score'
                            }
                        }
                    }
                    
                }
            });                
        })
        .catch(error => {
            console.error('There has been a problem with your fetch operation:', error);
        });
}