// currently selected device name
let currentDeviceSelection;
// Data request currently in progress
let ongoingFetchRequest = null;

// When the document is loaded, initialize the device list, start the data fetch schedule, and the device update schedule
document.addEventListener("DOMContentLoaded", function() {
    populateDevices();
    scheduleDataFetch();
    scheduleDeviceUpdate();
});


// Global variables for chart instances
let barChartInstance;
let avgThroughputAllDevicesChartInstance;
let peakThroughputAllDevicesChartInstance;
let avgPacketSizeAllDevicesChartInstance;
let packetCountAllDevicesChartInstance;
let destinationsCountAllDevicesChartInstance;
let throughputPerSecondDeviceChartInstance;
let avgThroughputDeviceChartInstance;
let peakThroughputDeviceChartInstance;
let avgPacketSizeDeviceChartInstance;
let packetCountDeviceChartInstance;
let uniqueDestinationsDeviceChartInstance;
let destinationTrafficDeviceChartInstance;
let packetSizeChartInstance;

// Get the list of devices and update the drop-down selector
function populateDevices() {
    // Request the backend to get the list of devices
    fetch('/devices')
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch devices");
            }
            return response.json();
        })
        .then(data => {
            // Get the selector element
            const selector = document.getElementById('deviceSelector');
            // Get the currently selected device
            const currentSelectedDevice = selector.value;
            // Clear the existing options of the selector
            selector.innerHTML = "";

            // Iterate through the list of devices, create an option for each device and add it to the selector
            data.devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device;
                option.innerText = device;
                selector.appendChild(option);
            });

            // If the currently selected device does not exist in the new device list, select the first device
            // Check if 'all_device' is in the device list
            if (data.devices.includes('all_device')) {
                selector.value = 'all_device';
                if (!currentSelectedDevice) { // If this is the first load, fetch the data directly
                    fetchAndPlotData();
                }
            }
            // Otherwise, the current selection is kept
            else if (data.devices.indexOf(currentSelectedDevice) === -1 && data.devices.length > 0) {
                selector.value = data.devices[0];
            } 
            else {
                selector.value = currentSelectedDevice;
            }
        })
        .catch(error => {
            // Print the error and display the error message
            console.error("Error fetching devices:", error);
            alert("Error fetching device list. Please try again later.");
        });
}

// Saves the current device selection state
function saveCurrentState() {
    currentDeviceSelection = document.getElementById('deviceSelector').value;
}

// Restores the previously saved device selection state
function restoreSavedState() {
    document.getElementById('deviceSelector').value = currentDeviceSelection;
}

// Destroy the existing chart instance
function destroyExistingCharts() {
    if (barChartInstance) barChartInstance.destroy();
    if (avgThroughputAllDevicesChartInstance) avgThroughputAllDevicesChartInstance.destroy();
    if (peakThroughputAllDevicesChartInstance) peakThroughputAllDevicesChartInstance.destroy();
    if (avgPacketSizeAllDevicesChartInstance) avgPacketSizeAllDevicesChartInstance.destroy();
    if (packetCountAllDevicesChartInstance) packetCountAllDevicesChartInstance.destroy();
    if (destinationsCountAllDevicesChartInstance) destinationsCountAllDevicesChartInstance.destroy();
    if (throughputPerSecondDeviceChartInstance) throughputPerSecondDeviceChartInstance.destroy();
    if (avgThroughputDeviceChartInstance) avgThroughputDeviceChartInstance.destroy();
    if (peakThroughputDeviceChartInstance) peakThroughputDeviceChartInstance.destroy();
    if (avgPacketSizeDeviceChartInstance) avgPacketSizeDeviceChartInstance.destroy();
    if (packetCountDeviceChartInstance) packetCountDeviceChartInstance.destroy();
    if (uniqueDestinationsDeviceChartInstance) uniqueDestinationsDeviceChartInstance.destroy();
    if (destinationTrafficDeviceChartInstance) destinationTrafficDeviceChartInstance.destroy();
    if (packetSizeChartInstance) packetSizeChartInstance.destroy();
}

// Gets the data of the selected device and plots it
function fetchAndPlotData() {
    // If there is a request in progress, it is interrupted
    if (ongoingFetchRequest) {
        ongoingFetchRequest.abort();
    }

    // Destroy existing charts
    destroyExistingCharts();
    // Saves the current device selection state
    saveCurrentState();

    // Gets the name of the currently selected device
    const deviceName = document.getElementById('deviceSelector').value;

    // Create an instance of AbortController so that you can abort requests
    const controller = new AbortController();
    ongoingFetchRequest = controller;

    // Request the backend to fetch data for the selected device
    fetch('/data', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ device_name: deviceName }),
        signal: controller.signal
    })    
    .then(response => {
        if (!response.ok) {
            throw new Error("Failed to fetch data");
        }
        return response.json();
    })
    .then(data => { 
        console.log(data); 
        return data; 
    })
    .then(data => {
        // If the data is valid, the graph is plotted, otherwise the message is displayed
        let hasMetrics = data.all_device_metrics && Object.keys(data.all_device_metrics).length;
        let hasThroughput = data.throughput_per_device && Object.keys(data.throughput_per_device).length;
        let hasMetricsPerDevice = data.metrics_per_device && Object.keys(data.metrics_per_device).length;
        let hasTraffic = data.traffic_per_device && Object.keys(data.traffic_per_device).length;

        if (hasMetrics || hasThroughput || hasMetricsPerDevice || hasTraffic) {
            plotData(data);
        } else {
            displayMessage("No data available for the selected device.");
        } 
    })
    .catch(error => {
        // Handle interrupt errors and other errors
        if (error.name === 'AbortError') {
            console.log("Fetch aborted");
        } else {
            console.error("Error fetching data:", error);
            displayError("Error fetching data. Please try again later.");
        }
    })
    .finally(() => {
        // Restores the previously saved device selection state and reschedules data acquisition
        restoreSavedState();
        scheduleDataFetch();
    });
}



function formatTime_sec(timeStr) {
    return timeStr.replace(/^\d{4}-/, '').replace(/\.\d+$/, '');
}

function formatTime_min(timeStr) {
    // We start by removing the year part at the beginning and the millisecond part at the end
    let partial = timeStr.replace(/^\d{4}-/, '').replace(/\.\d+$/, '');

    // Delete the seconds section
    partial = partial.replace(/:\d{2}$/, '');

    return partial;
}




// The specific logic of drawing the chart
function plotData(data) {

    // Destroy existing charts
    destroyExistingCharts();

    // When selecting "all_device"
    if (data.all_device_metrics) {

        document.getElementById('allDeviceData').style.display = 'block';

        const formattedTime = data.all_device_metrics.time.map(formatTime_min);
        showElement('avgThroughputAllDevicesChart');
        showElement('peakThroughputAllDevicesChart');
        showElement('avgPacketSizeAllDevicesChart');
        showElement('packetCountAllDevicesChart');
        showElement('destinationsCountAllDevicesChart');
        avgThroughputAllDevicesChartInstance = plotLineChart('avgThroughputAllDevicesChart', formattedTime, data.all_device_metrics['avg_throughput_all_devices(bps)'], 'avg throughput (bps)', 'Average Throughput of All Devices per Min');
        peakThroughputAllDevicesChartInstance = plotLineChart('peakThroughputAllDevicesChart', formattedTime, data.all_device_metrics['peak_throughput_all_devices(bps)'], 'peak throughput (bps)', 'Peak Throughput of All Devices per Min');
        avgPacketSizeAllDevicesChartInstance = plotLineChart('avgPacketSizeAllDevicesChart', formattedTime, data.all_device_metrics['avg_packet_size_all_devices(bytes)'], 'avg ip packet size (bytes)', 'Average IP Packet Size of All Devices per Min');
        packetCountAllDevicesChartInstance = plotLineChart('packetCountAllDevicesChart', formattedTime, data.all_device_metrics['packet_count_all_devices'], 'ip packet count', 'Number of IP Packets of All Devices per Min');
        destinationsCountAllDevicesChartInstance = plotLineChart('destinationsCountAllDevicesChart', formattedTime, data.all_device_metrics['destinations_count_all_devices'], 'destination ip count','Average Number of Unique Destinations of All Devices per Min');
    }else{
        notshowElement('avgThroughputAllDevicesChart');
        notshowElement('peakThroughputAllDevicesChart');
        notshowElement('avgPacketSizeAllDevicesChart');
        notshowElement('packetCountAllDevicesChart');
        notshowElement('destinationsCountAllDevicesChart');

        document.getElementById('allDeviceData').style.display = 'none';
    }

    if (data.all_device_traffic) {
        showElement('allDeviceTrafficChart');
        barChartInstance = plotBarChart('allDeviceTrafficChart', data.all_device_traffic.device_name, data.all_device_traffic['total_throughput(bits)'], 'traffic volume (bits)', 'Traffic Volume per Device in last 2 hours');
    }else{
        notshowElement('allDeviceTrafficChart');
    }

    

    // When selecting a specific device
    if (data.throughput_per_device) {
        document.getElementById('specificDeviceData').style.display = 'block';

        const formattedTime = data.throughput_per_device.time.map(formatTime_sec);
        showElement('throughputPerSecondDeviceChart');
        throughputPerSecondDeviceChartInstance = plotLineChart('throughputPerSecondDeviceChart', formattedTime, data.throughput_per_device['throughput_per_sec(bps)'], 'throughput (bps)', 'Throughput per Second (bps)');
    }else{
        notshowElement('throughputPerSecondDeviceChart');

        document.getElementById('specificDeviceData').style.display = 'none';
    }


    if (data.metrics_per_device) {
        const formattedTime = data.metrics_per_device.time.map(formatTime_min);
        showElement('avgThroughputDeviceChart');
        showElement('peakThroughputDeviceChart');
        showElement('avgPacketSizeDeviceChart');
        showElement('packetCountDeviceChart');
        showElement('uniqueDestinationsDeviceChart');
        avgThroughputDeviceChartInstance = plotLineChart('avgThroughputDeviceChart', formattedTime, data.metrics_per_device['avg_throughput_per_min(bps)'], 'avg throughput (bps)', 'Average Throughput per Min (bps)');
        peakThroughputDeviceChartInstance = plotLineChart('peakThroughputDeviceChart', formattedTime, data.metrics_per_device['peak_throughput_per_min(bps)'], 'peak throughput (bps)', 'Peak Throughput per Min');
        avgPacketSizeDeviceChartInstance = plotLineChart('avgPacketSizeDeviceChart', formattedTime, data.metrics_per_device['avg_packet_size_per_min(bytes)'], 'avg ip packet size (bytes)','Average IP Packet Size per Min');
        packetCountDeviceChartInstance = plotLineChart('packetCountDeviceChart', formattedTime, data.metrics_per_device['packet_count_per_min'], 'ip packet count', 'Number of IP Packets per Min');
        uniqueDestinationsDeviceChartInstance = plotLineChart('uniqueDestinationsDeviceChart', formattedTime, data.metrics_per_device['unique_destinations_count_per_min'], 'destination ip count', 'Number of Unique Destinations per Min');
    }else{
        notshowElement('avgThroughputDeviceChart');
        notshowElement('peakThroughputDeviceChart');
        notshowElement('avgPacketSizeDeviceChart');
        notshowElement('packetCountDeviceChart');
        notshowElement('uniqueDestinationsDeviceChart');
    }

    if (data.traffic_per_device) {
        showElement('destinationTrafficDeviceChart');
        destinationTrafficDeviceChartInstance = plotBarChart('destinationTrafficDeviceChart', data.traffic_per_device.destination_ip, data.traffic_per_device['throughput_per_ip(bits)'], 'traffic volume (bits)', 'Traffic Volume to per Destination IP in last 2 hours');
    }else{
        notshowElement('destinationTrafficDeviceChart');
    }

    if (data.packet_size_record) {
        showElement('packetSizeChart');
        packetSizeChartInstance = plotBarChart('packetSizeChart', data.packet_size_record['packet_size(bytes)'], data.packet_size_record['count'], 'count', 'Packet Size (bytes) Distribution in last 2 hours');
    }else{
        notshowElement('packetSizeChart');
    }
}


//Draw a line chart
function plotLineChart(ctxId, dataLabels, dataValues, labelName, title) {

    console.log("Labels:", dataLabels);  
    console.log("Values:", dataValues);  

    const ctx = document.getElementById(ctxId).getContext('2d');
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: dataLabels,
            datasets: [{
                label: labelName,
                data: dataValues,
                borderColor: 'blue',
                fill: false
            }]
        },
        options:{
            plugins: {
                title: {
                    display: true,
                    text: title  // Setting the image name
                }
            }
        }
    });
}

//Draw a bar chart
function plotBarChart(ctxId, dataLabels, dataValues, labelName, title) {
    const ctx = document.getElementById(ctxId).getContext('2d');
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: dataLabels,
            datasets: [{
                label: labelName,
                data: dataValues,
                backgroundColor: 'blue'
            }]
        },
        options: {
            plugins: {
                title: {
                    display: true,
                    text: title  // Setting the image name
                },
                zoom: {
                    pan: {
                        enabled: true, // Enable drag
                        mode: 'x', // can choose 'x', 'y', 'xy'
                    },
                    zoom: {
                        wheel: {
                            enabled: true, // Enable mouse wheel zoom
                        },
                        // drag: {
                        //     enabled: true, // Enable mouse drag area resizing
                        // },
                        pinch: {
                            enabled: true, // Enable two-finger zoom on touch screen devices
                        },
                        mode: 'x', // can choose 'x', 'y', 'xy'
                    },
                },
            },
        }
    });
}


function showElement(elementId) {
    document.getElementById(elementId).style.display = "block";
}


function notshowElement(elementId) {
    document.getElementById(elementId).style.display = "none";
}



// Displaying error messages
function displayError(message) {
    alert(message);
    console.log(message);
}

function displayMessage(message) {
    alert(message);
    console.log(message);

}



// Schedule data acquisition, which is executed every 1 minutes
function scheduleDataFetch() {
    setTimeout(() => {
        fetchAndPlotData();
    }, 1 * 60 * 1000);
}

// Schedule device updates, which are executed every 1 minute
function scheduleDeviceUpdate() {
    setTimeout(() => {
        populateDevices();
        scheduleDeviceUpdate();
    }, 1 * 60 * 1000);
}
