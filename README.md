# iot_traffic_visualization

'data_process.py' should run in the server to process PCAP files. The script is not set to run in a loop. If we want our code to continue running on the server, we need to make a simple change to the main function. When running data_process.py, make sure that the folders 'data_for_visualization' and 'data_finished_processed' are created.

'web_app.py' is the backend of the website program. The web program is set to run locally now.
