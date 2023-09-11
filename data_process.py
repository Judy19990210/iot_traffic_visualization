import os
import pandas as pd
from datetime import datetime
from scapy.all import *
from scapy.all import IP, Ether, rdpcap
from scapy.layers.inet import TCP
from collections import defaultdict
import shutil
import pytz
from io import StringIO


BASE_FOLDER_PATH = "/mnt/disk1/traffic"
BY_MAC_FOLDER_PATH= os.path.join(BASE_FOLDER_PATH, "by-mac")

YUDI_FOLDER_PATH = "/home/yudi/iot_traffic_visualization/backend"
DATA_FOR_VIZ_FOLDER_PATH = os.path.join(YUDI_FOLDER_PATH, "data_for_visualization")
DATA_FINISHED_PRO_FOLDER_PATH = os.path.join(YUDI_FOLDER_PATH, "data_finished_processed")

DISPLAY_PERIOD = 2  # hours

#------------------------------------------------------------------------------
def get_packet_count(pcap_file):
    """Get total packet count of pcap using tshark."""
    try:
        cmd = ['tshark', '-r', pcap_file, '-n', '-q', '-z', 'io,phs']
        output = subprocess.check_output(cmd).decode('utf-8')
        for line in output.splitlines():
            if line.strip().startswith('eth'):
                return int(line.split("frames:")[1].split()[0])
    except subprocess.CalledProcessError as e:
        # Try to parse the number of frames from the error output
        for line in e.output.decode('utf-8').splitlines():
            if line.strip().startswith('eth'):
                return int(line.split("frames:")[1].split()[0])
        print(f"Error determining packet count: {e.output}")
        return 0



def tshark_extract(pcap_file, hours):
    """Extract specific hours of data from pcap using tshark and return temp CSV file path."""
    try:
        print("Starting tshark extraction...")

        total_packets = get_packet_count(pcap_file)
        if total_packets is None or total_packets == 0:
            print("Error determining total packet count.")
            return None
        
        # Converts CURRENT_TIME from the local time zone to UTC
        # Define the end time as the last complete minute closest to CURRENT_TIME
        end_time = CURRENT_TIME.replace(second=0, microsecond=0)
        local_tz = pytz.timezone('Europe/London') # London time zone
        localized_dt = local_tz.localize(end_time)
        utc_dt = localized_dt.astimezone(pytz.utc)


        # Invoke tshark
        end_time = utc_dt
        start_time = end_time - timedelta( hours = hours )

        # Start by processing all packets
        packet_limit = total_packets
        retries = 0  # Added a retry counter for better control

        while packet_limit > 0 and retries < 10:
            cmd = [
                'tshark', 
                '-r', pcap_file, 
                '-T', 'fields',
                '-E', 'header=y',  # include headers in CSV
                '-E', 'separator=,',  # specify comma as separator
                '-e', 'frame.time_epoch',  # timestamp
                '-e', 'ip.len',  # IP packet length
                '-e', 'ip.dst',  # destination IP address
                '-Y', f'ip && frame.time >= "{start_time}" && frame.time <= "{end_time}"',  # IP filter and time filter combined
                '-c', str(packet_limit)
            ]

            # Run tshark and get the output
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()

            # Check for truncated packet messages in the error output
            if "packet size limited during capture" in error.decode('ISO-8859-1'):
                print("Warning: Detected truncated packets. Reducing packet limit for retry.")
                packet_limit -= 1
                retries += 1
                continue
            
            if process.returncode == 0:
                print("Tshark extraction completed successfully.")
                return output.decode('ISO-8859-1').strip().split('\n')
            else:
                # If tshark returns an error, reduce the number of packets and retry
                packet_limit -= 1
                retries += 1
        
        # If the retry limit is reached
        print("Failed to extract data even after reducing packet limit.")
        return None
    
    except Exception as e:
        print(f"Exception occurred: {e}")
        return None

    


def extract_data_from_pcap(pcap_file, hours = DISPLAY_PERIOD):
    try:
        print("Extracting required data from pcap file...")

        # tshark is used to extract the data for the specified number of hours and save it as CSV
        extracted_data = tshark_extract(pcap_file, hours)

        # for line in extracted_data:
        #      print(line)

        if not extracted_data:
            print(f"Error extracting data from {pcap_file} using tshark.")
            return None
        


        # For rows with the wrong number of fields, filter them and print out the data in question
        cleaned_data = []
        for index, line in enumerate(extracted_data, start=1):  # Add start=1 to start counting at 1
            fields = line.strip().split(',')

            if len(fields) == 3:
                cleaned_data.append(line)
            # if len(fields) != 3:  # Expecting only 3 fields based on your description
            #     print(f"Error in line {index}: Unexpected number of fields. Data: {line}")
            # else:
            #     cleaned_data.append(line)

        if not cleaned_data:
            print(f"Error: All data from {pcap_file} were invalid after cleaning.")
            return None

        sio = StringIO("\n".join(cleaned_data))

        df = pd.read_csv(sio, encoding='ISO-8859-1', header=0, sep=',')
        

        # A datetime object that converts a timestamp to UTC
        df['frame.time_epoch'] = pd.to_datetime(df['frame.time_epoch'], unit='s', utc=True)

        # Convert time from UTC to local time (e.g. 'Europe/London')
        df['frame.time_epoch'] = df['frame.time_epoch'].dt.tz_convert('Europe/London')

        # Compute throughput
        df['throughput'] = df['ip.len'] * 8 # bits
        
        # Packet count
        df['packet_count'] = 1
        
        # Renaming columns
        df.rename(columns={
            'frame.time_epoch': 'time',
            'ip.len': 'packet_size', # bytes
            'ip.dst': 'destination'
        }, inplace=True)

        # Select and rearrange the desired columns
        metrics = df[['time', 'throughput', 'packet_count', 'packet_size', 'destination']]
        metrics.set_index('time', inplace=True)

        print("Successfully extracted required data from pcap file.")
        # print(metrics)
        return metrics

    except Exception as e:
        print(f"Error: Failed to process file {pcap_file}. Reason: {e}")
        return None
    
#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
def aggregate_all_metrics_for_device(device_folder_path):
    """Scan all pcap files in the folder of a device and aggregate metrics."""
    print(f"Starting aggregation for device folder: {device_folder_path}")
    all_metrics = []
    pcap_files_to_process = get_files_to_process(device_folder_path)

    if not pcap_files_to_process:
        print(f"No pcap files found for processing in folder: {device_folder_path}")

    for pcap_file in pcap_files_to_process:
        print(f"Aggregating metrics for file: {pcap_file}")
        metrics = load_metrics_from_pcap(pcap_file)
        if metrics is not None:
            all_metrics.append(metrics)

    if all_metrics:
        print(f"Successfully aggregated metrics for device folder: {device_folder_path}")
        # print(all_metrics)
        return pd.concat(all_metrics)
    else:
        print(f"No metrics found for device folder: {device_folder_path}")
        return pd.DataFrame()  # Returns an empty DataFrame



def load_metrics_from_pcap(pcap_file):
    """Load and compute metrics from the given pcap file."""
    try:
        print(f"Starting to calculate metrics: {pcap_file}")
        metrics = extract_data_from_pcap(pcap_file)
        if metrics is not None:
            print(f"Successfully loaded metrics from pcap file: {pcap_file}")
            return metrics
        else:
            return None
    except Exception as e:
        print(f"Error during processing file: {pcap_file}, error: {e}")
        return None



def get_files_to_process(directory_path):
    print(f"Getting files to process from directory: {directory_path}")
    pcap_files = []
    try:
        pcap_files = sorted([os.path.join(dp, f) for dp, dn, filenames in os.walk(directory_path) for f in filenames if f.endswith('.pcap')], reverse=True)
        print(f"Found {len(pcap_files)} pcap files in directory: {directory_path}")
    except Exception as e:
        print(f"Error processing directory: {directory_path}, error: {e}")
        return []
    
    if not pcap_files:
        print(f"No pcap files found in directory: {directory_path}")
        return []

    files_to_return = []
    try:
        # Filter out files for which get_file_time_from_name returns None
        valid_files = [(f, get_file_time_from_name(f)) for f in pcap_files]
        valid_files = [(f, t) for f, t in valid_files if t is not None and t <= CURRENT_TIME] # Ensure time is before CURRENT_TIME

        two_hours_ago = CURRENT_TIME - timedelta( hours = DISPLAY_PERIOD )
        files_within_2h = [f for f, t in valid_files if t > two_hours_ago]

        if files_within_2h:
            twenty_six_hours_ago = CURRENT_TIME - timedelta( hours = DISPLAY_PERIOD + 24 )
            first_file_beyond_2h = next((f for f, t in valid_files if twenty_six_hours_ago <= t <= two_hours_ago), None)
            if first_file_beyond_2h:
                files_within_2h.append(first_file_beyond_2h)
            files_to_return = files_within_2h
        else:
            twenty_six_hours_ago = CURRENT_TIME - timedelta( hours = DISPLAY_PERIOD + 24 )
            most_recent_file_within_26h = next((f for f, t in valid_files if twenty_six_hours_ago <= t <= two_hours_ago), None)
            if most_recent_file_within_26h:  # Check if a valid file was found
                files_to_return.append(most_recent_file_within_26h)
            print(f"Selected {len(files_to_return)} files for processing from directory: {directory_path}")
    except Exception as e:
        print(f"Error filtering pcap files from directory: {directory_path}, error: {e}")
    
    return files_to_return


def get_file_time_from_name(file_path):
    try:
        file_name = os.path.basename(file_path)  # Extracting filenames
        date_str, time_str = file_name.split('_')[:2]
        datetime_str = f"{date_str}_{time_str}"
        return datetime.strptime(datetime_str, "%Y-%m-%d_%H.%M.%S")
    except Exception as e:
        print(f"Error processing filename {file_name}. Reason: {e}. Skipping...")
        return None
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def save_metrics_to_csv(metrics_df, device_name, mac_address):
    """Resample and save aggregated metrics to CSV files."""
    
    # Creating a device folder
    output_folder = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, device_name)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Save the mac_address to the mac_address.txt file
    mac_address_file_path = os.path.join(output_folder, "mac_address.txt")
    with open(mac_address_file_path, 'w') as mac_file:
        mac_file.write(mac_address)
    
    # If the DataFrame is empty, an empty DataFrame is created
    if metrics_df.empty:
        return
    
    # Remove the timezone information for the metrics_df time
    if 'time' in metrics_df.columns:
        metrics_df['time'] = metrics_df['time'].dt.tz_localize(None)
    else:
        metrics_df.index = metrics_df.index.tz_localize(None)
    
    # Sort the data by time
    metrics_df = metrics_df.sort_index()

    # Define the end time as the last complete minute closest to CURRENT_TIME
    end_time = CURRENT_TIME.replace(second=0, microsecond=0)

    # The start time is defined as a regression of n hours from the end time
    start_time = end_time - pd.Timedelta( hours = DISPLAY_PERIOD )

    # Data taken from metrics_df in this period
    truncated_df = metrics_df.truncate(before=start_time, after=end_time)

    
    if truncated_df.empty:
        return


    # 1. bits per second over the last n hours
    throughput_per_second = truncated_df.resample('1S').sum()['throughput'].reset_index()
    throughput_per_second.columns = ['time', 'throughput_per_sec(bps)']

    throughput_per_second = throughput_per_second.fillna(0)

    



    # 2. Average throughput per minute (bps), peak traffic (bps), average packet size (bytes), number of packets, number of destinations over the last n hours
    metrics_per_min = truncated_df.resample('1T').agg({
        'packet_size': 'mean',
        'packet_count': 'sum',
        'destination': lambda x: x.nunique()
    }).reset_index()

    # Calculate the average throughput and peak throughput per minute from the throughput per second calculated above
    throughput_avg_per_min = throughput_per_second.resample('1T', on='time').mean()['throughput_per_sec(bps)'] # bps
    throughput_peak_per_min = throughput_per_second.resample('1T', on='time').max()['throughput_per_sec(bps)'] # bps

    # Merge the new metric into metrics_per_min
    metrics_per_min['avg_throughput_per_min(bps)'] = throughput_avg_per_min.values
    metrics_per_min['peak_throughput_per_min(bps)'] = throughput_peak_per_min.values

    metrics_per_min = metrics_per_min.rename(columns={
    'packet_size': 'avg_packet_size_per_min(bytes)',
    'packet_count': 'packet_count_per_min',
    'destination': 'unique_destinations_count_per_min'
    })

    column_order = ['time', 'avg_throughput_per_min(bps)', 'peak_throughput_per_min(bps)','avg_packet_size_per_min(bytes)', 'packet_count_per_min', 'unique_destinations_count_per_min']
    metrics_per_min = metrics_per_min[column_order]

    metrics_per_min = metrics_per_min.fillna(0) # The missing value is set to 0
    metrics_per_min = metrics_per_min.round(3) # All floating-point numbers keep three decimal places

    


    # 4. Amount of data (bits) for each ip destination in the last n hours
    dest_traffic_per_hour = truncated_df.groupby(by='destination').agg({
        'throughput': 'sum'
    }).reset_index().sort_values(by='throughput', ascending=False)

    dest_traffic_per_hour.columns = ['destination_ip', 'throughput_per_ip(bits)']


    # 5. Log the size (bytes) of each packet for the past n hours
    packet_sizes_counts = truncated_df['packet_size'].value_counts().reset_index()

    packet_sizes_counts.columns = ['packet_size(bytes)', 'count']

    # Sort by packet size
    packet_sizes_counts = packet_sizes_counts.sort_values(by='packet_size(bytes)').reset_index(drop=True)

    # Put the data into CSV
    throughput_per_second.to_csv(os.path.join(output_folder, f'throughput_per_second_{device_name}.csv'), index=False, date_format='%Y-%m-%d %H:%M:%S.%f')
    metrics_per_min.to_csv(os.path.join(output_folder, f'metrics_per_min_{device_name}.csv'), index=False, date_format='%Y-%m-%d %H:%M:%S.%f')
    dest_traffic_per_hour.to_csv(os.path.join(output_folder, f'destination_traffic_{device_name}.csv'), index=False)
    packet_sizes_counts.to_csv(os.path.join(output_folder, f'packet_sizes_count_{device_name}.csv'), index=False)
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def process_all_devices_data():
    all_devices_data_list = []
    all_throughput_data_list = []

    # 1. Read the CSV file for each device
    for device_name in os.listdir(DATA_FOR_VIZ_FOLDER_PATH):
        # If it's the all_device folder, skip it
        if device_name == "all_device":
            continue

        device_folder = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, device_name)
        metrics_per_min_path = os.path.join(device_folder, f'metrics_per_min_{device_name}.csv')
        throughput_per_second_path = os.path.join(device_folder, f'throughput_per_second_{device_name}.csv')

        # Check if CSV file exists in the device folder
        if not os.path.exists(metrics_per_min_path) or not os.path.exists(throughput_per_second_path):
            # print(f"Required CSVs not found for device {device_name}. Skipping...")
            continue

        try:
            # metrics_df = pd.read_csv(metrics_per_min_path, parse_dates=['time'])
            
            # When reading the per-device CSV file, the peak_throughput column is simply discarded
            metrics_df = pd.read_csv(metrics_per_min_path, parse_dates=['time']).drop(columns=['peak_throughput_per_min(bps)'], errors='ignore')

            throughput_df = pd.read_csv(throughput_per_second_path, parse_dates=['time'])

            if metrics_df.empty or throughput_df.empty:
                print(f"CSVs for device {device_name} are empty. Skipping...")
                continue

            # Add throughput data to the list
            all_throughput_data_list.append(throughput_df)

            metrics_df.set_index('time', inplace=True)
            all_devices_data_list.append((device_name, metrics_df))

        except Exception as e:
            print(f"Error reading CSV for device {device_name}: {e}")
            continue


    # If there's no device data, just create the all_device folder without producing any CSVs
    if not all_devices_data_list:
        print("No device data found.")
        all_device_folder = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, "all_device")
        if not os.path.exists(all_device_folder):
            os.makedirs(all_device_folder)
        return
    
    # Save aggregated data
    all_device_folder = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, "all_device")
    if not os.path.exists(all_device_folder):
        os.makedirs(all_device_folder)
        


    # 2. Aggregate or accumulate data to generate summary metrics
    try:
        # Combine all throughput data
        all_throughput_data = pd.concat(all_throughput_data_list)
        all_throughput_data = all_throughput_data.sort_values(by='time')
        all_throughput_data.set_index('time', inplace=True)
        
        peak_throughput_total = all_throughput_data.resample('1T').max()['throughput_per_sec(bps)']
        peak_throughput_total.name = 'peak_throughput_all_devices(bps)'

        aggregated_data = pd.concat([df.reset_index() for _, df in all_devices_data_list])
        aggregated_data.sort_values(by='time', inplace=True)
        
        # print("step 1")
        # print(aggregated_data.head())
        # print(aggregated_data.info())

        # Aggregation functions for each column
        agg_functions = {
            'avg_throughput_per_min(bps)': 'mean',
            'avg_packet_size_per_min(bytes)': 'mean',
            'packet_count_per_min': 'sum',
            'unique_destinations_count_per_min': 'mean'
        }

        aggregated_data = aggregated_data.groupby('time').agg(agg_functions)
        
        # Make sure 'time' is a column, not an index
        if 'time' not in aggregated_data.columns:
            aggregated_data.reset_index(inplace=True)
        
        # Merge peak_throughput_total into aggregated_data
        aggregated_data = pd.merge(aggregated_data, peak_throughput_total.reset_index(), on='time', how='left')
        

        # Rename columns to match the expected output
        aggregated_data.rename(columns={
            'avg_throughput_per_min(bps)': 'avg_throughput_all_devices(bps)',
            'avg_packet_size_per_min(bytes)': 'avg_packet_size_all_devices(bytes)',
            'packet_count_per_min': 'packet_count_all_devices',
            'unique_destinations_count_per_min': 'destinations_count_all_devices'
        }, inplace=True)

        aggregated_data = aggregated_data.fillna(0)

        desired_order = [
            'time', 
            'avg_throughput_all_devices(bps)', 
            'peak_throughput_all_devices(bps)',
            'avg_packet_size_all_devices(bytes)', 
            'packet_count_all_devices', 
            'destinations_count_all_devices'
        ]
        aggregated_data = aggregated_data[desired_order] # Rearranging the sequence

        
        aggregated_data = aggregated_data.round(3) # All floating-point numbers keep three decimal places

        aggregated_data.to_csv(os.path.join(all_device_folder, 'all_device_aggregated_metrics_per_min.csv'), index=False)

    except Exception as e:
        print(f"Error during data aggregation: {e}")
    

    # 3. The traffic (bits) of each device in t minutes
    try:
        
        end_time = CURRENT_TIME.replace(second=0, microsecond=0)
      
        start_time = end_time - pd.Timedelta( hours = DISPLAY_PERIOD )

        device_traffic_list = []

        for device_name, device_df in all_devices_data_list:  # Iterate over the tuple
            
            truncated_df = device_df.truncate(before=start_time, after=end_time)
            
            total_throughput = round((truncated_df['avg_throughput_per_min(bps)'] * 60).sum()) # bits
            device_traffic_list.append((device_name, total_throughput))

        # Sort from largest to smallest
        sorted_device_traffic = sorted(device_traffic_list, key=lambda x: x[1], reverse=True)

        sorted_traffic_df = pd.DataFrame(sorted_device_traffic, columns=['device_name', 'total_throughput'])
        sorted_traffic_df.rename(columns={'total_throughput': 'total_throughput(bits)'}, inplace=True)  # rename columns
        sorted_traffic_df.to_csv(os.path.join(all_device_folder, 'all_device_sorted_traffic_last_n_minutes.csv'), index=False)
    except Exception as e:
        print(f"Error during device traffic calculation: {e}")
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def copy_data_for_visualization_to_finished_process():
    """ Copy everything from data_for_visualization into the data_finished_process folder."""
    
    # First, clear the data_finished_process folder
    for item_name in os.listdir(DATA_FINISHED_PRO_FOLDER_PATH):
        item_path = os.path.join(DATA_FINISHED_PRO_FOLDER_PATH, item_name)
        
        try:
            # Delete based on whether it is a file or folder
            if os.path.isfile(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)
        except Exception as e:
            print(f"Error deleting {item_name}: {e}")

    # Then copy the data from data_for_visualization
    for item_name in os.listdir(DATA_FOR_VIZ_FOLDER_PATH):
        source_path = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, item_name)
        destination_path = os.path.join(DATA_FINISHED_PRO_FOLDER_PATH, item_name)
        
        try:
            if os.path.isfile(source_path):
                shutil.copy2(source_path, destination_path)
            elif os.path.isdir(source_path):
                shutil.copytree(source_path, destination_path)
        except Exception as e:
            print(f"Error copying {item_name}: {e}")

    print("All data successfully copied to data_finished_process.")

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
def main():

    global CURRENT_TIME  
    CURRENT_TIME = datetime.now()  # Update the time each time main() is run
    
    # string_time = "2023-08-23 00:30:07.901887"
    # CURRENT_TIME = datetime.strptime(string_time, '%Y-%m-%d %H:%M:%S.%f')
    
    print(f"current time = {CURRENT_TIME}")
    

    # 1. Clear everything inside the DATA_FOR_VIZ_FOLDER_PATH
    for root, dirs, files in os.walk(DATA_FOR_VIZ_FOLDER_PATH, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))


    print("Starting to scan files...")

    processing_times = {}  # It is used to record the processing time of each device
    current_devices = []  # Used to keep track of devices that have been encountered in the current run


    # 2. Iterate over each device folder in the by-mac folder
    for mac_address in os.listdir(BY_MAC_FOLDER_PATH):
        device_folder_path = os.path.join(BY_MAC_FOLDER_PATH, mac_address)

        # Read the device name from the name.txt file
        name_file_path = os.path.join(device_folder_path, "name.txt")
        if os.path.exists(name_file_path):
            with open(name_file_path, 'r') as name_file:
                device_name = name_file.read().strip()
                if not device_name:  # Check if the device name is empty
                    continue
        else:
            continue  # If there is no name.txt file, skip this folder

        # If the device name contains "phone" or has been encountered in this run, skip it
        if "phone" in device_name.lower() or device_name in current_devices:
            continue

        start_time = time.time()

        print(f"Processing device with MAC: {mac_address} and Name: {device_name}")
        try:
            all_metrics_df = aggregate_all_metrics_for_device(device_folder_path)
            save_metrics_to_csv(all_metrics_df, device_name, mac_address)
            current_devices.append(device_name)

            end_time = time.time()
            processing_time = end_time - start_time
            processing_times[device_name] = processing_time

        except Exception as e:
            print(f"Error processing device with MAC: {mac_address} and Name: {device_name}: {e}")

    
    # After traversing the folders of all devices, the total data of all devices is calculated
    try:
        print("Starting to calculating all devices data")
        start_time = time.time()

        process_all_devices_data()

        end_time = time.time()
        processing_time = end_time - start_time
        processing_times["ALL_DEVICES_DATA"] = processing_time

    except Exception as e:
        print(f"Error during process_all_devices_data: {e}")

    # Generate and print a table of processing times
    df_processing_times = pd.DataFrame(list(processing_times.items()), columns=['Device Name', 'Processing Time (seconds)'])
    

    # Save df_processing_times to a CSV file
    output_folder1 = os.path.join(DATA_FOR_VIZ_FOLDER_PATH, "all_device")
    if not os.path.exists(output_folder1):
        os.makedirs(output_folder1)

    output_path1 = os.path.join(output_folder1, "all_device_processing_times.csv")
    df_processing_times.to_csv(output_path1, index=False)


    # Copy everything from data_for_visualization into the data_finished_process folder
    copy_data_for_visualization_to_finished_process()


    global FINISHED_TIME
    FINISHED_TIME = datetime.now() 
    run_period = FINISHED_TIME - CURRENT_TIME

    print("Finished running the program.")
    print(f"Program Started time is {CURRENT_TIME}. Finished time is {FINISHED_TIME}. The runtime of the program: {run_period}")


if __name__ == "__main__":
    main()
