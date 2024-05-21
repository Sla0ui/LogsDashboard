from flask import Flask, render_template
from services import ServiceManager
import mysql.connector
import matplotlib.pyplot as plt
import io
import base64
import ipaddress
import matplotlib.patches as mpatches
from map import plot_failed_connection_attempts_with_country

app = Flask(__name__)
plt.switch_backend('agg')

def get_db_connection():
    return mysql.connector.connect(
        user='root',
        passwd='Slaoui2003',
        host='localhost',
        port=3306,
        database='logs_db'
    )

def create_plot(figure):
    img = io.BytesIO()
    figure.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    plt.close(figure)
    return plot_url

@app.route('/')
def index():
    db_connection = get_db_connection()
    service = ServiceManager(db_connection)
    
    oar_data = service.get_OAR()
    
    uvph_data = service.get_UVPH()
    plot_uvph = plot_unique_visitors_per_hour(uvph_data)
    
    rf_data = service.get_RF()
    plot_rf = plot_requested_files(rf_data)
    
    sr_data = service.get_RS()
    plot_sr = plot_static_requests(sr_data)
    
    nfu_data = service.get_NFU()
    plot_nfu = plot_not_found_urls(nfu_data)
    
    vhi_data = service.get_VHI()
    plot_vhi = plot_visitors_hostname_ip(vhi_data)
    
    fcai_data = service.get_FCAI()
    plot_fcai = plot_failed_connection_attempts(fcai_data)
    
    httpsc_data = service.get_HTTPSC()
    plot_httpsc = plot_http_status_codes(httpsc_data)
    
    os_data = service.get_OS()
    plot_os = plot_operating_systems(os_data)
    
    br_data = service.get_BR()
    plot_br = plot_browsers(br_data)
    
    return render_template('index.html', 
                            formatted_data_oar=oar_data,
                            plot_uvph=plot_uvph,
                            plot_rf=plot_rf,
                            plot_sr=plot_sr,
                            plot_nfu=plot_nfu,
                            plot_vhi=plot_vhi,
                            plot_fcai=plot_fcai,
                            plot_httpsc=plot_httpsc,
                            plot_os=plot_os,
                            plot_br=plot_br
                           )

def plot_unique_visitors_per_hour(uvph_data):
    hours = [entry['hour'] for entry in uvph_data]
    visitors = [entry['unique_visits'] for entry in uvph_data]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(hours, visitors, marker='o')
    ax.set_title('Unique Visitors Per Hour')
    ax.set_xlabel('Hour')
    ax.set_ylabel('Number of Visitors')
    plt.xticks(rotation=45)
    plt.tight_layout()

    return create_plot(fig)

def plot_requested_files(rf_data):
    if rf_data:
        filtered_rf_data = [entry for entry in rf_data if entry['requested_url'] is not None]

        if not filtered_rf_data:
            return "No valid data to plot."

        urls = [entry['requested_url'] for entry in filtered_rf_data]
        counts = [entry['count'] for entry in filtered_rf_data]

        plt.figure(figsize=(10, 6))
        plt.bar(urls, counts)
        plt.title('Top Requested Resources by Hits')
        plt.xlabel('Resource URL')
        plt.ylabel('Hit Count')
        plt.xticks(rotation=45)
        plt.tight_layout()

        return create_plot(plt.gcf())

    return "No data available to plot."

def plot_static_requests(sr_data):
    if sr_data:
        static_requests = [entry['static_request'] for entry in sr_data]
        resource_types = [entry['resource_type'] for entry in sr_data]
        request_counts = [entry['request_count'] for entry in sr_data]

        colors = ['red' if req == 'POST' else 'blue' for req in static_requests]

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(resource_types, request_counts, color=colors)
        ax.set_xlabel('Number of Requests')
        ax.set_ylabel('Resource Type')
        ax.set_title('Static Requests by Resource Type')

        ax.legend(['POST (modifications)', 'GET (read)'])

        plt.tight_layout()
        return create_plot(fig)

def plot_not_found_urls(nfu_data):
    if nfu_data:
        nfu_data_filtered = [entry for entry in nfu_data if entry['requested_url'] is not None]

        if not nfu_data_filtered:
            return "No valid data to plot."

        urls = [entry['requested_url'] for entry in nfu_data_filtered]
        counts = [entry['count'] for entry in nfu_data_filtered]

        plt.figure(figsize=(10, 6))
        plt.bar(urls, counts)
        plt.title('Top Not Found URLs by Hits')
        plt.xlabel('URL')
        plt.ylabel('Hit Count')
        plt.xticks(rotation=45)
        plt.tight_layout()

        return create_plot(plt.gcf())

    return "No data available to plot."

def categorize_ip(ip_address):
    if '.' in ip_address:
        octets = ip_address.split('.')
    else:
        octets = ip_address.split('-')
    for octet in octets:
        try:
            int_octet = int(octet)
        except ValueError:
            return 'Invalid IP Address'
    if int(octets[0]) < 128:
        return 'IP Address: 0-127'
    elif int(octets[0]) < 192:
        return 'IP Address: 128-191'
    elif int(octets[0]) < 224:
        return 'IP Address: 192-223'
    else:
        return 'IP Address: 224-255'

def plot_visitors_hostname_ip(vhi_data):
    if vhi_data:
        hits_per_category = {}
        color_map = {}
        hostname_map = {}

        for entry in vhi_data:
            ip_address = entry['ip_address']
            hits = entry['hits']
            hostname = entry['hostname']

            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                continue

            category = categorize_ip(ip_address)
            if category in hits_per_category:
                hits_per_category[category] += hits
            else:
                hits_per_category[category] = hits

            if category not in color_map:
                color_map[category] = 'skyblue'

            if category not in hostname_map:
                hostname_map[category] = hostname

        plt.figure(figsize=(10, 6))
        categories = list(hits_per_category.keys())
        hits = list(hits_per_category.values())
        colors = [color_map[category] for category in categories]
        bars = plt.bar(categories, hits, color=colors)
        plt.title('Visitors IP Address Distribution')
        plt.xlabel('IP Address Category')
        plt.ylabel('Hits')
        plt.xticks(rotation=45)

        handles = [mpatches.Patch(color=color_map[category]) for category in categories]
        labels = [f"{category}\n({hostname_map[category]})" for category in categories]
        plt.legend(handles, labels, title="Hostname", loc="upper left", bbox_to_anchor=(1, 1))

        plt.tight_layout()

        return create_plot(plt.gcf())

def plot_failed_connection_attempts(fcai_data):
    if fcai_data:
        categories = []
        failed_attempts = []

        for ip_address, data in fcai_data.items():
            category = categorize_ip(ip_address)
            if category not in categories:
                categories.append(category)
                failed_attempts.append(0)
            index = categories.index(category)
            failed_attempts[index] += data['failed_attempts']

        plt.figure(figsize=(10, 6))
        plt.bar(categories, failed_attempts, color='skyblue')
        plt.title('Failed Connection Attempts')
        plt.xlabel('IP Address Category')
        plt.ylabel('Failed Attempts')
        plt.xticks(rotation=45)
        plt.tight_layout()

        return create_plot(plt.gcf())

@app.route('/map_fcai_c')
def show_map():
    db_connection = get_db_connection()

    service = ServiceManager(db_connection)

    fcai_c_data = service.get_FCAIC()

    map_file = plot_failed_connection_attempts_with_country(fcai_c_data)

    with open(map_file, "r") as file: 
        map_content = file.read()

    return map_content

def plot_http_status_codes(httpsc_data):
    if httpsc_data:
        status_codes = [entry['status_code'] for entry in httpsc_data]
        counts = [entry['count'] for entry in httpsc_data]

        fig, ax = plt.subplots(figsize=(10, 6))
        colors = ['red' if code == 400 or code == 404 or code == 403 or code == 500 else 'skyblue' for code in status_codes]
        ax.pie(counts, labels=status_codes, colors=colors, autopct='%1.1f%%', startangle=90)
        
        ax.set_title('HTTP Status Codes')
        ax.axis('equal')

        plt.tight_layout()

        return create_plot(fig)

def plot_operating_systems(os_data):
    if os_data:
        os_names = list(os_data.keys())
        counts = list(os_data.values())

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.pie(counts, labels=os_names, autopct='%1.1f%%', startangle=90)
        ax.set_title('Operating Systems Usage')

        plt.tight_layout()
        return create_plot(fig)

def plot_browsers(br_data):
    if br_data:
        browser_names = list(br_data.keys())
        counts = list(br_data.values())

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.pie(counts, labels=browser_names, autopct='%1.1f%%', startangle=90)
        ax.set_title('Browsers Usage')

        plt.tight_layout()
        return create_plot(fig)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')

