from flask import Flask, jsonify, render_template, redirect, url_for, request
from sniffer.sniffer import scan_and_organize
from sniffer import deep_scan
import sqlite3
import ipaddress
import os
from dotenv import load_dotenv
load_dotenv()

DB = "network.db"

app = Flask(__name__)

######################
## Helper Functions ##
######################

def ip_collate(ip1, ip2):
    """Custom collation function to sort IP addresses correctly."""
    try:
        ip1_obj = ipaddress.ip_address(ip1)
        ip2_obj = ipaddress.ip_address(ip2)
        if ip1_obj < ip2_obj: return -1
        if ip1_obj > ip2_obj: return 1
        return 0
    except ValueError:
        # Fallback to string comparison if invalid IP is encountered
        if ip1 < ip2: return -1
        if ip1 > ip2: return 1
        return 0

def get_db_connection():
    """Establish a connection to the SQLite database with the custom IP collation."""
    conn = sqlite3.connect(DB)
    conn.create_collation("IP_CMP", ip_collate)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/error_handler')
def error_handler():
    """Simple error handler route for disabled buttons."""
    message = request.args.get('message')
    if not message:
        message = "Gonk! Something went wrong Choom."
    return render_template('error.html', message=message)

@app.route('/')
def index():
    """Redirect the root URL to the dashboard."""
    return redirect(url_for('dashboard'))

#################
## Main Routes ##
#################

@app.route('/scan_devices', methods=['GET'])
def get_devices():
    """API endpoint to run a scan and return the results as JSON."""
    conn = get_db_connection()
    known_devices = conn.execute("SELECT * FROM devices").fetchall()
    known_macs = [device['mac'] for device in known_devices]
    
    # Create a set of reliable known hostnames to track devices that rotate their MACs
    known_hostnames = {device['hostname'] for device in known_devices if device['hostname'] and device['hostname'] != "Unknown"}
    
    # Run the scan using the imported function
    devices = scan_and_organize(os.environ.get('NETWORK_IP_RANGE'))
    scanned_macs = []
    
    for device in devices:
        scanned_macs.append(device['mac'])
        
        # 1. Match by MAC Address (Standard behavior)
        if device['mac'] in known_macs:
            # Update the existing device information
            conn.execute("UPDATE devices SET ip = ?, hostname = ?, vendor = ?, category = ?, open_ports = ?, last_seen = datetime('now'), status = ? WHERE mac = ?",
                         (device['ip'], device['hostname'], device['vendor'], device['category'], device['open_ports'], 'active', device['mac']))
        # 2. Match by Hostname (Fallback for Randomized MACs)
        elif device['hostname'] in known_hostnames:
            # Overwrite the old MAC address with the newly randomized one
            conn.execute("UPDATE devices SET ip = ?, mac = ?, vendor = ?, category = ?, open_ports = ?, last_seen = datetime('now'), status = ? WHERE hostname = ?",
                         (device['ip'], device['mac'], device['vendor'], device['category'], device['open_ports'], 'active', device['hostname']))
        # 3. Completely new device
        else:
            conn.execute("INSERT INTO devices (ip, mac, hostname, vendor, category, open_ports, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (device['ip'], device['mac'], device['hostname'], device['vendor'], device['category'], device['open_ports'], 'active'))

    # Mark devices not found in this scan as 'inactive'
    for known_mac in known_macs:
        if known_mac not in scanned_macs:
            conn.execute("UPDATE devices SET status = 'inactive' WHERE mac = ?", (known_mac,))

    conn.commit()
    conn.close()
    
    #return jsonify(devices)
    return redirect(url_for('dashboard'))

@app.route('/targeted_scan/<ip>', methods=['GET'])
def targeted_scan(ip):
    """Run a targeted scan and update its information in the database."""
    try:
        device = scan_and_organize(ip)[0]  # Assuming scan_and_organize returns a list of devices, we take the first one for the targeted IP
    except IndexError:
        return redirect(url_for('error_handler', message="Targeted scan failed. Device may be inactive or unreachable."))   
    conn = get_db_connection()
    try:
        conn.execute("UPDATE devices SET ip = ?, hostname = ?, vendor = ?, category = ?, open_ports = ?, last_seen = datetime('now'), status = ? WHERE ip = ?",
                     (device['ip'], device['hostname'], device['vendor'], device['category'], device['open_ports'], 'active', device['ip']))
    except Exception as e:
        print(f"Error updating device information: {e}")
    finally:
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """dashboard route to display the devices in a simple HTML format."""
    conn = get_db_connection()
    known_devices = conn.execute("SELECT * FROM devices LEFT JOIN aliases ON devices.id = aliases.id WHERE hostname != 'Unknown' ORDER BY status ASC, ip COLLATE IP_CMP ASC").fetchall()
    semi_known_devices = conn.execute("SELECT * FROM devices LEFT JOIN aliases ON devices.id = aliases.id WHERE hostname = 'Unknown' AND vendor != '%Unknown%' ORDER BY status ASC, ip COLLATE IP_CMP ASC").fetchall()
    unknown_devices = conn.execute("SELECT * FROM devices LEFT JOIN aliases ON devices.id = aliases.id WHERE hostname = 'Unknown' AND vendor = 'Unknown' ORDER BY status ASC, ip COLLATE IP_CMP ASC").fetchall()
    conn.close()
    
    router_url = os.environ.get('ROUTER_ADMIN_URL', '#')
    twingate_url = os.environ.get('TWINGATE_URL', '#')
    nextdns_url = os.environ.get('NEXTDNS_URL', '#')

    return render_template('dashboard.html', known_devices=known_devices, semi_known_devices=semi_known_devices, unknown_devices=unknown_devices, router_url=router_url, twingate_url=twingate_url, nextdns_url=nextdns_url)


@app.route('/device_info/<ip>/add_alias', methods=['GET', 'POST'])
def add_device_alias(ip):
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()

    if request.method == 'POST':
        # get form data
        new_hostname_alias = request.form['alias']
        new_category = request.form['alias_category']

        ## Checking to see if device already has an alias in the same category, and if so, update it instead of adding a new one
        existing_alias = conn.execute("SELECT * FROM aliases WHERE id = ?", (device['id'],)).fetchone()
        new = 0
        try:            
            existing_alias_dict = dict(existing_alias)
            new = 1
        except:
            existing_alias_dict = {}

        if new_hostname_alias:
            if new == 1:
                conn.execute("UPDATE aliases SET user_hostname = ? WHERE id = ?", (new_hostname_alias, device['id']))
                conn.commit()
            else:
                conn.execute("INSERT INTO aliases (id,user_hostname) VALUES (?,?)", (device['id'], new_hostname_alias))
                conn.commit()

        if new_category:
            if new == 1:
                conn.execute("UPDATE aliases SET user_category = ? WHERE id = ?", (new_category, device['id']))
                conn.commit()
            else:
                conn.execute("INSERT INTO aliases (id,user_category) VALUES (?,?)", (device['id'], new_category))
                conn.commit()

        conn.close()
        return redirect(url_for('device_info', ip=ip))
    
    conn.close()
    if not device:
        return redirect(url_for('error_handler', message="Device not found."))
    return render_template('device_info.html', device=device)

@app.route('/device_info/<ip>', methods=['GET'])
def device_info(ip):
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
    alias = conn.execute("SELECT * FROM aliases WHERE id = ?", (device['id'],)).fetchone()
    try:
        alias_dict = dict(alias)
    except:
        alias_dict = {}
    conn.close()
    if not device:
        return redirect(url_for('error_handler', message="Device not found."))
    return render_template('device_info.html', device=device, alias=alias_dict)

@app.route('/device_info/<ip>/delete_alias', methods=['GET', 'POST'])
def delete_device_alias(ip):
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()

    if request.method == 'POST':
        # possible aliases
        possible_aliases = ['user_hostname', 'user_category']

        # get form data
        alias_to_delete = request.form.to_dict()
        
        for key in alias_to_delete.keys():
            if key not in possible_aliases:
                return redirect(url_for('error_handler', message="Invalid alias category."))
            else:
                # Delete the alias
                conn.execute("UPDATE aliases SET {} = NULL WHERE id = ? AND {} = ?".format(key, key), (device['id'], alias_to_delete[key]))
                conn.commit()

        conn.close()
        return redirect(url_for('device_info', ip=ip))

    conn.close()
    if not device:
        return redirect(url_for('error_handler', message="Device not found."))
    
    return redirect(url_for('device_info', ip=ip))

######################
## Network Map Page ##
######################

@app.route('/network_map', methods=['GET'])
def network_map():
    return render_template('network_map.html')

######################
## MAC Address Page ##
######################

@app.route('/mac_addresses', methods=['GET'])
def mac_addresses():
    conn = get_db_connection()
    devices = conn.execute("SELECT mac, vendor, last_seen FROM devices WHERE mac IS NOT NULL ORDER BY vendor COLLATE NOCASE ASC").fetchall()
    conn.close()
    return render_template('mac_addresses.html', devices=devices)

######################
## Open Ports Page ##
######################

@app.route('/open_ports', methods=['GET'])
def open_ports():
    conn = get_db_connection()
    devices = conn.execute("SELECT open_ports, category FROM devices WHERE open_ports IS NOT NULL ORDER BY category COLLATE NOCASE ASC").fetchall()
    conn.close()
    return render_template('open_ports.html', devices=devices)

######################


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
