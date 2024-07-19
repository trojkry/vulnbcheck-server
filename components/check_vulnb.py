import os
import csv
from datetime import datetime
import concurrent.futures

def load_threats_csv(threats_file):
    threats = []
    with open(threats_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=';')
        for row in reader:
            threats.append(row)
    return threats

def compare_versions(version1, version2):
    v1_parts = [int(x) if x.isdigit() else 0 for x in version1.split('.')]
    v2_parts = [int(x) if x.isdigit() else 0 for x in version2.split('.')]
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_part = v1_parts[i] if i < len(v1_parts) else 0
        v2_part = v2_parts[i] if i < len(v2_parts) else 0
        if v1_part < v2_part:
            return -1
        if v1_part > v2_part:
            return 1
    return 0

def is_vulnerable(installed_version, affected_versions):
    affected_ranges = affected_versions.split(' ')
    for affected_range in affected_ranges:
        if '-' in affected_range:
            start, end = affected_range.split('-')
            start, end = start.strip(), end.strip()
            if compare_versions(start, installed_version) <= 0 and compare_versions(end, installed_version) >= 0:
                return True
        elif affected_range == installed_version:
            return True
    return False

def get_plugin_version(plugin_path):
    plugin_file = os.path.join(plugin_path, os.path.basename(plugin_path) + '.php')
    version = "Unknown"
    if os.path.isfile(plugin_file):
        with open(plugin_file, 'r', encoding='utf-8') as file:
            for line in file:
                if 'Version:' in line:
                    version = line.split('Version:')[1].strip()
                    break
    return version

def check_installed_plugins(plugins_dir, threats, site_name):
    matched_plugins = []
    for plugin in os.listdir(plugins_dir):
        plugin_path = os.path.join(plugins_dir, plugin)
        if os.path.isdir(plugin_path):
            plugin_name = plugin.lower()
            installed_version = get_plugin_version(plugin_path)
            for threat in threats:
                if threat['slug'].lower() == plugin_name:
                    affected_versions = threat['affected_versions']
                    if is_vulnerable(installed_version, affected_versions):
                        matched_plugins.append({
                            'Site Name': site_name,
                            'Plugin Name': threat['name'],
                            'Installed Version': installed_version,
                            'Threat Title': threat['title'],
                            'CVE': threat['cve'],
                            'CVSS Score': threat['cvss_score'],
                            'Reference': threat['reference']
                        })
                        break
    return matched_plugins

def write_report(matched_plugins, report_filename):
    headers = ['Site Name', 'Plugin Name', 'Installed Version', 'Threat Title', 'CVE', 'CVSS Score', 'Reference']
    with open(report_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for plugin in matched_plugins:
            writer.writerow(plugin)
    print(f"Report generated: {report_filename}")

def checkvlnb(parent_dir, threats):
    matched_plugins_all = []
    
    def process_site(site_dir):
        site_path = os.path.join(parent_dir, site_dir)
        plugins_dir = os.path.join(site_path, 'wp-content', 'plugins')
        if os.path.isdir(plugins_dir):
            return check_installed_plugins(plugins_dir, threats, site_dir)
        else:
            print(f"No plugins directory found for site: {site_dir}")
            return []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_site = {executor.submit(process_site, site_dir): site_dir for site_dir in os.listdir(parent_dir) if os.path.isdir(os.path.join(parent_dir, site_dir))}
        
        for future in concurrent.futures.as_completed(future_to_site):
            site_dir = future_to_site[future]
            try:
                matched_plugins = future.result()
                matched_plugins_all.extend(matched_plugins)
            except Exception as exc:
                print(f"Exception occurred for site {site_dir}: {exc}")

    if matched_plugins_all:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        host_name = os.uname().nodename
        report_filename = f"{timestamp}_{host_name}.csv"
        write_report(matched_plugins_all, report_filename)
    else:
        print("No vulnerable plugins found across all sites.")

    return matched
