import os
import csv
from datetime import datetime
import concurrent.futures

def load_threats_csv(threats_file):
    threats = []
    with open(threats_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        headers = next(reader)
        for row in reader:
            threats.append(dict(zip(headers, row)))
    return threats

def compare_versions(version1, version2):
    v1_parts = [int(x) if x.isdigit() else 0 for x in version1.split('.')]
    v2_parts = [int(x) if x.isdigit() else 0 for x in version2.split('.')]
    for v1_part, v2_part in zip(v1_parts, v2_parts):
        if v1_part < v2_part:
            return -1
        if v1_part > v2_part:
            return 1
    return (len(v1_parts) > len(v2_parts)) - (len(v1_parts) < len(v2_parts))

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
    if os.path.isfile(plugin_file):
        with open(plugin_file, 'r', encoding='utf-8') as file:
            for line in file:
                if 'Version:' in line:
                    return line.split('Version:')[1].strip()
    return "Unknown"

def check_installed_plugins(plugins_dir, threats, site_name):
    matched_plugins = []
    for plugin in os.listdir(plugins_dir):
        plugin_path = os.path.join(plugins_dir, plugin)
        if os.path.isdir(plugin_path):
            plugin_name = plugin.lower()
            installed_version = get_plugin_version(plugin_path)
            for threat in threats:
                if threat['slug'].lower() == plugin_name:
                    if is_vulnerable(installed_version, threat['affected_versions']):
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
        writer.writerows(matched_plugins)
    print(f"Report generated: {report_filename}")

def is_website_dir(directory):
    return os.path.isdir(os.path.join(directory, 'wp-content', 'plugins'))

def find_all_websites(root_dir):
    websites = []
    for root, dirs, files in os.walk(root_dir):
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            if is_website_dir(dir_path):
                websites.append(dir_path)
    return websites

def checkvlnb(parent_dir, threats):
    matched_plugins_all = []

    def process_site(site_dir):
        plugins_dirs = []
        for root, dirs, files in os.walk(site_dir):
            for dir in dirs:
                if dir == 'plugins' and 'wp-content' in root:
                    plugins_dirs.append(os.path.join(root, dir))

        site_matched_plugins = []
        with concurrent.futures.ThreadPoolExecutor() as plugin_executor:
            futures = [plugin_executor.submit(check_installed_plugins, plugins_dir, threats, site_dir) for plugins_dir in plugins_dirs]
            for future in concurrent.futures.as_completed(futures):
                site_matched_plugins.extend(future.result())
        
        return site_matched_plugins

    websites = find_all_websites(parent_dir)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_site = {executor.submit(process_site, site_dir): site_dir for site_dir in websites}
        
        for future in concurrent.futures.as_completed(future_to_site):
            site_dir = future_to_site[future]
            try:
                matched_plugins_all.extend(future.result())
            except Exception as exc:
                print(f"Exception occurred for site {site_dir}: {exc}")

    if matched_plugins_all:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        host_name = os.uname().nodename
        report_filename = f"{timestamp}_{host_name}.csv"
        write_report(matched_plugins_all, report_filename)
    else:
        print("No vulnerable plugins found across all sites.")

    return matched_plugins_all
