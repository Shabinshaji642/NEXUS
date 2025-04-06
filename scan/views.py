import nmap
import nvdlib
from django.shortcuts import render
# Checking Scan type


def check_scan_type(scan_type):
    if scan_type == 'quick':
        return '-sV -F'  # Fast scan
    elif scan_type == 'standard':
        return '-sV '  # Service version detection
    elif scan_type == 'full':
        return '-p- -sV'  # All ports with service detection
    return '-sV -F'


# Check cves
def check_cves(service):
    if (service['name'] == '') and  (service['version'] == ''):
        return []
    # name = service['name'].split()[0].lower()
    # version_cve = service['version'].split()[0]
    # if not version_cve[-2].isnumeric():
    #     version_cve = version_cve[:-2]
    #Handle empty service name
    name = service['name']
    if not name:
        return []
    name = name.split()[0].lower()

    # Handle empty version
    version = service['version']
    if not version:
        return []

    version_parts = version.split()
    if not version_parts:
        return []
    version_cve = version_parts[0]
    version_control = []
    for i in version_cve:
        if i.isnumeric() or i == '.':
            version_control.append(i)
    version_cve = ''.join(version_control)
    # Safely handle version trimming
    try:
        if len(version_cve) >= 2 and not version_cve[-2].isnumeric():
            version_cve = version_cve[:-2]
    except IndexError:
        pass
    print(name, version_cve)
    query = f'{name} {version_cve}'
    cves = []
    for cve in nvdlib.searchCVE(keywordSearch=query):
        cves.append({
            'cve_id': cve.id,
            'description': cve.descriptions[0].value if cve.descriptions else '',
            'cvss': cve.score[1],
            'severity': cve.score[2],
            'service': name,
            'version': version_cve
        })
    return cves


def index(request):
        if request.method == 'POST':
            hostname = request.POST['hostname']
            scan_type = request.POST['scan_type']
            arg = check_scan_type(scan_type)
            nm = nmap.PortScanner()
            nm.scan(hosts=hostname, arguments=arg)
            vulnerabilities = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        cves = check_cves(service)
                        vulnerabilities.extend(cves)
                        print(cves)
            print(vulnerabilities)
            return render(request, 'scan/results.html', {'vulnerabilities': vulnerabilities})

        return render(request, 'scan/index.html')

