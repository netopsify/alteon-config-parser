#!/usr/bin/env python
import jinja2
from pprint import pprint as pp
from ttp import ttp
import json
import pdb
import traceback
import sys
import re
import yaml
import argparse
import sys
import os
import ntpath

config_converter = argparse.ArgumentParser(prog='alteon-f5-config-converter.py',
                                           usage='./%(prog)s config host_vars\n./%(prog)s -h',
                                           description='Convert Alteon Native Configuration to F5 TMSH based Native Configuration')

# Add the arguments
config_converter.add_argument(
    'config', action='store', type=str, metavar='config', help='The path to Alteon native configuration file')
config_converter.add_argument(
    'host_vars', action='store', type=str, metavar='host_vars', help='Location of the host_vars files in YAML containing device specific information')
config_converter.add_argument(
    '--output_dir', action='store', type=str, metavar='output_dir', required=False, help='Location of the directory where to store the output')
config_converter.add_argument(
    '--runtime_vars_dir', action='store', type=str, metavar='runtime_vars_dir', required=False, help='Location of the directory where to store the runtime variable files')
config_converter.add_argument(
    '--alteon_state_dump', action='store', type=str, metavar='alteon_state_dump', required=False, help='Location of the Alteon state dump file')

# Execute the parse_args() method
args = config_converter.parse_args()

alteon_config_file = args.config
host_vars_file = args.host_vars

output_dir = args.output_dir
runtime_vars_dir = args.runtime_vars_dir
alteon_state_dump = args.alteon_state_dump

if not os.path.isfile(alteon_config_file):
    print('The specified configuration file does not exist')
    sys.exit()

if not os.path.isfile(host_vars_file):
    print('The specified configuration file does not exist')
    sys.exit()

if output_dir:
    if not os.path.isdir(output_dir):
        print('The specified directory does not exist')
        sys.exit()
else:
    output_dir = "./output"

if runtime_vars_dir:
    if not os.path.isdir(runtime_vars_dir):
        print('The specified directory does not exist')
        sys.exit()
else:
    runtime_vars_dir = "./runtime_vars"

if alteon_state_dump:
    if not os.path.isfile(alteon_state_dump):
        print('The specified configuration file does not exist')
        sys.exit()

############ Config Parser Function ############

############ Load Config Data Files ############

with open(alteon_config_file, 'r') as reader:
    data = reader.read()

############ Parse Data with TTP Templates ############
with open('./templates/real_servers_ttp.xml', 'r') as real_servers_ttp:
    real_servers_ttp_template = real_servers_ttp.read()

# create parser object and parse data using template:
real_servers_parser = ttp(data=data,
                          template=real_servers_ttp_template)
real_servers_parser.parse()

# print result in JSON format
real_servers_parsed_results = real_servers_parser.result()
real_servers_json_dumps = json.dumps(real_servers_parsed_results, sort_keys=True,
                                     indent=4, separators=(',', ': '))
real_servers = json.loads(real_servers_json_dumps)
# pp(real_servers[0][0]['nodes'])
with open(runtime_vars_dir + "/real_servers_parsed_results.json", "w+",) as f:
    f.write(json.dumps(real_servers[0][0], indent=4, sort_keys=True))

with open('./templates/groups_ttp.xml', 'r') as groups_ttp:
    groups_ttp_template = groups_ttp.read()

# create parser object and parse data using template:
groups_parser = ttp(data=data, template=groups_ttp_template)
groups_parser.parse()

# print result in JSON format
groups_parsed_results = groups_parser.result()
groups_json_dumps = json.dumps(groups_parsed_results, sort_keys=True,
                               indent=4, separators=(',', ': '))
groups = json.loads(groups_json_dumps)
# pp(groups[0][0]['pools'])
with open(runtime_vars_dir + "/groups_parsed_results.json", "w+",) as f:
    f.write(json.dumps(groups[0][0], indent=4, sort_keys=True))

with open('./templates/virtual_servers_ttp.xml', 'r') as virtual_servers_ttp:
    virtual_servers_ttp_template = virtual_servers_ttp.read()

# create parser object and parse data using template:
virtual_servers_parser = ttp(
    data=data, template=virtual_servers_ttp_template)
virtual_servers_parser.parse()

# print result in JSON format
virtual_servers_parsed_results = virtual_servers_parser.result()
virtual_servers_json_dumps = json.dumps(virtual_servers_parsed_results, sort_keys=True,
                                        indent=4, separators=(',', ': '))
virtual_servers = json.loads(virtual_servers_json_dumps)
# pp(virtual_servers[0][0]['virt'])
with open(runtime_vars_dir + "/virtual_servers_parsed_results.json", "w+",) as f:
    f.write(json.dumps(virtual_servers[0][0], indent=4, sort_keys=True))

with open('./templates/ssl_ttp.xml', 'r') as ssl_ttp:
    ssl_ttp_template = ssl_ttp.read()

# create parser object and parse data using template:
ssl_parser = ttp(
    data=data, template=ssl_ttp_template)
ssl_parser.parse()

# print result in JSON format
ssl_parsed_results = ssl_parser.result()
ssl_json_dumps = json.dumps(ssl_parsed_results, sort_keys=True,
                            indent=4, separators=(',', ': '))
ssl = json.loads(ssl_json_dumps)

# Print pbind_cookie results
# pp(ssl[0][0]['pbind_cookie'])
with open(runtime_vars_dir + "/pbind_cookie_parsed_results.json", "w+",) as f:
    f.write(json.dumps(ssl[0][0], indent=4, sort_keys=True))

# Print pbind_sslid results
# pp(ssl[1][0]['pbind_sslid'])
with open(runtime_vars_dir + "/pbind_sslid_parsed_results.json", "w+",) as f:
    f.write(json.dumps(ssl[1][0], indent=4, sort_keys=True))

nodes = real_servers[0][0]['nodes']
pools = groups[0][0]['pools']
vips = virtual_servers[0][0]['virt']

pbind_cookie = ssl[0][0]['pbind_cookie']
if not isinstance(pbind_cookie, list):
    pbind_cookie = [pbind_cookie]

pbind_sslid = ssl[1][0]['pbind_sslid']
if not isinstance(pbind_sslid, list):
    pbind_sslid = [pbind_sslid]

########## SSL Bundles, Certs, Kyes #############
# FIXME need to fix this parsing.
#################################################
with open('./templates/ssl_cert_bundle_ttp.xml', 'r') as ssl_cert_bundle_ttp:
    ssl_cert_bundle_ttp_template = ssl_cert_bundle_ttp.read()

# create parser object and parse data using template:
ssl_cert_bundle_parser = ttp(
    data=data, template=ssl_cert_bundle_ttp_template)
ssl_cert_bundle_parser.parse()

# print result in JSON format
ssl_cert_bundle_parsed_results = ssl_cert_bundle_parser.result()
ssl_cert_bundle_json_dumps = json.dumps(ssl_cert_bundle_parsed_results, sort_keys=True,
                                        indent=4, separators=(',', ': '))
ssl_cert_bundle = json.loads(ssl_cert_bundle_json_dumps)

with open(runtime_vars_dir + "/ssl_cert_bundle_parsed_results.json", "w+",) as f:
    f.write(json.dumps(ssl_cert_bundle[0][0], indent=4, sort_keys=True))

with open('./templates/ssl_certs_ttp.xml', 'r') as ssl_certs_ttp:
    ssl_certs_ttp_template = ssl_certs_ttp.read()

# create parser object and parse data using template:
ssl_certs_parser = ttp(
    data=data, template=ssl_certs_ttp_template)
ssl_certs_parser.parse()

# print result in JSON format
ssl_certs_parsed_results = ssl_certs_parser.result()
ssl_certs_json_dumps = json.dumps(ssl_certs_parsed_results, sort_keys=True,
                                  indent=4, separators=(',', ': '))
ssl_certs = json.loads(ssl_certs_json_dumps)

with open(runtime_vars_dir + "/ssl_certs_parsed_results.json", "w+",) as f:
    f.write(json.dumps(ssl_certs[0][0], indent=4, sort_keys=True))

with open('./templates/ssl_policies_ttp.xml', 'r') as ssl_policies_ttp:
    ssl_policies_ttp_template = ssl_policies_ttp.read()

# create parser object and parse data using template:
ssl_policies_parser = ttp(
    data=data, template=ssl_policies_ttp_template)
ssl_policies_parser.parse()

# print result in JSON format
ssl_policies_parsed_results = ssl_policies_parser.result()
ssl_policies_json_dumps = json.dumps(ssl_policies_parsed_results, sort_keys=True,
                                     indent=4, separators=(',', ': '))
ssl_policies = json.loads(ssl_policies_json_dumps)

with open(runtime_vars_dir + "/ssl_policies_parsed_results.json", "w+",) as f:
    f.write(json.dumps(ssl_policies[0][0], indent=4, sort_keys=True))

##############Till here data is parsed###############

#### Below function is now combining vip relevant data only...####
# Updating the VIPS Dictionary with cookie and sslid; pbind settings

for vip, vip_config in vips.items():
    if isinstance(vip_config,list):
        print(f"There are multiple /virt configs for {vip}.\n")
        for srv in vip_config:
            for vip_port, config in srv['services'].items():
                for cookie in pbind_cookie:
                    try:
                        if config['virt_seq'] == cookie['virt_seq'] and vip_port == cookie['vip_port']:
                            config['pbind'] = cookie['pbind']
                            config['pbind_type'] = cookie['pbind_type']
                            config['rcount'] = cookie['rcount']
                    except:
                        extype, value, tb = sys.exc_info()
                        traceback.print_exc()
                        pdb.post_mortem(tb)
                for sslid in pbind_sslid:
                    if config['virt_seq'] == sslid['virt_seq'] and vip_port == sslid['vip_port']:
                        config['pbind'] = sslid['pbind']
    elif isinstance(vip_config,dict):
        if 'services' in vip_config.keys():
            for vip_port, config in vip_config['services'].items():
                for cookie in pbind_cookie:
                    try:
                        if config['virt_seq'] == cookie['virt_seq'] and vip_port == cookie['vip_port']:
                            config['pbind'] = cookie['pbind']
                            config['pbind_type'] = cookie['pbind_type']
                            config['rcount'] = cookie['rcount']
                    except:
                        extype, value, tb = sys.exc_info()
                        traceback.print_exc()
                        pdb.post_mortem(tb)
                for sslid in pbind_sslid:
                    if config['virt_seq'] == sslid['virt_seq'] and vip_port == sslid['vip_port']:
                        config['pbind'] = sslid['pbind']

# Saving new VIPs dict to file
with open(runtime_vars_dir + "/vips.json", "w+",) as f:
    f.write(json.dumps(vips, indent=4, sort_keys=True))
# pp(nodes)
# pp(pools)
# pp(vips)
# pp(pbind_cookie)
# pp(pbind_sslid)

############ END Config Parser Function ############

############ Creating helper filters ############


def regex_replace(s, find, replace):
    """A non-optimal implementation of a regex filter"""
    return re.sub(find, replace, s)


def to_nice_yaml(a, indent=2):
    '''Make verbose, human readable yaml'''
    transformed = yaml.dump(a, indent=indent,
                            allow_unicode=True, default_flow_style=False)
    return transformed

############ END Creating helper filters ############


############ Creating helper data ############
nodes_seq_dict = {}
nodes_name_dict = {}
for node in nodes:
    _ = nodes_seq_dict.update({node['node_seq']: node})
    _ = nodes_name_dict.update({node['node_name']: node})

# pp(nodes_seq_dict)
# pp(nodes_name_dict)
with open(runtime_vars_dir + "/nodes_seq_dict.json", "w+",) as f:
    f.write(json.dumps(nodes_seq_dict, indent=4, sort_keys=True))

with open(runtime_vars_dir + "/nodes_name_dict.json", "w+",) as f:
    f.write(json.dumps(nodes_name_dict, indent=4, sort_keys=True))

pools_seq_dict = {}
pools_name_dict = {}
for pool in pools:
    _ = pools_seq_dict.update({pool['group_seq']: pool})
    _ = pools_name_dict.update({pool['group_name']: pool})

with open(runtime_vars_dir + "/pools_seq_dict.json", "w+",) as f:
    f.write(json.dumps(pools_seq_dict, indent=4, sort_keys=True))

with open(runtime_vars_dir + "/pools_name_dict.json", "w+",) as f:
    f.write(json.dumps(pools_name_dict, indent=4, sort_keys=True))

vips_vip_ip_dict = {}
vips_vip_seq_dict = {}
with open(runtime_vars_dir + "/vips_vip_ip_dict.json", "w+",) as f:
    f.write(json.dumps(virtual_servers[0][0]['virt'], indent=4, sort_keys=True))

for vip, config in vips.items():
    if isinstance(config,dict):
        _ = vips_vip_seq_dict.update({config['virt_seq']: config})
        # _ = vips_vip_seq_dict['virt_seq'].update(
        #     {'vip_ip': {}})
        _ = vips_vip_seq_dict[config['virt_seq']].update(
            {'vip_ip': vip})

with open(runtime_vars_dir + "/vips_vip_seq_dict.json", "w+",) as f:
    f.write(json.dumps(vips_vip_seq_dict, indent=4, sort_keys=True))

pbind_cookie_vip_seq_dict = {}
pbind_cookie_vip_service_dict = {}
for pbind in pbind_cookie:
    _ = pbind_cookie_vip_seq_dict.update({pbind['virt_seq']: pbind})
    _ = pbind_cookie_vip_service_dict.update({pbind['vip_port']: pbind})

with open(runtime_vars_dir + "/pbind_cookie_vip_seq_dict.json", "w+",) as f:
    f.write(json.dumps(pbind_cookie_vip_seq_dict, indent=4, sort_keys=True))

with open(runtime_vars_dir + "/pbind_cookie_vip_service_dict.json", "w+",) as f:
    f.write(json.dumps(pbind_cookie_vip_service_dict, indent=4, sort_keys=True))

pbind_sslid_vip_seq_dict = {}
for pbind in pbind_sslid:
    _ = pbind_sslid_vip_seq_dict.update({pbind['virt_seq']: pbind})

with open(runtime_vars_dir + "/pbind_sslid_vip_seq_dict.json", "w+",) as f:
    f.write(json.dumps(pbind_sslid_vip_seq_dict, indent=4, sort_keys=True))

############ END Creating helper data ############

# Pirnt length for visibility

print('Total Real Servers are = ' + str(len(nodes)))
print('Total groups are = ' + str(len(pools)))
print('Total Virtual Servers are = ' + str(len(vips)))
print('Total SSL Cookie profiles are = ' + str(len(pbind_cookie)))
print('Total SSLID profiles are = ' + str(len(pbind_sslid)))

############ Creating Data Structure in Yaml ############

def model_alteon_data(vips):
    all_vips = []
    for vip, vip_config in vips.items():
        # print(vip)
        if isinstance(vip_config, list):
            for srv in vip_config:
                if srv['config_state'] == 'ena':
                    if 'services' in srv.keys():
                        for vip_port, srv_config in srv['services'].items():
                            vip_dict = dict({
                                "vip_ip": "",
                                "vip_port": "",
                                "vip_name": "",
                                "vip_type": "",
                                "virt_seq": "",
                                "pool": {
                                    "name": "",
                                    "lb_method": "",
                                    "members": []
                                }})
                            vip_dict['virt_seq'] = srv_config["virt_seq"]
                            vip_dict['vip_ip'] = vip
                            vip_dict['vip_port'] = vip_port
                            if srv['vip_name'] != 'None':
                                vip_name = regex_replace(
                                    srv['vip_name'], "[^A-Za-z0-9-_.]", "")
                                vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                            elif srv['vip_name'] == 'None':
                                group_name = pools_seq_dict[srv_config['group_seq']
                                                            ]['group_name']
                                if group_name != 'None':
                                    vip_name = regex_replace(
                                        group_name, "[^A-Za-z0-9-_.]", "")
                                    vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                    vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                elif group_name == 'None':
                                    node_list = pools_seq_dict[srv_config['group_seq']
                                                            ]['node_list']
                                    for i, node in enumerate(node_list):
                                        node_name = nodes_seq_dict[node['node_seq']
                                                                ]['node_name']
                                        if node_name != 'None':
                                            vip_name = node_name
                                            vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                            vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                            break
                                        elif node_name == 'None' and i != len(node_list) - 1:
                                            continue
                                        else:
                                            vip_name = "migrated-from-alteon"
                                            vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                            vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                else:
                                    vip_name = "unknown-vip_name-fixme"
                                    vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                    vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                            lb_method = pools_seq_dict[srv_config['group_seq']
                                                    ]['lb_method']
                            if lb_method == 'roundrobin':
                                vip_dict['pool']['lb_method'] = "round-robin"
                            elif lb_method == 'None':
                                vip_dict['pool']['lb_method'] = "least-connections-member"
                            nodes_list = pools_seq_dict[srv_config['group_seq']
                                                        ]['node_list']
                            for node in nodes_list:

                                node_seq = node['node_seq']
                                node_ip = node_name = nodes_seq_dict[node_seq]['node_ip']

                                node_name = regex_replace(
                                    nodes_seq_dict[node_seq]['node_name'], "[^A-Za-z0-9-_.]", "")
                                vip_dict['pool']['members'].append({
                                    'node_name': node_name if node_name != 'None' else vip_dict['vip_name'] + "_real_server_" + str(node_seq),
                                    'node_ip': node_ip,
                                    'node_port': srv_config['real_port'] if srv_config['real_port'] != 'None' else vip_port
                                })
                            if 'pbind' in srv_config.keys() and 'ssl_profile' not in srv_config.keys():
                                if srv_config['pbind'] != "None":
                                    if srv_config['pbind'] == "sslid":
                                        vip_dict['vip_type'] = "b"
                                    elif srv_config['pbind'] == "clientip":
                                        vip_dict['vip_type'] = "e"
                                    else:
                                        vip_dict['vip_type'] = "a"
                                else:
                                    vip_dict['vip_type'] = "a"
                            elif 'pbind' in srv_config.keys() and 'ssl_profile' in srv_config.keys():
                                if srv_config['pbind'] != "None":
                                    if srv_config['pbind'] == "cookie":
                                        vip_dict['vip_type'] = "c"
                                        vip_dict['ssl_profile'] = srv_config['ssl_profile']
                                        vip_dict['ssl_profile'].update({
                                            'persistence': srv_config['pbind'],
                                            'persist_cookie': srv_config['pbind_type'],
                                        })
                                    else:
                                        vip_dict['vip_type'] = "a"
                                else:
                                    vip_dict['vip_type'] = "a"
                            elif srv_config['dbind'] == "ena":
                                vip_dict['vip_type'] = "a"

                            elif srv_config['dbind'] == "None":
                                vip_dict['vip_type'] = "d"

                            else:
                                vip_dict['vip_type'] = "a"

                            all_vips.append(vip_dict)

        elif isinstance(vip_config, dict):
            if vip_config['config_state'] == 'ena':
                if 'services' in vip_config.keys():
                    for vip_port, srv_config in vip_config['services'].items():
                        vip_dict = dict({
                            "vip_ip": "",
                            "vip_port": "",
                            "vip_name": "",
                            "vip_type": "",
                            "virt_seq": "",
                            "pool": {
                                "name": "",
                                "lb_method": "",
                                "members": []
                            }})
                        vip_dict['virt_seq'] = srv_config["virt_seq"]
                        vip_dict['vip_ip'] = vip
                        vip_dict['vip_port'] = vip_port
                        if vip_config['vip_name'] != 'None':
                            vip_name = regex_replace(
                                vip_config['vip_name'], "[^A-Za-z0-9-_.]", "")
                            vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                            vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                        elif vip_config['vip_name'] == 'None':
                            group_name = pools_seq_dict[srv_config['group_seq']
                                                        ]['group_name']
                            if group_name != 'None':
                                vip_name = regex_replace(
                                    group_name, "[^A-Za-z0-9-_.]", "")
                                vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                            elif group_name == 'None':
                                node_list = pools_seq_dict[srv_config['group_seq']
                                                        ]['node_list']
                                for i, node in enumerate(node_list):
                                    node_name = nodes_seq_dict[node['node_seq']
                                                            ]['node_name']
                                    if node_name != 'None':
                                        vip_name = node_name
                                        vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                        vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                        break
                                    elif node_name == 'None' and i != len(node_list) - 1:
                                        continue
                                    else:
                                        vip_name = "migrated-from-alteon"
                                        vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                        vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                            else:
                                vip_name = "unknown-vip_name-fixme"
                                vip_dict['vip_name'] = "vs-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                                vip_dict['pool']['name'] = "pool-tcp-" + str(vip_port) + "-" + vip_name + "-" + str(vip)
                        lb_method = pools_seq_dict[srv_config['group_seq']
                                                ]['lb_method']
                        if lb_method == 'roundrobin':
                            vip_dict['pool']['lb_method'] = "round-robin"
                        elif lb_method == 'None':
                            vip_dict['pool']['lb_method'] = "least-connections-member"
                        nodes_list = pools_seq_dict[srv_config['group_seq']
                                                    ]['node_list']
                        for node in nodes_list:

                            node_seq = node['node_seq']
                            node_ip = node_name = nodes_seq_dict[node_seq]['node_ip']

                            node_name = regex_replace(
                                nodes_seq_dict[node_seq]['node_name'], "[^A-Za-z0-9-_.]", "")
                            vip_dict['pool']['members'].append({
                                'node_name': node_name if node_name != 'None' else vip_dict['vip_name'] + "_real_server_" + str(node_seq),
                                'node_ip': node_ip,
                                'node_port': srv_config['real_port'] if srv_config['real_port'] != 'None' else vip_port
                            })
                        if 'pbind' in srv_config.keys() and 'ssl_profile' not in srv_config.keys():
                            if srv_config['pbind'] != "None":
                                if srv_config['pbind'] == "sslid":
                                    vip_dict['vip_type'] = "b"
                                elif srv_config['pbind'] == "clientip":
                                    vip_dict['vip_type'] = "e"
                                else:
                                    vip_dict['vip_type'] = "a"
                            else:
                                vip_dict['vip_type'] = "a"
                        elif 'pbind' in srv_config.keys() and 'ssl_profile' in srv_config.keys():
                            if srv_config['pbind'] != "None":
                                if srv_config['pbind'] == "cookie":
                                    vip_dict['vip_type'] = "c"
                                    vip_dict['ssl_profile'] = srv_config['ssl_profile']
                                    vip_dict['ssl_profile'].update({
                                        'persistence': srv_config['pbind'],
                                        'persist_cookie': srv_config['pbind_type'],
                                    })
                                else:
                                    vip_dict['vip_type'] = "a"
                            else:
                                vip_dict['vip_type'] = "a"
                        elif srv_config['dbind'] == "ena":
                            vip_dict['vip_type'] = "a"

                        elif srv_config['dbind'] == "None":
                            vip_dict['vip_type'] = "d"

                        else:
                            vip_dict['vip_type'] = "a"

                        all_vips.append(vip_dict)

    return all_vips

# VIP Types - reference only
# If dbind then use standard vip
# Else use fast-l4

# If metric roundrobin use roundrobin lb method in f5
# If no metric defined in alteon group config then use least-connection-member in f5 config

lb_vip_types = {
    "a": {
        "keepalive": "tcp",
        "vip_type": "standard"
    },
    "b": {
        "keepalive": "tcp",
        "sticky": "sslid",
        "ssl_offload": False,
        "vip_type": "standard"
    },
    "c": {
        "keepalive": "tcp",
        "sticky": "cookie",
        "ssl_offload": True,
        "vip_type": "standard"
    },
    "d": {
        "keepalive": "tcp",
        "vip_type": "FastL4"
    },
    "e": {
        "keepalive": "tcp",
        "vip_type": "FastL4",
        "persist": "source_addr"
    }
}
###################################################################

# Render VIPs data
vips_data_structure = model_alteon_data(vips)

# Convert it to YAML Format
vips_data_structure_yaml = to_nice_yaml(vips_data_structure)

# Write Yaml Data to file
with open(output_dir + "/vips.yml", "w+",) as f:
    f.write(vips_data_structure_yaml)

############ END Data Structure in Yaml ############

############ Generating F5 Config ############

ENV = jinja2.Environment(loader=jinja2.FileSystemLoader("."), extensions=[
    'jinja2.ext.loopcontrols'])

ENV.filters['regex_replace'] = regex_replace
ENV.filters['to_nice_yaml'] = to_nice_yaml

# ENV.trim_blocks = True
# ENV.lstrip_blocks = True

config_template = ENV.get_template("templates/config.j2")

with open(host_vars_file) as f:
    host_vars = yaml.load(f, Loader=yaml.FullLoader)

with open(output_dir + "/" + os.path.basename(alteon_config_file), "w",) as f:
    code = config_template.render(
        vips=yaml.load(vips_data_structure_yaml, Loader=yaml.FullLoader),
        host_vars=host_vars,
        nodes=nodes  # For creating nodes from real servers list.
    )
    f.write(code)
