# alteon-config-parser

This will convert Radware's Alteon Load Balancer Configuration to F5 TMSH based script.

Mainly you need to provide two things to the script.

1. Alteon Configuration Dump
2. Populate the custom configuration variable. (example in `examples/host_vars.yml`)

*Note: The purpose of `examples/host_vars.yml` is to provide configuration objects that are custom to new F5 cofiguration"*

As you can see in `examples/host_vars.yml` you can also provide some details for generating network configuration. This can generate network related configuration too.

The script is moduler (divided into 4 stages) and hence can be enhanced/customized very easily.

1. Extract the configuration objects and store it in JSON objects. (will be stored at `./runtime_vars` folder by default)
2. Model the extracted objects per the logic of TMSH commands. (`Creating Data Structure in Yaml ` section in the `alteon-f5-config-converter.py` script)
3. Generate TMSH based configuration based on Jinja templates.
4. Output the generated config and the modeled data. The modeled data can be re-used as input to automation tools such as Ansible.

The script utilized two types of templating engine.

1. TTP based ([Template Text Parser](https://ttp.readthedocs.io/en/latest/index.html)). The extraction from Alteon configuration is done using TTP. These templates can be found under `templates` directory with `.xml` extension.
2. Jinja2 (F5 configuration is generated using this.). These templates can be found under `templates` directory with `.j2` extension.

If you want to customize this tool, you would generally do the following.

1. Fix/Add the TTP templates per your requirements.
2. Fix/Add `Creating Data Structure in Yaml ` section in the `alteon-f5-config-converter.py` script. Keep in mind the modeling is setting the VIP types and VIP types are then used to generate the different types of configuration.
3. Fix Jinja templates per your need.

## Example

`./alteon-f5-config-converter.py examples/device01.cfg examples/host_vars.yml --output_dir examples/output --runtime_vars_dir examples/runtime_vars`

This will convert Alteon based configuration (`examples/device01.cfg`) to `examples/output/device01.cfg` TMSH based config.
It will also store runtime vars into `examples/runtime_vars` directory.
As you can see its also creating network configuration.

### Bonus

This tool can also extract the dump of the Alteon devices. Base script is provided.
However, a detailed parser `alteon-dump-parser` using Ansible is also available.

### Requirements

* ttp (tested with 0.2.0)
* jinja2
* pyyaml
