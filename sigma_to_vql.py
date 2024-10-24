import argparse
import logging
import os
import re
import ruamel.yaml as yaml
from dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("SigmaToVQL.log"),
        logging.StreamHandler()
    ]
)


@dataclass
class ArtifactMap:
    """Stores each read artifact map from artifact_map.yaml in an easy-to-reference object"""
    artifact: str
    source: str
    category: str
    product: str
    service: str
    fields: dict
    sigmamap: str
    sourcename: str
    parameters: dict


@dataclass
class ArtifactVQL:
    """Used to prepare output VQL"""
    name: str
    author: str
    description: str
    type: str
    sources: list


def parse_arguments():
    """Parse/Validate input arguments via argparse - return the output as well as unknown arbitrary arguments as a list[str]"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rules", type=str, default="rules", help="Directory containing input Sigma rules to translate into VQL")
    parser.add_argument("-a", "--args", type=str, default="arguments.yaml", help="Path to YAML file containing parameter replacements for artifact maps")
    parser.add_argument("-v", "--vars", type=str, default="variables.yaml", help="Path to YAML file containing variable replacements for sigma rules")
    parser.add_argument("-m", "--maps", type=str, default="maps", help="Path to directory containing artifact maps")
    parser.add_argument("-o", "--output", type=str, default="output", help="Directory where translated VQL and merged rules should be stored")
    args, unknown = parser.parse_known_args()
    if not os.path.exists(args.rules) or not os.path.exists(args.maps):
        raise Exception(f"Specified Directory Does Not Exist: {args.rules}")

    # allows for arbitrary input parameters to be fed into the artifact mapping as a replacement and ultimately
    # be used in the VQL params for specific artifacts
    # For example -DateAfter to replace param DateAfter in relevant artifacts such as Windows.NTFS.MFT
    # Care must be taken to ensure the formatting of these is in-line with artifact expectations as no validation is performed
    # for arg in unknown:
    #    if arg.startswith(("-", "--")):
    #        parser.add_argument(arg.split('=')[0], type=str)

    # args = parser.parse_args()
    return args, unknown


def get_validated_maps(data: list, params) -> list:
    """
    Iterates through all input ArtifactMap to ensure they contain the necessary fields and replace as necessary
    :param params: Script input parameters for replacement to Artifacts
    :param data: List of ArtifactMap objects
    :return: list of validated ArtifactMaps
    """
    required_fields = ["artifact_name", "artifact_subsource", "sigma_logmap", "field_map"]
    validated_maps = []
    for i in data:
        map_valid = True
        for field in required_fields:
            if field not in i:
                logging.error(f"Map missing required field: {field} - {i}")
                map_valid = False
        if not map_valid:
            continue
        required_map_fields = ["category", "product", "service"]
        for category in required_map_fields:
            if category not in i["sigma_logmap"]:
                logging.error(f"{i['artifact_name']} missing required sigma_logmap key: {category}")
                map_valid = False
        if map_valid:
            tmp = ArtifactMap(artifact=i["artifact_name"], source=i["artifact_subsource"],
                              category=i["sigma_logmap"]["category"], product=i["sigma_logmap"]["product"],
                              service=i["sigma_logmap"]["service"], fields=i["field_map"], sigmamap=f'{i["sigma_logmap"]["category"]}/{i["sigma_logmap"]["product"]}/{i["sigma_logmap"]["service"]}',
                              sourcename=f"{i['artifact_name']} - {i['artifact_subsource']}", parameters={})
            if "parameters" in i:
                for k in i["parameters"].keys():
                    if k in params:
                        # If the artifact map has an input parameter, and we specify it at the command-line, replace it
                        if params[k] == "True":
                            params[k] = True
                        elif params[k] == "False":
                            params[k] = False
                        tmp.parameters[k] = params[k]
                if tmp.artifact in params:
                    for k, v in params[tmp.artifact].items():
                        tmp.parameters[k] = v
            validated_maps.append(tmp)
    return validated_maps


def build_mapping_vql(valid_maps: list) -> dict:
    """
    Receives all valid map objects and builds a dictionary storing name and query for each - helper VQL function
    The 'query' serves as the stub for later completion once sigma rules are loaded/merged
    :param valid_maps:
    :return:
    """
    mappings = {}
    for m in valid_maps:
        tmp = {}
        if m.source is not None:
            tmp["name"] = m.sourcename
        else:
            tmp["name"] = m.artifact
        tmp["query"] = f"""LET LogSources <= sigma_log_sources(
    `{m.sigmamap}` = {{
    SELECT * FROM Artifact.{m.artifact}("""

        if m.source is not None:
            tmp["query"] += f"source=\"{m.source}\""
        if len(m.parameters) != 0:
            if m.source is not None:
                tmp["query"] += f","
            length = len(m.parameters)
            idx = 1
            for k in m.parameters.keys():
                #  TODO - Review and Test
                if type(m.parameters[k] is str):
                    tmp["query"] += f"{k}=\"{m.parameters[k]}\""
                elif type(m.parameters[k] is bool):
                    tmp["query"] += f"{k}={m.parameters[k]}"
                else:
                    # TODO - will this work for ints?
                    tmp["query"] += f"{k}=\"{m.parameters[k]}\""
                if idx != length:
                    tmp["query"] += ","
                idx += 1
        tmp["query"] += """)
    }
)\n"""

        if m.fields is None:
            m.fields = {}
        tmp["query"] += "LET FieldMapping <= dict(\n"
        for field in m.fields.keys():
            tmp["query"] += f"  {field}=\"x=>x.{m.fields[field]}\"\n"
        tmp["query"] += ")\n"
        mappings[m.sigmamap] = tmp
    return mappings


def get_input_files(rules_directory: str) -> list:
    """
    Retrieves all YAML files inside the specified input directory recursively
    :param rules_directory: Directory to check for YAML input files
    :return: Returns list of fully-qualified file paths for all YAML files
    """
    output_list = []
    for root, dirs, files in os.walk(rules_directory):
        for file in files:
            if file.endswith(".yaml"):
                output_list.append(os.path.join(root, file))
    return output_list


def validate_rules(rule_files: list) -> list:
    """
    Validate Sigma rules to ensure required fields are present and not malformed
    :param rule_files: List of individual Sigma Rules
    :return: Returns a validated list of Sigma rules, discarding those that are invalid
    """
    # TODO - PySigma Rule Validation
    rules = []
    for file in rule_files:
        with open(file) as f:
            try:
                # data = yaml.safe_load(f)
                documents = yaml.safe_load_all(f)
            except yaml.YAMLError as exc:
                logging.error(f"Error Parsing YAML ({file}): {exc}")
                continue
            for d in documents:
                rules.append(d)

    return rules


def replace_variables(rule: dict, variables: dict) -> dict:
    """
    Replace any known-variables that appear in rule detection logic
    :param rule: Dictionary representing the currently inspected Sigma rule
    :param variables: Dictionary representing known global and artifact-local variables
    :return:
    """
    # Currently variables are represented as '$var_NAME$
    var_pattern = re.compile("^%.*%$")
    logsource = f"{rule['logsource']['category']}\\{rule['logsource']['product']}\\{rule['logsource']['service']}"
    for k in rule["detection"].keys():
        if k in "condition":
            continue
        for key, v in rule["detection"][k].items():
            if type(v) is not str:
                continue
            if var_pattern.match(v):
                # We are facing a variable - do we have a replacement?
                var_name = v.strip("%")
                var_found = False
                if var_name in variables:
                    rule["detection"][k][key] = variables[var_name]
                    var_found = True
                    logging.info(f"Replaced Variable [global] - {rule['title']}, Variable: {var_name}")
                if logsource in variables:
                    if var_name in variables[logsource]:
                        rule["detection"][k][key] = variables[logsource][var_name]
                        var_found = True
                        logging.info(f"Replaced Variable [local] - {rule['title']}, Variable: {var_name}")
                if not var_found:
                    logging.error(f"Rule using undefined Variable - {rule['title']}, Variable: {var_name}")

    return rule


def read_variables(variable_file: str) -> dict:
    """Reads all variables into a dict - globals are stored standalone while locals are stored under their appropriate key
    :param variable_file: File where variable configurations are stored
    :return: dictionary containing key->value variable maps for global and logsource local replacements
    """
    variables = {}
    if os.path.exists(variable_file):
        with open(variable_file) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                logging.error(f"Error Parsing Variable File YAML ({variable_file}): {exc}")
                return variables
        for k in data["global"]:
            variables[k] = data["global"][k]
        for k in data["local"]:
            if len(data["local"][k]) != 0:
                variables[k] = {}
                for key in data["local"][k]:
                    variables[k][key] = data["local"][k][key]
    else:
        logging.info(f"Specified Variable File ({variable_file}) does not exist!")
    logging.info(f"Loaded {len(variables)} Variables")
    return variables


def build_rule_maps(rules: list, variables: dict) -> dict:
    """
    Builds a dictionary that contains a map of logsource -> related Sigma rules
    :param rules: list of validated Sigma rules
    :param variables: list of variables used to replace in-line any global or logsource local variables
    :return:
    """
    # Iterate rules and merge them into separate lists based on category/product/service combination
    rule_lists = {}
    for rule in rules:
        rule = replace_variables(rule, variables)
        category = "*"
        product = "*"
        service = "*"
        if "category" in rule["logsource"]:
            category = rule["logsource"]["category"]
        if "product" in rule["logsource"]:
            product = rule["logsource"]["product"]
        if "service" in rule["logsource"]:
            service = rule["logsource"]["service"]
        tmp_name = f"{category}_{product}_{service}"
        if tmp_name in rule_lists:
            rule_lists[tmp_name].append(rule)
        else:
            rule_lists[tmp_name] = [rule]
    return rule_lists


def str_presenter(dumper, data):
    """Helper function to help handle block display of strings without tags being present"""
    if len(data.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


def build_input_parameters(unknown_arguments, arguments_file) -> dict:
    """
    Builds a dictionary containing parameters for Artifact invocations
    :param unknown_arguments: list of arbitrary arguments passed in via the command-line
    :param arguments_file: YAML file containing global and artifact-local parameter specifications for easier re-use
    :return: dictionary of parameters for later use when building VQL/ArtifactMaps
    """
    parameters = {}
    parser = argparse.ArgumentParser()
    for arg in unknown_arguments:
        if arg.startswith(("-", "--")):
            parser.add_argument(arg.split('=')[0], type=str)
    args = parser.parse_args()
    for k in vars(args):
        parameters[k] = vars(args)[k]

    if os.path.exists(arguments_file):
        with open(arguments_file, "r") as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                logging.error(f"Error Parsing Arguments YAML ({arguments_file}): {exc}")
                return parameters

        for k in data["global"].keys():
            # Command-Line overrides the arguments file if both exist
            if k not in parameters:
                parameters[k] = data["global"][k]

        if "local" in data:
            if data["local"] is not None:
                for k in data["local"]:
                    parameters[k] = {}
                    for p in data["local"][k]:
                        parameters[k][p] = data["local"][k][p]
    logging.info(f"Loaded {len(parameters)} Parameters")
    return parameters


def get_artifact_maps(maps_directory: str) -> list:
    """
    Reads the specified directory to find all YAML files - each of which should contain 1 or more artifact maps
    :param maps_directory: string representing the fully-qualified directory containing artifact maps
    :return: returns a list of dicts, each of which represents a raw artifact map
    """
    # TODO - Check for logsource collisions - each map should have a unique combination
    map_file_list = []
    for root, dirs, files in os.walk(maps_directory):
        for file in files:
            if file.endswith(".yaml"):
                logging.info(f"Found Map File: {file}")
                map_file_list.append(os.path.join(root, file))
    maps = []
    for i in map_file_list:
        with open(i, "r") as f:
            try:
                count = 0
                data = yaml.safe_load(f)
                for m in data:
                    count += 1
                    maps.append(m)
                logging.info(f"Loaded {count} maps from {i}")
            except yaml.YAMLError as exc:
                logging.error(f"Error Parsing Artifact Map YAML ({i}): {exc}")
    return maps


def main():
    logging.info("Starting SigmaToVQL...")
    args, unknown_args = parse_arguments()
    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    logging.info(f"Reading Input Parameters...")
    parameters = build_input_parameters(unknown_args, args.args)
    logging.info(f"Reading Artifact Maps...")
    artifact_maps = get_artifact_maps(args.maps)
    if len(artifact_maps) == 0:
        logging.error("No Maps Loaded - Quitting")
        return
    else:
        logging.info(f"Loaded {len(artifact_maps)} Artifact Maps")

    artifact_output = ArtifactVQL(name="Custom.SigmaToVQL.Merged",
                                  author="Autogenerated by github.com/joeavanzato/SigmaToVQL",
                                  description="Defines Sigma Log Sources/Field Mappings and executes relevant queries on a Velociraptor Client",
                                  type="CLIENT",
                                  sources=[])

    logging.info(f"Validating Artifact Maps...")
    valid_maps = get_validated_maps(artifact_maps, parameters)
    vql_maps = build_mapping_vql(valid_maps)
    logging.info(f"Reading Sigma Rules...")
    sigma_files = get_input_files("rules")
    validated_rules = validate_rules(sigma_files)
    logging.info(f"Reading Input Variables...")
    variables = read_variables(args.vars)
    rule_lists = build_rule_maps(validated_rules, variables)

    if not os.path.exists(args.output):
        os.mkdir(args.output)
    merged_rules_dir = os.path.join(args.output, "merged_rules")
    if not os.path.exists(merged_rules_dir):
        os.mkdir(merged_rules_dir)

    # Merge all Sigma rules associated with a common logmap
    logging.info(f"Merging Sigma Rules...")
    file_key_map = {}
    for k in rule_lists.keys():
        file_name = f"{k}.yaml"
        file_path = os.path.join(merged_rules_dir, file_name)
        with open(file_path, "w") as f:
            yaml.dump_all(rule_lists[k], f, default_flow_style=False)
        file_key_map[k.replace("_", "/")] = os.path.abspath(file_path).replace("\\", "\\\\")

    # Prepare the individual source queries on a per-logmap basis
    for key in rule_lists.keys():
        tmp_lookup_key = key.replace("_", "/")
        if tmp_lookup_key not in vql_maps:
            logging.error(f"No Artifact Map for Defined logsource: {tmp_lookup_key}")
            continue
        vql_maps[tmp_lookup_key]["query"] += f"LET RulePath = \"{file_key_map[tmp_lookup_key]}\"\n"
        vql_maps[tmp_lookup_key]["query"] += f"LET Rules = read_file(filename=RulePath, length=10000000)\n"
        vql_maps[tmp_lookup_key]["query"] += 'SELECT * FROM sigma(rules=split(string=Rules, sep_string="---"),log_sources=LogSources,debug=False,field_mapping=FieldMapping)'

    # Finalize the VQL 'sources' per logmap
    for k in vql_maps.keys():
        tmp = {
            "name": vql_maps[k]["name"],
            "query": vql_maps[k]["query"]
        }
        # tmp["query"] = LiteralScalarString(vql_maps[k]["query"])
        # We only add sources that have 1 or more rules to not clutter the main VQL
        if k.replace("/", "_") in rule_lists:
            artifact_output.sources.append(tmp)

    # Generate the final output artifact
    logging.info(f"Generating Artifact Output...")
    artifact_output_path = os.path.join(args.output, "Custom_SigmaToVQL_Merged.yaml")
    with open(artifact_output_path, "w") as f:
        # TODO - Add proper formatter to the class instead of doing it this way
        tmp = {"name": artifact_output.name,
               "author": artifact_output.author,
               "description": artifact_output.description,
               "type": artifact_output.type,
               "sources": artifact_output.sources
               }
        yaml.dump(tmp, f, default_flow_style=False)
    logging.info(f"Artifact Created: {artifact_output_path}")


main()
