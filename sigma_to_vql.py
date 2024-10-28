import argparse
import base64
import gzip
import logging
import os
import re
import ruamel.yaml as yaml
from typing import Tuple
from pathlib import Path
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
    select_addon: str


@dataclass
class ArtifactVQL:
    """Used to prepare output VQL"""
    name: str
    author: str
    description: str
    type: str
    sources: list
    export: str


def parse_arguments():
    """Parse/Validate input arguments via argparse - return the output as well as unknown arbitrary arguments as a list[str]"""
    # TODO - Add bool to allow gzip of read rules directly into artifact, removing need for file
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rulesdir", type=str, default="rules",
                        help="Directory containing input Sigma rules to translate into VQL")
    parser.add_argument("-a", "--argsfile", default="arguments.yaml",
                        help="Path to YAML file containing parameter replacements for artifact maps")
    parser.add_argument("-v", "--varsfile", default="variables.yaml",
                        help="Path to YAML file containing variable replacements for sigma rules")
    parser.add_argument("-m", "--mapsdir", default="maps",
                        help="Path to directory containing artifact maps")
    parser.add_argument("-f", "--fieldmapfile", default="field_maps.yaml",
                        help="Path to file containing global field maps")
    parser.add_argument("-o", "--outputdir", default="output",
                        help="Directory where translated VQL and merged rules should be stored")
    parser.add_argument("-i", "--inline", action='store_true',
                        help="GZIPs and Base64 rules to include directly in the VQL instead of a standalone file")
    args, unknown = parser.parse_known_args()
    #args = parser.parse_args()
    if not os.path.exists(args.rulesdir):
        raise Exception(f"Specified Directory Does Not Exist: {args.rulesdir}")
    if not os.path.exists(args.mapsdir):
        raise Exception(f"Specified Directory Does Not Exist: {args.mapsdir}")

    # allows for arbitrary input parameters to be fed into the artifact mapping as a replacement and ultimately
    # be used in the VQL params for specific artifacts
    # For example -DateAfter to replace param DateAfter in relevant artifacts such as Windows.NTFS.MFT
    # Care must be taken to ensure the formatting of these is in-line with artifact expectations as no validation is performed
    # for arg in unknown:
    #    if arg.startswith(("-", "--")):
    #        parser.add_argument(arg.split('=')[0], type=str)

    # args = parser.parse_args()
    return args, unknown


def get_validated_maps(data: list, params: dict) -> list:
    """
    Iterates through all input ArtifactMap to ensure they contain the necessary fields and replace as necessary
    :param params: Script input parameters for replacement to Artifacts
    :param data: List of ArtifactMap objects
    :return: list of validated ArtifactMaps
    """
    required_fields = ["artifact_name", "artifact_subsource", "sigma_logmap", "field_map"]
    # logsources = []
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
        for field in required_map_fields:
            if field not in i["sigma_logmap"]:
                logging.error(f"{i['artifact_name']} missing required sigma_logmap key: {field}, defaulting to *")
                i["sigma_logmap"][field] = "*"
                #map_valid = False
        if map_valid:
            tmp = ArtifactMap(artifact=i["artifact_name"], source=i["artifact_subsource"],
                              category=i["sigma_logmap"]["category"], product=i["sigma_logmap"]["product"],
                              service=i["sigma_logmap"]["service"], fields=i["field_map"], sigmamap=f'{i["sigma_logmap"]["category"]}/{i["sigma_logmap"]["product"]}/{i["sigma_logmap"]["service"]}',
                              sourcename=f"{i['artifact_name']} - {i['artifact_subsource']}", parameters={}, select_addon="")

            # # TODO - Fix this to support wild-card appropriately
            # tmpsource = f"{tmp.category} - {tmp.product} - {tmp.service}"
            # if tmpsource in logsources:
            #     logging.error(f"{i['artifact_name']} has duplicate log source!")
            #     logsources.append(tmpsource)
            # else:
            #     logsources.append(tmpsource)
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
            if "select_addon" in i:
                tmp.select_addon = i["select_addon"]
            validated_maps.append(tmp)
    logging.info(f"Loaded {len(validated_maps)} Validated Artifact Maps")
    return validated_maps


def build_mapping_vql(valid_maps: list) -> dict:
    """
    Receives all valid map objects and builds a dictionary storing name and query for each - helper VQL function
    The 'query' serves as the stub for later completion once sigma rules are loaded/merged
    :param valid_maps:
    :param field_maps:
    :return:
    """
    #  In order to allow multiple artifacts to be defined on the same log-source, we will chain them together like below
    #         SELECT * FROM chain(
    #           a={SELECT * FROM Artifact.Windows.System.Powershell.PSReadline()},
    #           b={SELECT * FROM Artifact.Windows.System.Powershell.ModuleAnalysisCache()},
    #           async=TRUE)
    #         }
    # This means we should first iterate through all maps to find related logsource/map combos since we don't know ahead of time
    combos = {}
    for m in valid_maps:

        if m.sigmamap in combos:
            combos[m.sigmamap].append(m)
        else:
            combos[m.sigmamap] = [m]

    # Now we can iterate through the combinations and then again within to build full artifact chains per source

    mappings = {}
    for c in combos.keys():
        fields = {}
        tmp = {}
        tmp["name"] = c
        tmp["query"] = f"""LET LogSources <= sigma_log_sources(
        `{c}` = {{
        SELECT * FROM chain(
        """
        qidx = 0
        for m in combos[c]:
            if m.fields is not None:
                for k in m.fields.keys():
                    if k in fields:
                        logging.error(f"Field Map Collision - Field '{k}' on Log Source {c}")
                    fields[k] = m.fields[k]
            select_addon = ""
            if m.select_addon != "":
                select_addon = m.select_addon
            tmp["query"] += f"""query_{qidx}={{SELECT *{select_addon} FROM Artifact.{m.artifact}("""
            if m.source is not None:
                tmp["query"] += f"source=\"{m.source}\""
            qidx += 1
            if len(m.parameters) != 0:
                if m.source is not None:
                    tmp["query"] += f","
                length = len(m.parameters)
                idx = 1
                for k in m.parameters.keys():
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
            tmp["query"] += """)},
        """
        tmp["query"] += """async=TRUE)
        }
    )
        """

        tmp["query"] += """
LET LocalFieldMapping <= dict(\n"""
        field_count = len(fields)
        field_idx = 1
        for field in fields.keys():
            tmp["query"] += f"  `{field}`=\"x=>x.{fields[field]}\""
            if field_idx != field_count:
                tmp["query"] += ",\n"
            else:
                tmp["query"] += "\n"
            field_idx += 1
        tmp["query"] += ")\n"
        tmp["query"] += "LET NewFieldMapping <= FieldMapping + LocalFieldMapping\n"
        tmp["query"] += 'SELECT * FROM sigma(rules=split(string=Rules, sep_string="---"),log_sources=LogSources,debug=False,field_mapping=NewFieldMapping)'
        #print(tmp["query"])
        mappings[c] = tmp

#     for m in valid_maps:
#         continue
#         tmp = {}
#         if m.source is not None:
#             tmp["name"] = m.sourcename
#         else:
#             tmp["name"] = m.artifact
#         tmp["query"] = f"""LET LogSources <= sigma_log_sources(
#     `{m.sigmamap}` = {{
#     SELECT * FROM Artifact.{m.artifact}("""
#
#         if m.source is not None:
#             tmp["query"] += f"source=\"{m.source}\""
#         if len(m.parameters) != 0:
#             if m.source is not None:
#                 tmp["query"] += f","
#             length = len(m.parameters)
#             idx = 1
#             for k in m.parameters.keys():
#                 #  TODO - Review and Test
#                 if type(m.parameters[k] is str):
#                     tmp["query"] += f"{k}=\"{m.parameters[k]}\""
#                 elif type(m.parameters[k] is bool):
#                     tmp["query"] += f"{k}={m.parameters[k]}"
#                 else:
#                     # TODO - will this work for ints?
#                     tmp["query"] += f"{k}=\"{m.parameters[k]}\""
#                 if idx != length:
#                     tmp["query"] += ","
#                 idx += 1
#         tmp["query"] += """)
#     }
# )\n"""
#
#         if m.fields is None:
#             m.fields = {}
#         tmp["query"] += "LET FieldMapping <= dict(\n"
#         for field in m.fields.keys():
#             tmp["query"] += f"  {field}=\"x=>x.{m.fields[field]}\"\n"
#         tmp["query"] += ")\n"
#         mappings[m.sigmamap] = tmp
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
    category, product, service = "*", "*", "*"
    if "category" in rule["logsource"]:
        category = rule["logsource"]["category"]
    if "product" in rule["logsource"]:
        product = rule["logsource"]["product"]
    if "service" in rule["logsource"]:
        service = rule["logsource"]["service"]
    logsource = f"{category}\\{product}\\{service}"
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
        tmp_name = f"{category}|{product}|{service}"
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


def build_input_parameters(unknown_arguments: list, arguments_file: str) -> dict:
    """
    Builds a dictionary containing parameters for Artifact invocations
    :param unknown_arguments: list of arbitrary arguments passed in via the command-line
    :param arguments_file: YAML file containing global and artifact-local parameter specifications for easier re-use
    :return: dictionary of parameters for later use when building VQL/ArtifactMaps
    """
    parameters = {}
    for arg in unknown_arguments:
        if arg.startswith(("-", "--")):
            args = arg.split('=', 1)
            if len(args) != 2:
                logging.error(f"Invalid Argument Format - Missing '=' delimiter: {arg}")
                continue
            parameters[args[0]] = args[1]

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
    map_file_list = []
    for root, dirs, files in os.walk(maps_directory):
        for file in files:
            if file.startswith("map_") and file.endswith(".yaml"):
                logging.info(f"Found Map File: {file}")
                map_file_list.append(os.path.join(root, file))
    maps = []
    for i in map_file_list:
        with open(i, "r") as f:
            try:
                count = 0
                data = yaml.safe_load(f)
                if data is None:
                    continue
                for m in data:
                    count += 1
                    maps.append(m)
                logging.info(f"Loaded {count} maps from {i}")
            except yaml.YAMLError as exc:
                logging.error(f"Error Parsing Artifact Map YAML ({i}): {exc}")
    return maps


def get_field_maps(field_map_file: str) -> dict:
    """
    Gets globally available field maps from the specified YAML file
    :param field_map_file:
    :return:
    """
    if not os.path.exists(field_map_file):
        logging.error(f"Specified Field Map File does not exist: {field_map_file}")
        return {}
    with open(field_map_file) as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            logging.error(f"Error Parsing YAML ({field_map_file}): {exc}")
            return {}
    return data


def build_artifact_vql(args, field_maps: dict) -> tuple[ArtifactVQL, str]:
    """
    Builds the artifact stub depending on whether or not we are merging all rules into GZIP export or pointing to a file
    :param args: Script input argparse NameSpace
    :param field_maps: Global field-maps pulled from field_maps.yaml
    :return: ArtifactVQL object containing the appropriate attributes
    """


    field_map_string = """LET FieldMapping <= dict(
"""
    idx = 1
    field_count = len(field_maps)
    for field in field_maps.keys():
        field_map_string += f"  `{field}`=\"x=>x.{field_maps[field]}\""
        if idx != field_count:
            field_map_string += ",\n"
        else:
            field_map_string += """\n)\n"""
        idx += 1

    merged_rules_file = os.path.abspath(os.path.join(args.outputdir, "merged_rules.yaml"))
    # Forward-Slash is a special char in VQL that helps reduce need to escape characters
    artifact_output = ArtifactVQL(
        name="Custom.SigmaToVQL.Merged",
        author="Autogenerated by github.com/joeavanzato/SigmaToVQL",
        description="Defines Sigma Log Sources/Field Mappings and executes relevant rules.",
        type="CLIENT",
        export=f"{field_map_string}\n",
        sources=[])
    return artifact_output, merged_rules_file


def main():
    logging.info("Starting SigmaToVQL...")
    args, unknown_args = parse_arguments()
    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    logging.info(f"Reading Input Parameters...")
    parameters = build_input_parameters(unknown_args, args.argsfile)
    logging.info(f"Reading Global Field Maps...")
    field_maps = get_field_maps(args.fieldmapfile)
    logging.info(f"Reading Artifact Maps...")
    artifact_maps = get_artifact_maps(args.mapsdir)
    if len(artifact_maps) == 0:
        logging.error("No Maps Loaded - Quitting")
        return
    else:
        logging.info(f"Loaded {len(artifact_maps)} Artifact Maps")
    logging.info(f"Building Artifact VQL Stub...")
    artifact_output, merged_rules_file = build_artifact_vql(args, field_maps)
    logging.info(f"Validating Artifact Maps...")
    valid_maps = get_validated_maps(artifact_maps, parameters)
    vql_maps = build_mapping_vql(valid_maps)
    logging.info(f"Reading Sigma Rules...")
    sigma_files = get_input_files("rules")
    validated_rules = validate_rules(sigma_files)
    logging.info(f"Reading Input Variables...")
    variables = read_variables(args.varsfile)
    rule_lists = build_rule_maps(validated_rules, variables)

    if not os.path.exists(args.outputdir):
        os.mkdir(args.outputdir)
    merged_rules_dir = os.path.join(args.outputdir, "merged_rules")
    if not os.path.exists(merged_rules_dir):
        os.mkdir(merged_rules_dir)

    # Merge all Sigma rules associated with a common logmap
    logging.info(f"Merging Sigma Rules...")
    file_key_map = {}
    rules = []
    for k in rule_lists.keys():
        for rule in rule_lists[k]:
            rules.append(rule)
        file_name = f"{k}.yaml"
        file_name = file_name.replace("*", "").replace("|", "_")
        file_path = os.path.join(merged_rules_dir, file_name)
        with open(file_path, "w") as f:
            yaml.dump_all(rule_lists[k], f, default_flow_style=False)
        file_key_map[k] = os.path.abspath(file_path).replace("\\", "\\\\")

    # dump merged output
    logging.info(f"Writing Merged Rule File: {merged_rules_file}")
    with open(merged_rules_file, "w") as f:
        yaml.dump_all(rules, f, default_flow_style=False)

    # Storing rules as a gzip string in export section
    if args.inline:
        logging.info(f"Building GZIP/B64 Rules into VQL")
        rules_data = Path(merged_rules_file).read_text()
        b64_zipped_rules_string = base64.b64encode(gzip.compress(rules_data.encode()))
        artifact_output.export += f"""LET Rules = gunzip(string=base64decode(string=\"{b64_zipped_rules_string.decode("utf-8")}\"))"""
    else:
        # Need to make sure this file is transported to the client along with the artifact
        logging.info(f"Building Rule File Reference into VQL")
        tmp_merged_file = merged_rules_file.replace('\\', '/')
        artifact_output.export += f"""LET Rules = read_file(filename=\"{tmp_merged_file}\", length=10000000)"""

    # This is currently just a validation check to make sure we have a logsource defined for each specified rule
    for key in rule_lists.keys():
        tmp_lookup_key = key.replace("|", "/")
        # Basically we want to iterate through vql_maps to see if there is one that 'matches' this using regex
        match_pattern = tmp_lookup_key.replace("*", ".*")
        match_found = False
        for logsource in vql_maps:
            if re.match(match_pattern, logsource):
                match_found = True
        if not match_found:
            logging.error(f"No Artifact Map matches Rule-Defined logsource: {tmp_lookup_key}")

    # Finalize the VQL 'sources' per logmap
    for k in vql_maps.keys():
        tmp = {
            "name": vql_maps[k]["name"],
            "query": vql_maps[k]["query"]
        }
        # tmp["query"] = LiteralScalarString(vql_maps[k]["query"])
        # REMOVED:We only add sources that have 1 or more rules to not clutter the main VQL
        #if k.replace("/", "|") in rule_lists:
        artifact_output.sources.append(tmp)

    # Generate the final output artifact
    logging.info(f"Generating Artifact Output...")
    artifact_output_path = os.path.join(args.outputdir, "Custom_SigmaToVQL_Merged.yaml")
    with open(artifact_output_path, "w") as f:
        # TODO - Add proper formatter to the class instead of doing it this way
        tmp = {"name": artifact_output.name,
               "author": artifact_output.author,
               "description": artifact_output.description,
               "type": artifact_output.type,
               "sources": artifact_output.sources,
               "export": artifact_output.export
               }
        yaml.dump(tmp, f, default_flow_style=False)
    logging.info(f"Artifact Created: {artifact_output_path}")


main()
