
from pathlib import Path
#TODO: Account for custom profiles
SNMP_PROFILES = Path("../../integrations-core/snmp/datadog_checks/snmp/data/default_profiles")

# Cache for sysObjectID and profiles
_cached_sys_obj_id = "NOT_SET"
_cached_profiles = "NOT_SET"

def parse_snmp_walk():
    ##TODO: Put notice for user to replace file path
    file = "test_snmp_walk.txt"
    oids = {}
    
    # Try different encodings to handle various SNMP walk output formats
    for encoding in ['utf-8', 'utf-16', 'latin-1']:
        try:
            with open(file, "r", encoding=encoding) as f:
                lines = f.readlines()
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"Could not decode {file} with any supported encoding")
    
    current_oid = None
    for line in lines:
        new_line = line.replace("iso", "1")
        if " = " in new_line:
            parts = new_line.split(" = ", 1)
            current_oid = parts[0].lstrip(".")
            oids[current_oid] = parts[1].strip() if len(parts) > 1 else ""
        elif current_oid and new_line.strip():
            oids[current_oid] += " " + new_line.strip()
    
    return oids
    
def find_oid(oid: str):
    snmp_walk = parse_snmp_walk()
    if oid not in snmp_walk:
        print(f"Can't find OID {oid} in SNMP walk")
        return None
    
    raw_oid = snmp_walk.get(oid)
    if "OID:" in raw_oid:
        result = raw_oid.split("OID:")[1].strip()
    else:
        result = raw_oid.strip()
    return result.lstrip(".")

def normalize_sys_id(oid):
    if "#" in oid:
        oid = oid.split("#",1)[0].strip()
    
    sys_obj_id = oid.lstrip("-").strip()

    return sys_obj_id
def build_profile_oid_map():
    profiles =[]
    for file in SNMP_PROFILES.iterdir():
        if file.is_file() and "yaml" in file.name:
            profiles.append(file.name)

    profile_mapper ={}
    for profile in profiles:
        file_path = f"{SNMP_PROFILES}/{profile}"
        with open(file_path, "r") as f:
            for line in f:
                try:
                    if not line.startswith("sysobjectid"):
                        continue
                    parts = line.split(":", 1)
                    oid_list = []
                    # This finds obj ids on the same line
                    if parts[1].strip() != "":
                        oid_list.append(parts[1])
                    else:
                    # Goes through YAML finding all sys-obj-ids 
                    # if more than 1
                        while True:
                            next_line = next(f).strip()
                            if not next_line.startswith("-"):
                                break
                            oid_list.append(next_line)
                except StopIteration:
                     continue 
                oids = []
                for oid in oid_list:
                    normalized_oid = normalize_sys_id(oid)
                    oids.append(normalized_oid)
                profile_mapper[profile] = oids

    return profile_mapper

def match_sys_oid(sys_oid: str, oid: str) -> bool:
    sys_oid = sys_oid.strip()
    oid = oid.strip()

    if oid.endswith("*"):
         # remove the *
        prefix = oid[:-1]
        return sys_oid.startswith(prefix)
    else:
        return sys_oid == oid

def get_sys_obj_id():
    """Get the sysObjectID, prompting user if not found in walk. Caches the result."""
    global _cached_sys_obj_id
    if _cached_sys_obj_id != "NOT_SET":
        return _cached_sys_obj_id
    
    sys_obj_id = find_oid("1.3.6.1.2.1.1.2.0")
    if sys_obj_id is None:
        print("Could not find sysObjectID (1.3.6.1.2.1.1.2.0) in SNMP walk.")
        user_input = input("Enter the sysObjectID manually (or press Enter to skip profile matching): ").strip()
        if user_input:
            # Normalize: strip leading dot if present
            sys_obj_id = user_input.lstrip(".")
    
    _cached_sys_obj_id = sys_obj_id
    return sys_obj_id

def profile_matcher():
    sys_obj_id = get_sys_obj_id()
    if sys_obj_id is None:
        return None
    
    profiles = build_profile_oid_map()
    matching = {}

    for key, oids in profiles.items():
        for oid in oids:
            if match_sys_oid(sys_obj_id, oid):
                matching[key] = (oid)

    profile = select_best_matching_profile(matching)
    return profile
    
def select_best_matching_profile(matching_profiles: dict):
    matching_profile = ""
    default_length = 0
    # Datadog-agent matches profile based on if sysobjid == profile 
    # and if multiple exists then we determine which one is closer in length
    for profile, item in matching_profiles.items():
        if item.endswith("*"):
            oid = item[:-1]
        else:
            oid = item
        if len(oid) >= (default_length):
            default_length = len(oid)
            matching_profile = profile
    return matching_profile

def extract_all_profiles():
    global _cached_profiles
    if _cached_profiles != "NOT_SET":
        return _cached_profiles
    
    profile = profile_matcher()
    if profile is None or profile == "":
        print("No matching profile found. Will output raw SNMP walk data without profile matching.")
        _cached_profiles = []
        return []
    
    default_profile = f"{SNMP_PROFILES}/{profile}"
    extended_profiles = []

    profile_list = []

    with open(default_profile, "r") as f:
        for line in f:
            try:
                if "extends" in line:
                    while True:
                        next_profile = next(f).strip()
                        if not next_profile.startswith("-"):
                            break
                        profile_name = next_profile.split("- ")[1]
                        extended_profiles.append(profile_name)
            except StopIteration:
                 continue
    
    for profile in extended_profiles:
        profile_list.append(f"{SNMP_PROFILES}/{profile}")
    
    profile_list.append(default_profile)

    _cached_profiles = profile_list
    return profile_list

def extract_profile_metrics():
    profile_list = extract_all_profiles()
    metrics = {}

    for profile in profile_list:
        profile_filename = Path(profile).name
        with open(profile, "r") as f:
            for line in f:
                try:
                    if "OID:" not in line:
                        prev_line = line.strip()
                        continue
                    ## TODO: Fix this naming
                    raw_oid = normalize_sys_id(line)
                    if "OID: " not in raw_oid:
                        prev_line = line.strip()
                        continue
                    oid = raw_oid.split("OID: ")[1]
                    # Grab the OID then get the next line for the name
                    next_line = next(f).strip()
                    if next_line.startswith("name:"):
                        metric_name = next_line.split("name: ")[1]
                        metrics[metric_name] = {"oid": oid, "profile": profile_filename}
                    else:
                        # Use the prev line to grab the name
                        try:
                            metric_name = prev_line.split("name: ")[1]
                            metrics[metric_name] = {"oid": oid, "profile": profile_filename}
                        except IndexError:
                            continue
                except StopIteration:
                            continue 
    
    return metrics

def map_walk_to_metrics():
    profile_metrics = extract_profile_metrics()
    snmp_walk = parse_snmp_walk()

    metrics = {}
    for oid, value in snmp_walk.items():
        interface = oid.split(".")[-1]
        base_oid = oid.rsplit('.', 1)[0]
        
        # Check if oid matches any profile metric
        matched = False
        for k, v in profile_metrics.items():
            if base_oid in v["oid"]:
                metric_name = k
                found_in = v["profile"]
                matched = True
                break
        
        if not matched:
            found_in = "N/A"
            metric_name = "N/A"
        
        metric_data = [metric_name, base_oid, interface, value, found_in]
        metrics[oid] = metric_data

    return metrics

def write_metrics_to_file():
    metrics = map_walk_to_metrics()
    profiles = extract_all_profiles()
    file = "test.txt"
    sys_obj_id = get_sys_obj_id()

    with open("test.txt", "w") as f:
        f.write(f"Profiles Found for Sys Obj ID: {sys_obj_id}\n")
        for profile in profiles:
            profile_filename = Path(profile).name
            f.write(profile_filename)
            f.write("\n")
        f.write("\n")
        f.write("Metric Name | OID | Interface | Value | Found In Profile\n")

    with open(file, "a") as f:
        for _, metric_data in metrics.items():
            metric_name, oid, interface, value, found_in = metric_data
            f.write(
                f"{metric_name} | {oid} | {interface} | {value} | {found_in}\n"
            )
    
    print(file, "created")

write_metrics_to_file()
