# Fix 1.3

import os
import struct
import argparse
import shutil
import re
import time
import zipfile
from pathlib import Path
import sys
from dataclasses import dataclass
from typing import Dict, List, Tuple

@dataclass
class RemapData:
    character: str
    indices: List[int]

@dataclass
class HashMap:
    old_vs_new: Dict[str, Dict[str, str]]
    old_vs_new13: Dict[str, Dict[str, str]]

old_vs_new = {
    "Verina": {
        "83ced9f7": "82aa82e1"
    },
    "ChangLi": {
        "d8decbca": "1ccb8008",
        "fd9483ca": "060f5303",
        "8f067708": "f23483e3",
        "c79a4ccb": "225aad5a",
        "77975500": "5f8aac45"
    },
    "Rover (Female)": {
        "be84b775": "e8b5a730"
    },
    "Rover (Male)": {
        "d53c2cc7": "c9db8418",
        "f8375eb4": "3ab7c4d1",
        "6e2f48ba": "a4be44e5"
    },
    "Yinlin": {
        "86b95122": "00120eee",
        "148a83c6": "33d00a20",
        "750390fa": "584b7755",
        "9ebf7cad": "5065eae3",
        "e56f82b1": "e50849e0",
        "76967821": "9ea4dc96",
        "1f0f6dc8": "58b06268",
        "30053482": "87bbb0c1"
    },
    "Baizhi": {
        "37bed36b": "718456ac",
        "52c9b804": "d7756134"
    },
    "Calcharo": {
        "8b43ad38": "f3e04a65",
        "cb23f0b5": "52197a16",
        "f657b0b8": "8a7d6de5"
    },
    "Jiyan": {
        "b05fac63": "9631335c",
        "1b3a68de": "7741698a"
    }
}

old_vs_new13 = {
    "YangYan": {
        "77fe24ce": "d25b9648",
        "edf438d9": "3bd37212",
        "95caeb9c": "250c59b6",
        "123bcc8e": "fba3de34",
        "bd8fff82": "c3b2a42e",
        "f42c4870": "8e27c9a2",
        "69c48be0": "1a9b9391",
        "92d4ad47": "49b790e0",
        "16f9802d": "ae886086",
        "fc40048f": "250c59b6",
        "b487d389": "6905a9bd",
        "1607589b": "02e9009d"
    },
    "Chixia": {
        "eee73787": "ab72381e",
        "435d999a": "aeb47e33",
        "45e0cedb": "7988637b",
        "489b5f2a": "94afca13",
        "cb974015": "94d10f56",
        "ba246036": "873ca04e",
        "4a2657d7": "a7141c04"
    },
    "Jianxin": {
        "80f8caf9": "e9f8341f",
        "affc2fc3": "82d39ecb",
        "ead048c8": "068dd115"
    },
    "Rover (Female)": {
        "63d590db": "c0ca0958"
    },
    "Verina": {
        "2d5b41f6": "372bd73a",
        "fd892e3c": "953daba7"
    },
    "Sanhua": {
        "2584190a": "cef6494f",
        "28708ab8": "0bd3b5ab",
        "5efe7892": "89ba19a1",
        "11b9cadd": "f0713dc7"
    },
    "Rover (Male)": {
        "f16d5dae": "a1c0d97c"
    },
    "Yinlin": {
        "00120eee": "86b95122",
        "584b7755": "750390fa",
        "87bbb0c1": "30053482",
        "9ea4dc96": "76967821",
        "58b06268": "1f0f6dc8",
        "71525c2a": "7d1b007a",
        "e50849e0": "e56f82b1",
        "3271530d": "5f0fbdb9"
    }
}

hash_maps = HashMap(old_vs_new, old_vs_new13)

remaps = {
    "83ced9f7": RemapData("Verina", [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 41, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
        109, 110, 111, 77, 112, 113, 115, 114, 116, 117, 118, 119, 120, 121,
        122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
        136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
        150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
        164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 178, 177, 174, 175,
        176, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
        192, 193, 194]),
    "d8decbca": RemapData("ChangLi", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
                66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
                90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
                112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
                134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157,
                158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
                182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
                208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
                235, 236, 237, 252, 238, 257, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 258, 259, 260,
                261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 277, 278, 279, 280]),
}

def log_message(log, message):
    log.append(message)
    print(message)

def create_backup(file_path, ini_file=False):
    backup_name = ('DISABLED ' if ini_file else '') + os.path.basename(file_path) + '.bak'
    backup_path = os.path.join(os.path.dirname(file_path), backup_name)
    shutil.copy2(file_path, backup_path)
    return backup_path

def collect_ini_files(folder_path: str) -> List[str]:
    print("\nCollecting ini files, please wait...")
    ini_files = []
    exclude_keywords = {'desktop', 'ntuser', 'disabled_backup', "disabled"}

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith('.ini'):
                # Check the filename (not the full path) for exclude keywords
                if not any(keyword in file.lower() for keyword in exclude_keywords):
                    file_path = os.path.join(root, file)
                    ini_files.append(file_path)

    print(f"Found {len(ini_files)} ini files.")
    return ini_files

def extract_texture_from_zip(textures_folder, texture_name):
    try:
        root_path = Path(sys._MEIPASS).resolve()
    except Exception:
        root_path = Path().resolve()

    zip_path = root_path / 'FixTexture.zip'

    extracted_path = None
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extract(texture_name, textures_folder)
        extracted_path = os.path.join(textures_folder, texture_name)

    return extracted_path

def apply_lightmap_fix(file_path):
    log = []
    file_modified = False

    try:
        with open(file_path, 'r', encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        texture_to_extract = None
        for line in lines:
            if line.strip().startswith("filename"):
                if "435d999a" in line:
                    new_line = "filename = Textures/FixFaceLightmap t=aeb47e33.dds\n"
                    new_lines.append(new_line)
                    file_modified = True
                    texture_to_extract = "FixFaceLightmap t=aeb47e33.dds"
                elif "28708ab8" in line:
                    new_line = "filename = Textures/FixFaceLightMapSanhua t=0bd3b5ab.dds\n"
                    new_lines.append(new_line)
                    file_modified = True
                    texture_to_extract = "FixFaceLightMapSanhua t=0bd3b5ab.dds"
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        if file_modified and texture_to_extract:
            textures_folder = os.path.join(os.path.dirname(file_path), 'Textures')
            if not os.path.exists(textures_folder):
                os.makedirs(textures_folder)

            extracted_path = extract_texture_from_zip(textures_folder, texture_to_extract)
            if extracted_path:
                log_message(log, f"Extracted texture: {os.path.basename(extracted_path)}")

            with open(file_path, 'w', encoding="utf-8") as f:
                f.writelines(new_lines)
            log_message(log, f'Applying lightmap fix to: {os.path.basename(file_path)}')
        else:
            log_message(log, f'File: {os.path.basename(file_path)} had no matches for lightmap fix. Skipping')

    except Exception as e:
        log_message(log, f'Error processing file: {os.path.basename(file_path)}')
        log_message(log, str(e))

    return log, file_modified

def apply_hash_fix(folder_path):
    log = []
    processed_files_count = 0
    ini_files = collect_ini_files(folder_path)

    if not ini_files:
        log_message(log, "No .ini files found. Make sure you're in the correct directory.")
        return log, processed_files_count, 0

    for file_path in ini_files:
        try:
            log_message(log, f"Processing INI file: {file_path}")

            # Apply lightmap fix
            lightmap_log, lightmap_modified = apply_lightmap_fix(file_path)
            log.extend(lightmap_log)

            with open(file_path, 'r', encoding="utf-8") as f:
                s = f.read()
            meshes_folder = os.path.join(os.path.dirname(file_path), 'Meshes')
            if not os.path.exists(meshes_folder):
                log_message(log, f'Meshes folder not found in directory: {os.path.dirname(file_path)}')
                continue

            blend_files = [blend_file for blend_file in os.listdir(meshes_folder)
                           if os.path.isfile(os.path.join(meshes_folder, blend_file)) and
                           "blend" in blend_file.lower() and ".buf" in blend_file.lower()]

            file_modified = lightmap_modified
            for remap_key, vg_remap in remaps.items():
                if remap_key in s:
                    if not blend_files:
                        log_message(log, f'No blend file found for {vg_remap.character} in folder: {meshes_folder}')
                        continue

                    log_message(log, f'Found blend files for {vg_remap.character}. Applying remap...')
                    for blend_file in blend_files:
                        blend_file_path = os.path.join(meshes_folder, blend_file)
                        try:
                            with open(blend_file_path, "rb") as g:
                                blend_data = g.read()
                                remap_data = remap(blend_data, vg_remap.indices)
                            with open(blend_file_path, "wb") as g:
                                g.write(remap_data)
                                log_message(log, f"File: {blend_file} VGs remapped successfully!")
                            file_modified = True
                        except Exception as e:
                            log_message(log, f'Error remapping file: {blend_file}')
                            log_message(log, str(e))
                            continue

            jianxin_hashes_found = False
            for version, hash_map in [("1.2", hash_maps.old_vs_new), ("1.3", hash_maps.old_vs_new13)]:
                version_modified = False
                for character, mappings in hash_map.items():
                    for old, new in mappings.items():
                        pattern = rf'^hash\s*=\s*{re.escape(old.lower())}'
                        matches = re.findall(pattern, s, re.MULTILINE | re.IGNORECASE)
                        occurrences = len(matches)

                        if occurrences > 0:
                            s = re.sub(pattern, f'hash = {new.lower()}', s, flags=re.MULTILINE | re.IGNORECASE)
                            if old == "435d999a":
                                log_message(log, f'Found {old} ({occurrences} valid occurrences) ------> Match! to {new} for Yinlin, YangYan, Chixia, Yinlin!')
                            else:
                                log_message(log, f'Found {old} ({occurrences} valid occurrences) ------> Match! to {new} for {character}!')
                            file_modified = True
                            version_modified = True
                            if character == "Jianxin" and old in ["affc2fc3", "ead048c8"]:
                                jianxin_hashes_found = True
                        elif re.search(rf'^hash\s*=\s*{re.escape(new.lower())}', s, re.MULTILINE | re.IGNORECASE):
                            new_occurrences = len(re.findall(rf'^hash\s*=\s*{re.escape(new.lower())}', s, re.MULTILINE | re.IGNORECASE))
                            if old == "435d999a":
                                log_message(log, f'Found {new} ({new_occurrences} valid occurrences) ------> Already remapped for Yinlin, YangYan, Chixia, Yinlin!')
                            else:
                                log_message(log, f'Found {new} ({new_occurrences} valid occurrences) ------> Already remapped for {character}!')
                            if character == "Jianxin" and old in ["affc2fc3", "ead048c8"]:
                                jianxin_hashes_found = True

            # Special handling for Jianxin Shapekey sum, thank you Spectrum :3
            if jianxin_hashes_found:
                lines = s.split('\n')
                shapekey_line_found = False
                for i, line in enumerate(lines):
                    if line.strip().startswith("$\\WWMIv1\\shapekey_checksum"):
                        lines[i] = "$\\WWMIv1\\shapekey_checksum = 1876"
                        log_message(log, f'Updated shapekey_checksum for Jianxin')
                        file_modified = True
                        shapekey_line_found = True
                        break
                if not shapekey_line_found:
                    log_message(log, f'Warning: shapekey_checksum line not found for Jianxin')
                s = '\n'.join(lines)

            if file_modified:
                backup_ini = create_backup(file_path, ini_file=True)
                log_message(log, f"Backup created: {backup_ini}")
                with open(file_path, 'w', encoding="utf-8") as f:
                    f.write(s)
                log_message(log, f'File: {os.path.basename(file_path)} has been modified!')
                processed_files_count += 1
            else:
                log_message(log, f'File: {os.path.basename(file_path)} had no matches. Skipping')

        except Exception as e:
            log_message(log, f'Error processing file: {os.path.basename(file_path)}')
            log_message(log, str(e))
            continue
        log_message(log, "=" * 70)

    return log, processed_files_count, len(ini_files)

def remap_verina(folder_path):
    return apply_hash_fix(folder_path)

def remap(blend_data, new_order, stride=8):
    if len(blend_data) % stride != 0:
        raise ValueError("Invalid blend file length")

    remapped_blend = bytearray()

    for i in range(0, len(blend_data), stride):
        blendindices = struct.unpack_from("<BBBB", blend_data, i)
        blendweights = blend_data[i + 4:i + 8]

        outputindices = bytearray()
        for index in blendindices:
            remapped_index = new_order[index] if index < len(new_order) else index
            outputindices.append(remapped_index)

        remapped_blend += outputindices + blendweights

    if len(remapped_blend) != len(blend_data):
        raise ValueError("Remapped blend file is invalid")

    return remapped_blend

def force_remap(folder):
    '''Force remap a character based on the remap options.'''
    log = []
    processed_files_count = 0
    log_message(log, 'Remap options:')
    for i, (k, v) in enumerate(remaps.items()):
        log_message(log, f'{i+1}: {v.character}')

    while True:
        try:
            option = int(input('Select a character to remap: ')) - 1
            if 0 <= option < len(remaps):
                break
            print('Invalid option')
        except ValueError:
            print('Invalid option')

    option_key = list(remaps.keys())[option]

    for root, dirs, files in os.walk(folder):
        blend_files = [os.path.join(root, file) for file in files if file.lower().endswith(('.blend.buf', '.blend.buf.bak'))]
        if not blend_files:
            log_message(log, f"No blend files found in folder: {root}")
            continue

        # Check if there's any .bak file in the current folder
        bak_files = [f for f in files if f.endswith('.bak')]
        if bak_files:
            log_message(log, f'Found .bak files in {root}. Skipping remapping for this folder.')
            continue

        for blend_file in blend_files:
            try:
                backup_file = create_backup(blend_file)
                log_message(log, f"Backup created: {backup_file}")

                with open(blend_file, "rb") as g:
                    blend_data = g.read()
                    remap_data = remap(blend_data, remaps[option_key].indices)
                with open(blend_file, "wb") as g:
                    g.write(remap_data)
                log_message(log, f"File: {os.path.basename(blend_file)} VGs remapped successfully!")
                processed_files_count += 1
            except Exception as e:
                log_message(log, f'Error processing file: {os.path.basename(blend_file)}')
                log_message(log, str(e))

    return log, processed_files_count, len(blend_files)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--force_remap', action='store_true', default=False)
    args = parser.parse_args()
    folder_path = os.getcwd()
    start_time = time.time()
    if args.force_remap:
        log, processed_files_count, total_files = force_remap(folder_path)
    else:
        log, processed_files_count, total_files = remap_verina(folder_path)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nProcessing took {elapsed_time:.2f} seconds")
    print(f"Total files found: {total_files}")
    print(f"Processed {processed_files_count} files")

    input('Press Enter to exit...')
