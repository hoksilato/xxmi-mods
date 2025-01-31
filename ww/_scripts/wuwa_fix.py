#Fix 1.2 + Verina REMAP

import os
import struct
import argparse
import shutil
import re

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

remaps = {
    "83ced9f7": ('Verina', [
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
    "d8decbca": ("Changli",[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
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

def create_backup(file_path, ini_file=False):
    if ini_file:
        backup_name = 'DISABLED ' + os.path.basename(file_path) + '.bak'
    else:
        backup_name = os.path.basename(file_path) + '.bak'
    backup_path = os.path.join(os.path.dirname(file_path), backup_name)
    shutil.copy2(file_path, backup_path)
    return backup_path

def remap_verina(folder_path):
    log = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path) and file.lower().endswith('.ini') and file.lower() != 'desktop.ini':
                try:
                    log_message(log, f"Processing INI file: {file_path}")

                    with open(file_path, 'r', encoding="utf-8") as f:
                        s = f.read()
                        old_stream = s

                    meshes_folder = os.path.join(root, 'Meshes')
                    if not os.path.exists(meshes_folder):
                        log_message(log, f'Meshes folder not found in directory: {root}')
                        continue

                    blend_files = [blend_file for blend_file in os.listdir(meshes_folder)
                                   if os.path.isfile(os.path.join(meshes_folder, blend_file)) and
                                   "blend" in blend_file.lower() and ".buf" in blend_file.lower()]

                    for remap_key, vg_remap in remaps.items():
                        if remap_key in s:
                            if not blend_files:
                                log_message(log, f'No blend file found for {vg_remap[0]} in folder: {meshes_folder}')
                                continue

                            log_message(log, f'Found blend files for {vg_remap[0]}. Applying remap...')
                            for blend_file in blend_files:
                                blend_file_path = os.path.join(meshes_folder, blend_file)
                                backup_blend = create_backup(blend_file_path)
                                log_message(log, f"Backup created: {backup_blend}")

                                try:
                                    with open(blend_file_path, "rb") as g:
                                        blend_data = g.read()
                                        remap_data = remap(blend_data, vg_remap[1])
                                    with open(blend_file_path, "wb") as g:
                                        g.write(remap_data)
                                        log_message(log, f"File: {blend_file} VGs remapped successfully!")
                                except Exception as e:
                                    log_message(log, f'Error remapping file: {blend_file}')
                                    log_message(log, str(e))
                                    continue

                    modified = False
                    for character, mappings in old_vs_new.items():
                        for old, new in mappings.items():
                            pattern = rf'^hash\s*=\s*{re.escape(old.lower())}'
                            matches = re.findall(pattern, s, re.MULTILINE)
                            occurrences = len(matches)

                            if occurrences > 0:
                                s = re.sub(pattern, f'hash = {new.lower()}', s, flags=re.MULTILINE)
                                log_message(log, f'Found {old} ({occurrences} valid occurrences) ------> Match! to {new} for {character}!')
                                modified = True
                            elif new in s:
                                log_message(log, f'Found {new} ------> Already remapped for {character}!')

                    if modified:
                        backup_ini = create_backup(file_path, ini_file=True)
                        log_message(log, f"Backup created: {backup_ini}")
                        with open(file_path, 'w', encoding="utf-8") as f:
                            f.write(s)
                        log_message(log, f'File: {os.path.basename(file_path)} has been modified!')
                    else:
                        log_message(log, f'File: {os.path.basename(file_path)} had no matches. Skipping')

                except Exception as e:
                    log_message(log, f'Error processing file: {os.path.basename(file_path)}')
                    log_message(log, str(e))
                    continue
                log_message(log, "=" * 70)

    return log

def remap(blend_data, new_order, stride=8):
    if len(blend_data) % stride != 0:
        raise ValueError("Invalid blend file length")

    remapped_blend = bytearray()
    log_messages = []

    for i in range(0, len(blend_data), stride):

        blendindices = struct.unpack_from("<BBBB", blend_data, i)
        blendweights = blend_data[i + 4:i + 8]

        outputindices = bytearray()
        for index in blendindices:
            if index < len(new_order):
                remapped_index = new_order[index]
                outputindices.append(remapped_index)
                log_messages.append(f"Remapping index {index} to {remapped_index}")
            else:
                outputindices.append(index)


        outputweights = bytearray(blendweights)


        remapped_blend += outputindices + outputweights


    if len(remapped_blend) % stride != 0:
        raise ValueError("Remapped blend file is invalid")

    return remapped_blend

def force_remap(folder):
    '''Force remap a character based on the remap options.'''
    log = []
    log_message(log, 'Remap options:')
    for i, (k,v) in enumerate(remaps.items()):
        log_message(log, f'{i+1}: {v[0]}')
    option = -1
    while option == -1:
        try:
            option = int(input('Select a character to remap: ')) - 1
            if option < 0 or option >= len(remaps):
                log_message(log, 'Invalid option')
                option = -1
        except ValueError:
            log_message(log, 'Invalid option')
            option = -1
        for i, (k,v) in enumerate(remaps.items()):
            if option == i:
                option = k
    for root, dirs, files in os.walk(folder):
        blend_files = [x for x in files if "blend" in x.lower() and ".buf" in x.lower()
                    and os.path.dirname(os.path.join(root, x)) == folder]
        if len(blend_files) == 0:
            log_message(log, "No blend file found in this folder. Aborting!")
        for blend_file in blend_files:
            try:
                with open(os.path.join(root, blend_file), "rb") as g:
                    blend_data = g.read()
                    remap_data = remap(blend_data, remaps[option][1])
                with open(os.path.join(root, blend_file), "wb") as g:
                    g.write(remap_data)
                    log_message(log, f"File: {blend_file} VGs has been remapped successfully!")
            except Exception as e:
                log_message(log, f'Error processing file: {blend_file}')
                log_message(log, str(e))
                continue
    return log

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--force_remap', action='store_true', default=False)
    args = parser.parse_args()

    current_directory = os.getcwd()
    if args.force_remap:
        log = force_remap(current_directory)
    else:
        log = remap_verina(current_directory)
    print("\n".join(log))

    input('Done!')
