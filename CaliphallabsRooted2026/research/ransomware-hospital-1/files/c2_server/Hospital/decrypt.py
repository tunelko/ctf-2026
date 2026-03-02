import os
import re
import struct
from cryptography.fernet import Fernet

def decrypt_and_unpack(input_file, key_file, output_folder):
    if not os.path.exists(key_file):
        print(f"Error: Archivo clave '{key_file}' no encontrado.")
        return
    if not os.path.exists(input_file):
        print(f"Error: Archivo cifrado'{input_file}' no encontrado.")
        return

    try:
        with open(key_file, "rb") as kf:
            key = kf.read()
        cipher = Fernet(key)

        path_precursor = os.path.join(output_folder, "precursor-lesions")
        path_xrays = os.path.join(output_folder, "x-rays")

        for path in [path_precursor, path_xrays]:
            if not os.path.exists(path):
                os.makedirs(path)

        print(f"[*] Iniciando el descifrado de {input_file}...")

        with open(input_file, "rb") as f_in:
            while True:
                size_data = f_in.read(4)
                if not size_data:
                    break 

                block_size = struct.unpack(">I", size_data)[0]
                encrypted_block = f_in.read(block_size)
                decrypted_block = cipher.decrypt(encrypted_block)

                pattern = re.compile(b"FILE_NAME:(.*?)CONTENT:(.*?)END_FILE", re.DOTALL)
                match = pattern.search(decrypted_block)

                if match:
                    filename = match.group(1).decode()
                    content = match.group(2)
                    
                    if filename.lower().startswith("ocp"):
                        final_path = os.path.join(path_precursor, filename)
                        folder_tag = "[PRECURSOR]"
                    elif filename.lower().startswith("series"):
                        final_path = os.path.join(path_xrays, filename)
                        folder_tag = "[X-RAYS]"
                    else:
                        final_path = os.path.join(output_folder, filename)
                        folder_tag = "[OTHER]"
                    
                    with open(final_path, "wb") as f_out:
                        f_out.write(content)
                    print(f"    {folder_tag} Restored: {filename}")

        print(f"\n[+] Descifrado completado.")
        print(f"    Comprobar: {path_precursor}/")
        print(f"    Comprobar: {path_xrays}/")

    except Exception as e:
        print(f"[-] Error descifrado: {e}")

if __name__ == "__main__":
    decrypt_and_unpack("files.enc", "key.txt", "restored_medical_files")