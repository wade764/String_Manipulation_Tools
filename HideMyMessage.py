import sys
import base64
import zlib
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from argparse import ArgumentParser



# Helper function to check if the given data is binary.
def is_binary(data):
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    return bool(data.translate(None, textchars))



# Helper function to provide a hex dump of the given data.
def hex_dump(data, length=16):
    result = []
    for i in range(0, len(data), length):
        line = data[i:i+length]
        hex_data = ' '.join(f'{b:02x}' for b in line)
        ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
        result.append(f'{i:04x}  {hex_data:<{length*3}}  {ascii_data}')
    return '\n'.join(result)



# Helper function to generate a key from the given string.
def generate_key(key):
    sha256 = hashlib.sha256()
    sha256.update(key.encode('utf-8'))
    return sha256.digest()



# Encypts the given string with the given key.
def encrypt_string(data, key):
    iv = get_random_bytes(16)
    aes = AES.new(generate_key(key), AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted_bytes = aes.encrypt(padded_data)
    compressed_bytes = zlib.compress(iv + encrypted_bytes)
    encoded_bytes = base64.b64encode(compressed_bytes)
    return encoded_bytes



# Decrypts the given string with the given key.
def decrypt_string(encoded_data, key):
    decoded_bytes = base64.b64decode(encoded_data)
    decompressed_bytes = zlib.decompress(decoded_bytes)
    iv, encrypted_bytes = decompressed_bytes[:16], decompressed_bytes[16:]
    aes = AES.new(generate_key(key), AES.MODE_CBC, iv)
    decrypted_bytes = unpad(aes.decrypt(encrypted_bytes), AES.block_size)
    return decrypted_bytes



# Processes the given file with the given key and mode.
def process_file(file_path, key, mode):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        
        if mode == 'encrypt':
            processed_data = encrypt_string(data, key)
            output_file_path = file_path + '.enc'
        else:
            processed_data = decrypt_string(data, key)
            output_file_path = file_path + '.dec'

        with open(output_file_path, 'wb') as file:
            file.write(processed_data)
        print(f"Output written to {output_file_path}")

    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)



# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# This is an improved version of string_encoder_decoder.py.
#
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# HideMyMessage.py adds the following additional features:
#
#    Argument Parsing: Implemented argparse for robust command-line argument handling.
#    File Handling:    Used with statement for file operations to ensure proper opening and
#                      closing of files, and switched to binary mode for reading and writing.
#    Random IV:        Introduced random IV generation for encryption.
#    Refactoring:      Broke down the main function into smaller, more manageable functions.
#    Error Handling:   Added basic error handling for file operations and processing steps.
#    Key Generation:   Modularized key generation from the provided string key.
#
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Usage:
#     
#    python HideMyMessage.py encrypt -k key input_file
#    python HideMyMessage.py decrypt -k key input_file
#
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

def main():
    parser = ArgumentParser(description="String Encoder/Decoder Tool")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode of operation")
    parser.add_argument('-k', '--key', required=True, help="Encryption/Decryption Key")
    parser.add_argument('file', help="Input file")

    args = parser.parse_args()

    process_file(args.file, args.key, args.mode)



# Ensures that the main function is called only when the script
# is executed directly (not when imported as a module in another script).
if __name__ == "__main__":
    main()