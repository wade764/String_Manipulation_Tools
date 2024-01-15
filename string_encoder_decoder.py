import sys
import base64
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib



# Helper function to check if the given data is binary.
def is_binary(data):
    """Check if the given data is binary."""
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    return bool(data.translate(None, textchars))



# Helper function to provide a hex dump of the given data.
def hex_dump(data, length=16):
    """Provide a hex dump of the given data."""
    result = []
    for i in range(0, len(data), length):
        line = data[i:i+length]
        hex_data = ' '.join(f'{b:02x}' for b in line)
        ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in line)
        result.append(f'{i:04x}  {hex_data:<{length*3}}  {ascii_data}')
    return '\n'.join(result)



# Helper function to pad the given data to the given block size.
def pad(data, block_size):
    """Pad the given data to the given block size."""
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding] * padding)



# Encypts the given string with the given key.
def encrypt_string(string, key):
    # AES Encrypt
    sha256 = hashlib.sha256()
    sha256.update(key.encode('utf-8'))
    aes_key = sha256.digest()
    aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
    padded_data = string.encode('utf-8')
    padded_data = pad(padded_data, AES.block_size)
    encrypted_bytes = aes.encrypt(padded_data)

    # GZip Compress
    compressed_bytes = zlib.compress(encrypted_bytes)

    # Base64 Encode
    encoded_bytes = base64.b64encode(compressed_bytes)

    return encoded_bytes.decode('utf-8')



# Decrypts the given string with the given key.
def decrypt_string(encoded_string, key):
    # Base64 Decode
    decoded_bytes = base64.b64decode(encoded_string)

    # GZip Decompress
    decompressed_bytes = zlib.decompress(decoded_bytes)

    # AES Decrypt
    sha256 = hashlib.sha256()
    sha256.update(key.encode('utf-8'))
    aes_key = sha256.digest()
    aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
    decrypted_bytes = unpad(aes.decrypt(decompressed_bytes), AES.block_size)

    if is_binary(decrypted_bytes):
        return hex_dump(decrypted_bytes)
    else:
        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            print("Decoding error:", e)
            return hex_dump(decrypted_bytes)



# Helper function to print the error message and exit the program.
def error_message():
    print("Usage: python string_encoder_decoder.py -e|-d -k key input_file")

    # Exit the program gracefully
    sys.exit(1)



# Helper function to check the user arguments.
def check_user_arguments(arg_count):
    # Check for correct number of arguments
    if arg_count != 5:
        print("Error: Incorrect number of arguments")
        error_message()
    
    # Check for correct flag
    if sys.argv[1] != "-e" and sys.argv[1] != "-d":
        print("Error: Incorrect flag")
        error_message()
    
    # Check for correct key
    if sys.argv[2] != "-k":
        print("Error: Incorrect key")
        error_message()



# This program reads from a .txt file and encrypts or decrypts the contents based
# on the -e or -d flag. The -k flag is required and used to set the key value.
# The encrypted or decrypted contents are then written to a new
# file with the same name as the original file, but with the .enc or .dec extension.
def main():
    
    # Get number of arguments
    arg_count = len(sys.argv)
    print(f"Number of arguments: {arg_count}")

    # Check to make sure the -h help flag is used
    if arg_count == 1 and sys.argv[1] == "-h":
        print("Help flag detected")
        error_message()

    # Check valid num and type of arguments
    check_user_arguments(arg_count)

    # Check for valid file
    try:
        file = open(sys.argv[4], "r")
    except:
        print("Error opening file")
        return
    
    # Setting the arguments to local variables
    operation = sys.argv[1]
    key = sys.argv[3]

    # Check if I am encrypting or decrypting
    if sys.argv[1] == "-e":
        # Encrypt
        encrypted_string = encrypt_string(file.read(), key)

        # Write to file
        file_name = sys.argv[4][:-4] + ".enc"
        file = open(file_name, "w")
        file.write(encrypted_string)
        file.close()

    else:
        # Decrypt
        decrypted_string = decrypt_string(file.read(), key)

        # Write to file
        file_name = sys.argv[4][:-4] + ".dec"
        file = open(file_name, "w")
        file.write(decrypted_string)
        file.close()



# Ensures that the main function is called only when the script
# is executed directly (not when imported as a module in another script).
if __name__ == "__main__":
    main()