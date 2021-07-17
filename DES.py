# Information regarding the internal workings
# of DES. Information was gathered from
# https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
#
# input file: Contians the message that needs encrypting.
#   Message should be in ASCII or encrption and hexidecimal for decryption.
# key file: Contains the key used for encrypting.
#   Key should be 64-bits and in hexidecimal.
# Utilizing ECB and NULL padding.

# Note: Since encrypting will give an output that is not of traditional characters,
# it may be difficult to save the output in order to utilize it for decryption.
# That being the case, outputs are provided as both ASCII and hexadecimal. The
# decryption function is set up to accept hexidecimal inputs as a result.

# Imports
import sys

# Variables needed to get DES to work.
initial_permutation = [58,50,42,34,26,18,10,2,
                       60,52,44,36,28,20,12,4,
                       62,54,46,38,30,22,14,6,
                       64,56,48,40,32,24,16,8,
                       57,49,41,33,25,17,9,1,
                       59,51,43,35,27,19,11,3,
                       61,53,45,37,29,21,13,5,
                       63,55,47,39,31,23,15,7]
final_permutation = [40,8,48,16,56,24,64,32,
                     39,7,47,15,55,23,63,31,
                     38,6,46,14,54,22,62,30,
                     37,5,45,13,53,21,61,29,
                     36,4,44,12,52,20,60,28,
                     35,3,43,11,51,19,59,27,
                     34,2,42,10,50,18,58,26,
                     33,1,41,9,49,17,57,25]
expansion = [32,1,2,3,4,5,
             4,5,6,7,8,9,
             8,9,10,11,12,13,
             12,13,14,15,16,17,
             16,17,18,19,20,21,
             20,21,22,23,24,25,
             24,25,26,27,28,29,
             28,29,30,31,32,1]
primitive = [16,7,20,21,
             29,12,28,17,
             1,15,23,26,
             5,18,31,10,
             2,8,24,14,
             32,27,3,9,
             19,13,30,6,
             22,11,4,25]
p_choice_1 = [57,49,41,33,25,17,9,
              1,58,50,42,34,26,18,
              10,2,59,51,43,35,27,
              19,11,3,60,52,44,36,
              63,55,47,39,31,23,15,
              7,62,54,46,38,30,22,
              14,6,61,53,45,37,29,
              21,13,5,28,20,12,4]
p_choice_2 = [14,17,11,24,1,5,
              3,28,15,6,21,10,
              23,19,12,4,26,8,
              16,7,27,20,13,2,
              41,52,31,37,47,55,
              30,40,51,45,33,48,
              44,49,39,56,34,53,
              46,42,50,36,29,32]
sbox = [[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
          [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
          [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
          [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
         [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
          [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
          [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
          [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
         [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
          [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
          [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
          [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
         [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
          [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
          [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
          [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
         [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
          [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
          [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
          [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
         [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
          [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
          [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
          [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
         [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
          [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
          [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
          [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
         [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
          [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
          [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
          [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]
left_shift_values = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# Changing how the data is viewed and manipulated.
def hex2bin(hex_text):
    # Designed to generate leading zeros to make
    # output into 4 bits.
    bin_text = ""
    for i in range(len(hex_text)):
        bin_value = bin(int(hex_text[i],16))[2:]
        bin_value = (4-len(bin_value))*"0" + bin_value
        bin_text = bin_text + bin_value
    return bin_text
def bin2hex(bin_text):
    hex_text = ""
    for i in range(0,len(bin_text),4):
        hex_text = hex_text + hex(int(bin_text[i:i+4],2))[2:]
    return hex_text
def str2bin(str_text):
    # Designed to generate leading zeros to make
    # output into 8 bits.
    bin_text = ""
    for i in range(len(str_text)):
        bin_value = bin(int(ord(str_text[i])))[2:]
        bin_value = (8-len(bin_value))*"0" + bin_value
        bin_text = bin_text + bin_value
    return bin_text
def bin2str(bin_text):
    str_text = ""
    for i in range(0,len(bin_text),8):
        str_text = str_text + chr(int(bin_text[i:i+8],2))
    return str_text

# Group of functions used to perform tasks needed for DES.
# Function used in permuting.
def permutation_function(text,p_board,size):
    permutation = ""
    for i in range(0,size):
        permutation = permutation + text[p_board[i]-1]
    return permutation
# Shift values left.
def left_shift(text, shift_value):
    shift_value = shift_value%len(text)
    shifted = ""
    for i in range(shift_value,len(text)):
        shifted = shifted + text[i]
    shifted = shifted + text[0:shift_value]
    return shifted
# XOR two binary values together.
def xor(bin_1, bin_2):
    # Note that the two values that are put into XOR
    # have to be of the same length.
    solution = ""
    for i in range(len(bin_1)):
        if bin_1[i] == bin_2[i]:
            solution = solution + "0"
        else:
            solution = solution + "1"
    return solution
# Generates all the round keys.
def round_key_generator(key):
    # Key expected as a binary.
    key = permutation_function(key, p_choice_1, 56)
    left = key[0:28]
    right = key[28:56]
    round_keys = []
    # Create key for each round
    for i in range(16):
        left = left_shift(left, left_shift_values[i])
        right = left_shift(right, left_shift_values[i])
        new_key = left+right
        new_key = permutation_function(new_key, p_choice_2, 48)
        round_keys.append(new_key)
    return round_keys
# Encrypts data using DES.
def encrypt(text,round_keys):
    # Text and keys expected as binaries.
    plaintext = permutation_function(text, initial_permutation, 64)
    # Break data into right and left
    left = plaintext[0:32]
    right = plaintext[32:64]
    # Run through each round
    for i in range(16):
        right_expand = permutation_function(right, expansion, 48)
        xor_text = xor(right_expand, round_keys[i])
        sbox_text = ""
        # Find appropriate sbox value
        for j in range(8):
            row = int(xor_text[j*6]+xor_text[j*6+5],2)
            col = int(xor_text[j*6+1:j*6+5],2)
            sbox_value = sbox[j][row][col]
            sbox_text = sbox_text + hex2bin(hex(sbox_value)[2:])
        sbox_text = permutation_function(sbox_text, primitive, 32)
        left = xor(left, sbox_text)
        # Swap left and right
        if i != 15:
            temp = right
            right = left
            left = temp
    mixed_text = left+right
    ciphertext = permutation_function(mixed_text, final_permutation, 64)
    return ciphertext
# Decrypt option, just reverse the round keys and encrypt
def decrypt(text,round_keys):
    reverse_round_keys = round_keys[::-1]
    plaintext = encrypt(text, reverse_round_keys)
    return plaintext

# Running the program
print("DES Encryption System")
# Since the round keys need to be read in reverse,
# encryption and decryption need to be specified.
choice = input("Please indicate the required function.\n\t(1) encrypting\n\t(2) decrypting\n")
while True:
    if choice == "1" or choice == "2":
        break
    else:
        choice = input("Please input either the number 1 or 2 for either encryption or decryption:\n")
# Read text file.
input_file = input("Please input the text file:\n")
f = open(input_file, "r")
input_text = f.read()
f.close()
# Adjust input file based on encryption or decryption.
if choice == "1":
    binary_text = str2bin(input_text)
else:
    binary_text = hex2bin(input_text)
# Add padding if not a multiple of 64.
if (len(binary_text)%64) != 0:
    binary_text = binary_text + (64-(len(binary_text)%64))*"0"
# Read key.
input_file = input("Please input the key file:\n")
f = open(input_file, "r")
input_key = f.read()
f.close()
binary_key = hex2bin(input_key)
if len(binary_key) != 64:
    sys.exit("Key is not 64-bits long.")
generated_keys = round_key_generator(binary_key)
# Perform the encryption.
if choice == "1":
    ciphertext = ""
    for i in range(0, len(binary_text), 64):
        ciphertext = ciphertext + encrypt(binary_text[i:i+64], generated_keys)
    print("Ciphertext in ASCII:\n" + bin2str(ciphertext))
    print("\nCiphertext in Hexadecimal:\n" + bin2hex(ciphertext))
else:
    plaintext = ""
    for i in range(0, len(binary_text), 64):
        plaintext = plaintext + decrypt(binary_text[i:i+64], generated_keys)
    print("Plaintext in ASCII:\n" + bin2str(plaintext))
    print("\nPlaintext in Hexadecimal:\n" + bin2hex(plaintext))
