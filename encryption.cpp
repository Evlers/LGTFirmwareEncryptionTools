#include <iostream>
#include <fstream>

using namespace std;

static void codec_data(uint8_t* ptr, uint32_t len);

/**
 * @brief The master program for encrypting the firmware file
 *
 * @param offset The offset address of the file
 * @param ptr Data based on offset addresses
 * @param len Length of data
 */
int main(int argc, char **argv)
{
    if (argc < 3) {
        cout << "command <input file> <output file>";
        return -1;
    }

    char *in_file_path = argv[1];   // input file
    char *out_file_path = argv[2];  // output file

    ifstream in_file(in_file_path, ios::in | ios::binary);
    if (!in_file) {
        cout << "Can't open" << in_file_path << " file";
        return -2;
    }

    ofstream out_file(out_file_path, ios::out | ios::binary | ios::trunc);
    if (!out_file) {
        cout << "Can't create" << out_file_path << " file";
        return -3;
    }
    
    in_file.seekg(0, ios::end);                                             // Point to the file stream tail
    streampos in_file_len = in_file.tellg();                                // Get the pointer current position

    in_file.seekg(0, 0);                                                    // Point to the file stream header
    char* file_data = new char[in_file_len];                                // Create the file data buffer
    in_file.read(file_data, in_file_len);                                   // Read the plaintext data for file
    in_file.close();                                                        // Close the input file stream

    codec_data((uint8_t *)file_data, (uint32_t)in_file_len);                // Enciphered the firmware data

    out_file.write(file_data, in_file_len);                                 // Write the ciphertext data to output file
    out_file.close();                                                       // Close and save the output file stream

    cout << "Create an encrypted file: " << out_file_path;

    return 0;
}

/**
 * @brief Encryption firmware file encoding decoding
 *
 * @param offset The offset address of the file
 * @param ptr Data based on offset addresses
 * @param len Length of data
 */
static void codec_data(uint8_t* ptr, uint32_t len)
{
    static uint8_t const key[16] = { 0xAE, 0x86, 0x30, 0x7F, 0x67, 0x86, 0x21, 0x11, 0x24, 0x88, 0xD7, 0xC4, 0x3C, 0xF7, 0x99, 0x40 }; // codec key

    for (uint32_t i = 0; i < len; i++)
    {
        uint32_t sectors = i >> 9;                                          // Calculate the sector of the offset address of the file based on 512 as the sector
        uint32_t sectors_offset = i % 512;                                  // Calculates the offset address within the sector
        ptr[i] ^= sectors_offset + key[(sectors + sectors_offset) % 16];    // codec data
    }
}
