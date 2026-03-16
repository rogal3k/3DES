#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Lista słabych kluczy z dokumentacji NIST
const std::vector<uint64_t> WEAK_KEYS = {
    // Słabe klucze (Weak Keys)
    0x0101010101010101, 0xFEFEFEFEFEFEFEFE, 0xE0E0E0E0F1F1F1F1, 0x1F1F1F1F0E0E0E0E,

    // Na wpół słabe klucze (Semi-weak Keys)
    0x011F011F010E010E, 0x1F011F010E010E01, 0x01E001E001F101F1, 0xE001E001F101F101,
    0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01, 0x1FE01FE00EF10EF1, 0xE01FE01FF10EF10E,
    0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E, 0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1,

    // Potencjalnie słabe klucze (Possibly weak keys)
    0x01011F1F01010E0E, 0x1F1F01010E0E0101, 0xE0E01F1FF1F10E0E, 0x0101E0E00101F1F1,
    0x1F1FE0E00E0EF1F1, 0xE0E0FEFEF1F1FEFE, 0x0101FEFE0101FEFE, 0x1F1FFEFE0E0EFEFE,
    0xE0FE011FF1FE010E, 0x011F1F01010E0E01, 0x1FE001FE0EF101FE, 0xE0FE1F01F1FE0E01,
    0x011FE0FE010EF1FE, 0x1FE0E01F0EF1F10E, 0xE0FEFEE0F1FEFEF1, 0x011FFEE0010EFEF1,
    0x1FE0FE010EF1FE01, 0xFE0101FEFE0101FE, 0x01E01FFE01F10EFE, 0x1FFE01E00EFE01F1,
    0xFE011FE0FE010EF1, 0xFE01E01FFE01F10E, 0x1FFEE0010EFEF101, 0xFE1F01E0FE0E01F1,
    0x01E0E00101F1F101, 0x1FFEFE1F0EFEFE0E, 0xFE1FE001FE0EF101, 0x01E0FE1F01F1FE0E,
    0xE00101E0F10101F1, 0xFE1F1FFEFE0E0EFE, 0x01FE1FE001FE0EF1, 0xE0011FFEF1010EFE,
    0xFEE0011FFEF1010E, 0x01FEE01F01FEF10E, 0xE001FE1FF101FE0E, 0xFEE01F01FEF10E01,
    0x01FEFE0101FEFE01, 0xE01F01FEF10E01FE, 0xFEE0E0FEFEF1F1FE, 0x1F01011F0E01010E,
    0xE01F1FE0F10E0EF1, 0xFEFE0101FEFE0101, 0x1F01E0FE0E01F1FE, 0xE01FFE01F10EFE01,
    0xFEFE1F1FFEFE0E0E, 0x1F01FEE00E01FEF1, 0xE0E00101F1F10101, 0xFEFEE0E0FEFEF1F1
};

// Funkcja sprawdzająca czy klucz jest słaby
bool isWeakKey(const unsigned char* key3des) {
    // 3DES korzysta z 24 bajtów, ale każdy z trzech 8-bajtowych segmentów jest sprawdzany osobno
    for (int i = 0; i < 3; ++i) {
        uint64_t keyPart = 0;
        std::memcpy(&keyPart, key3des + (i * 8), 8);
        
        for (uint64_t weak : WEAK_KEYS) {
            if (keyPart == weak) {
                return true;
            }
        }
    }
    return false;
}

// Funkcja szyfrująca/deszyfrująca strumieniowo
bool processFile(const std::string& inPath, const std::string& outPath, 
                 const unsigned char* key, const unsigned char* iv, bool encrypt) {
    
    std::ifstream inFile(inPath, std::ios::binary);
    std::ofstream outFile(outPath, std::ios::binary);
    
    if (!inFile.is_open() || !outFile.is_open()) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Inicjalizacja algorytmu 3DES w trybie CBC
    if (encrypt) {
        EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    } else {
        EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    }

    const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB bufor 
    std::vector<unsigned char> inBuffer(CHUNK_SIZE);
    // Bufor wyjściowy musi być nieco większy na padding bloku
    std::vector<unsigned char> outBuffer(CHUNK_SIZE + EVP_CIPHER_block_size(EVP_des_ede3_cbc())); 
    
    int outLen;
    while (inFile.read(reinterpret_cast<char*>(inBuffer.data()), CHUNK_SIZE) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        if (encrypt) {
            EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), bytesRead);
        } else {
            EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, inBuffer.data(), bytesRead);
        }
        outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    // Finalizacja - dodanie/usunięcie paddingu (PKCS#7)
    if (encrypt) {
        EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen);
    } else {
        int ret = EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen);
        if (ret != 1) {
            std::cerr << "Błąd deszyfrowania (np. nieprawidłowy padding/klucz)." << std::endl;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    outFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {
    // 3DES wymaga klucza 24-bajtowego (192 bity) oraz IV 8-bajtowego (64 bity)
    unsigned char key[24];
    unsigned char iv[8];

    // Wygenerowanie bezpiecznego, losowego klucza i IV
    do {
        RAND_bytes(key, sizeof(key));
    } while (isWeakKey(key));

    RAND_bytes(iv, sizeof(iv));

    std::string inputFile = "plik_do_zaszyfrowania.mp4";
    std::string encFile = "plik_zaszyfrowany.enc";
    std::string decFile = "plik_odszyfrowany.mp4";

    long long fileSize = 0;
    std::ifstream f(inputFile, std::ios::ate | std::ios::binary);
    if(f.is_open()) {
        fileSize = f.tellg();
        f.close();
        std::cout << "Rozmiar pliku wejsciowego: " << fileSize << " bajtow" << std::endl;
    } else {
        std::cerr << "Ostrzezenie: Nie znaleziono pliku " << inputFile << std::endl;
    }

    std::cout << "Rozpoczynam szyfrowanie (Tryb CBC)..." << std::endl;
    auto startEnc = std::chrono::high_resolution_clock::now();
    processFile(inputFile, encFile, key, iv, true);
    auto endEnc = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffEnc = endEnc - startEnc;
    std::cout << "Czas szyfrowania: " << diffEnc.count() << " s" << std::endl;

    std::cout << "Rozpoczynam deszyfrowanie..." << std::endl;
    auto startDec = std::chrono::high_resolution_clock::now();
    processFile(encFile, decFile, key, iv, false);
    auto endDec = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffDec = endDec - startDec;
    std::cout << "Czas deszyfrowania: " << diffDec.count() << " s" << std::endl;

    std::ofstream results("wyniki.txt", std::ios::app);
    if (results.is_open()) {
        results << "Plik: " << inputFile << " | Rozmiar: " << fileSize << " B"
                << " | Szyfrowanie: " << std::fixed << std::setprecision(6) << diffEnc.count() << " s"
                << " | Deszyfrowanie: " << diffDec.count() << " s" << std::endl;
        std::cout << "Zapisano wyniki do wyniki.txt" << std::endl;
    }


    return 0;
}