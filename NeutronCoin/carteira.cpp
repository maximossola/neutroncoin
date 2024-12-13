#include "Carteira.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

Carteira::Carteira() {
    chave = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY_generate(ctx, &chave);
    EVP_PKEY_CTX_free(ctx);
}

Carteira::~Carteira() {
    if (chave) {
        EVP_PKEY_free(chave);
    }
}

std::string Carteira::gerarEndereco() const {
    // Obter a chave pública em formato binário
    std::vector<unsigned char> chavePublicaBin(256);  // Alocar dinamicamente
    unsigned char* p = chavePublicaBin.data();
    int chavePublicaLen = i2d_PUBKEY(chave, &p);

    // Calcular o hash da chave pública binária usando EVP_Digest
    unsigned char hashResult[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, chavePublicaBin.data(), chavePublicaLen);
    EVP_DigestFinal_ex(mdctx, hashResult, NULL);
    EVP_MD_CTX_free(mdctx);

    // Converter o hash para string hexadecimal
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hashResult[i]);
    }

    std::string endereco = "NC" + ss.str();
    return endereco;
}

EVP_PKEY* Carteira::getChavePrivada() const {
    return chave;
}

EVP_PKEY* Carteira::getChavePublica() const {
    return EVP_PKEY_dup(chave);  // Duplicar a chave com segurança
}
