#ifndef CARTEIRA_H
#define CARTEIRA_H

#include <openssl/evp.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/pem.h>

class Carteira {
public:
    // Construtor
    Carteira();
    
    // Destruidor
    ~Carteira();

    // Método para gerar o endereço a partir da chave pública
    std::string gerarEndereco() const;

    // Getter para a chave privada
    EVP_PKEY* getChavePrivada() const;

    // Getter para a chave pública
    EVP_PKEY* getChavePublica() const;

private:
    EVP_PKEY* chave;  // Chave privada e pública
};

#endif  // CARTEIRA_H
