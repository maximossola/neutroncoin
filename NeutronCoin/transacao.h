#ifndef TRANSACAO_H
#define TRANSACAO_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <sstream>
#include <iomanip>
#include <iostream>

class Transacao {
public:
    // Construtor da classe Transacao
    Transacao(const std::string& remetente, const std::string& destinatario,
              double valor);

    // Método para assinar a transação
    bool assinarTransacao(EVP_PKEY* chavePrivada);

    // Método para verificar a assinatura da transação
    bool verificarAssinatura(EVP_PKEY* chavePublica) const;

    // Getters para acessar os atributos da transação
    std::string getRemetente() const;
    std::string getDestinatario() const;
    double getValor() const;

    // Converter o vetor de assinatura para string hexadecimal
    std::string getAssinatura() const;

    // Método para exibir informações da transação
    void exibirInformacoes() const;

private:
    // Método para calcular o hash da transação
    std::vector<unsigned char> calcularHashTransacao() const;

    std::string remetente;
    std::string destinatario;
    double valor;
    std::vector<unsigned char> assinatura;
};

#endif  // TRANSACAO_H
