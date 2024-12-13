#include <iomanip>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include "Bloco.h"
#include "Carteira.h"
#include "Transacao.h"
#include "Blockchain.h"

int main() {
    // Criar uma carteira para gerar chaves e endereços
    Carteira minhaCarteira;
    std::cout << "Endereço da carteira: " << minhaCarteira.gerarEndereco() << std::endl;

    // Criar uma transação
    Transacao t("Alice", "Bob", 10.0);
    std::cout << "Valor da transação: " << t.getValor() << std::endl;

    // Assinar a transação com a chave privada da carteira
    if (t.assinarTransacao(minhaCarteira.getChavePrivada())) {
        std::cout << "Transação assinada com sucesso." << std::endl;
    }

    // Verificar a assinatura da transação
    if (t.verificarAssinatura(minhaCarteira.getChavePublica())) {
        std::cout << "Assinatura verificada com sucesso." << std::endl;
    } else {
        std::cout << "Falha na verificação da assinatura." << std::endl;
    }

    // Exibir as informações da transação
    t.exibirInformacoes();

    // Exemplo de uso de bloco
    std::vector<std::string> transacoes = {"Alice -> Bob: 10", "Bob -> Charlie: 5"};
    Bloco blocoGenesis(0, transacoes, "0", time(0));
    
    // Minerar o bloco e exibir o hash minerado
    std::cout << "Hash minerado: " << blocoGenesis.minerarBloco() << std::endl;

    // Exibir as informações do bloco
    blocoGenesis.exibirInformacoes();

    // Ajuste de dificuldade após a mineração
    Bloco::ajustarDificuldade();

    // Exibir a nova dificuldade
    std::cout << "Nova dificuldade: " << Bloco::getDificuldade() << std::endl;

    return 0;
}


