#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <vector>
#include <string>
#include "Bloco.h"  // Para usar a classe Bloco

class Blockchain {
public:
    Blockchain();  // Construtor que cria o bloco Genesis

    // Adiciona um novo bloco à blockchain
    void adicionarBloco(const std::vector<std::string>& transacoes);

    // Verifica se a blockchain é válida (se não houve alteração)
    bool verificarIntegridade() const;

    // Exibe os blocos da blockchain
    void exibirBlockchain() const;

private:
    std::vector<Bloco> blocos;  // Armazena os blocos da blockchain
};

#endif
