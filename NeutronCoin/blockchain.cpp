#include "Blockchain.h"
#include <ctime>
#include <iostream>

Blockchain::Blockchain() {
    // Criando o bloco Genesis
    std::vector<std::string> transacoes = {"Genesis Block"};
    Bloco genesis(0, transacoes, "0", time(0));
    blocos.push_back(genesis);  // Adiciona o bloco Genesis à blockchain
}

void Blockchain::adicionarBloco(const std::vector<std::string>& transacoes) {
    int indice = blocos.size();
    std::string hashAnterior = blocos[indice - 1].getHashBloco();  // Pega o hash do bloco anterior
    Bloco novoBloco(indice, transacoes, hashAnterior, time(0));   // Cria um novo bloco
    novoBloco.minerarBloco();  // Minerar o bloco (gerar hash com PoW)
    blocos.push_back(novoBloco);  // Adiciona o bloco à blockchain
}

bool Blockchain::verificarIntegridade() const {
    for (size_t i = 1; i < blocos.size(); ++i) {
        // Verifica se o hash do bloco atual é válido
        const Bloco& blocoAnterior = blocos[i - 1];
        const Bloco& blocoAtual = blocos[i];

        if (blocoAtual.getHashAnterior() != blocoAnterior.getHashBloco()) {
            return false;  // Se o hash do bloco anterior não corresponde, a blockchain foi corrompida
        }

        if (blocoAtual.getHashBloco() != blocoAtual.calcularHashBloco("")) {
            return false;  // Se o hash do bloco atual não corresponde ao seu conteúdo, é inválido
        }
    }
    return true;  // A blockchain é válida
}

void Blockchain::exibirBlockchain() const {
    for (const auto& bloco : blocos) {
        bloco.exibirInformacoes();
    }
}

std::string Bloco::getHashBloco() const {
    return hashBloco;
}

std::string Bloco::getHashAnterior() const {
    return hashAnterior;
}