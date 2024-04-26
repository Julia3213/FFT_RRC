#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>



int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Unable to create socket" << std::endl;
        return 1;
    }

    // Привязка к IP и порту
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(12345);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error: Bind failed" << std::endl;
        return 1;
    }

    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Error: Listen failed" << std::endl;
        return 1;
    }

    std::cout << "Waiting for incoming connection..." << std::endl;
    int clientSocket = accept(serverSocket, NULL, NULL);
    if (clientSocket < 0) {
        std::cerr << "Error: Accept failed" << std::endl;
        return 1;
    }

    // Получение сообщения RRCConnectionRequest от клиента
    void *encodedMessage = nullptr; // Буфер для принятого сообщения
    // Принимаем сообщение от клиента
    ssize_t recvLen = recv(clientSocket, encodedMessage, sizeof(encodedMessage), 0);
    if (recvLen < 0) {
        std::cerr << "Error: Receive failed" << std::endl;
        return 1;
    }

    // Декодирование принятого сообщения RRCConnectionRequest
    
    asn_dec_rval_t rval = ber_decode(0, &asn_DEF_RRCConnectionRequest, (void **)&rrcrequest, encodedMessage, recvLen);
    if (rval.code != RC_OK) {
        fprintf(stderr, "Failed to decode RRCConnectionRequest: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    // Выводим значения полей структуры RRCConnectionRequest
    // Пример вывода данных
    std::cout << "InitialUE_Identity: " << rrcrequest.initialUE_Identity.choice.randomValue.buf << std::endl;
    std::cout << "EstablishmentCause: " << rrcrequest.establishmentCause << std::endl;
    std::cout << "ProtocolErrorIndicator: " << rrcrequest.protocolErrorIndicator << std::endl;

    // Закрываем файл и завершаем программу
    close(fd);

    // Формирование и отправка сообщения RRCConnectionSetupComplete клиенту
    RRCConnectionSetupComplete_t rrcComplete;
    memset(&rrcComplete, 0, sizeof(rrcComplete)); // Обнуляем структуру

    // Заполняем структуру данными (примерные значения)
    rrcComplete.rrc_TransactionIdentifier = 456;

    // Пример заполнения остальных полей структуры (можете подставить свои значения)
    rrcComplete.criticalExtensions.present = RRCConnectionSetupComplete__criticalExtensions_PR_c1;
    rrcComplete.criticalExtensions.choice.c1.present = RRCConnectionSetupComplete__criticalExtensions__c1_PR_rrcConnectionSetupComplete_r8;
    rrcComplete.criticalExtensions.choice.c1.choice.rrcConnectionSetupComplete_r8.selectedPLMN_Identity = 1;
    // Заполните остальные поля структуры в соответствии с вашими требованиями

    // Кодируем структуру RRCConnectionSetupComplete в формат DER
    uint8_t encodedMessage[4096];
    asn_enc_rval_t encRetVal = der_encode_to_buffer(&asn_DEF_RRCConnectionSetupComplete, &rrcComplete, encodedMessage, sizeof(encodedMessage));
    if (encRetVal.encoded == -1) {
        std::cerr << "Error encoding RRCConnectionSetupComplete: " << encRetVal.failed_type->name << std::endl;
        return 1;
    }

    // Отправляем закодированное сообщение клиенту
    ssize_t sentLen = send(clientSocket, encodedMessage, encRetVal.encoded, 0);
    if (sentLen < 0) {
        std::cerr << "Error: Send failed" << std::endl;
        return 1;
    }
    // Закрытие сокетов
    close(clientSocket);
    close(serverSocket);

    return 0;
}
