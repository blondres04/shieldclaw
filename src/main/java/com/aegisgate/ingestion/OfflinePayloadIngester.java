package com.aegisgate.ingestion;

import com.aegisgate.audit.PRPayloadDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
@Slf4j
@RequiredArgsConstructor
public class OfflinePayloadIngester {

    private final ObjectMapper objectMapper;
    private final KafkaProducerService kafkaProducerService;

    @Value("${payload.directory:src/main/resources/offline-payloads}")
    private String payloadDirectory;

    @Scheduled(fixedRate = 15000)
    public void scanAndIngest() {
        Path readyDir = Path.of(payloadDirectory, "ready");

        if (!Files.isDirectory(readyDir)) {
            log.debug("Ready directory does not exist: {}", readyDir);
            return;
        }

        File[] files = readyDir.toFile().listFiles((d, name) -> name.endsWith(".json"));

        if (files == null || files.length == 0) {
            log.debug("No ready payloads found in {}", readyDir);
            return;
        }

        for (File file : files) {
            try {
                PRPayloadDTO payload = objectMapper.readValue(file, PRPayloadDTO.class);
                String messageKey = extractKey(file.getName(), payload);
                kafkaProducerService.publishPayload(messageKey, payload);
                log.info("Ingested payload [key={}] from {}", messageKey, file.getName());

                if (!file.delete()) {
                    log.warn("Failed to delete ingested file: {}", file.getName());
                }
            } catch (Exception e) {
                log.error("Failed to process payload {}: {}", file.getName(), e.getMessage());
            }
        }
    }

    private String extractKey(String filename, PRPayloadDTO payload) {
        if (payload.prId() != null && !payload.prId().isBlank()) {
            return payload.prId();
        }
        return filename.replace(".json", "");
    }
}
