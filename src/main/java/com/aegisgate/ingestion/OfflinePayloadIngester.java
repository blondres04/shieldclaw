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
        Path dir = Path.of(payloadDirectory);

        if (!Files.isDirectory(dir)) {
            log.debug("Payload directory does not exist: {}", dir);
            return;
        }

        File[] files = dir.toFile().listFiles((d, name) -> name.endsWith(".json"));

        if (files == null || files.length == 0) {
            log.debug("No offline payloads found in {}", dir);
            return;
        }

        for (File file : files) {
            try {
                PRPayloadDTO payload = objectMapper.readValue(file, PRPayloadDTO.class);
                kafkaProducerService.publishPayload(payload);
                log.info("Ingested offline payload [{}] from {}", payload.prId(), file.getName());
            } catch (Exception e) {
                log.error("Failed to deserialize payload from {}: {}", file.getName(), e.getMessage());
            }
        }
    }
}
