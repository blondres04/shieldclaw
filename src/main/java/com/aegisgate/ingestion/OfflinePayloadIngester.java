package com.aegisgate.ingestion;

import com.aegisgate.audit.PRPayloadDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.InputStream;

@Service
@Slf4j
@RequiredArgsConstructor
public class OfflinePayloadIngester {

    private final ObjectMapper objectMapper;
    private final KafkaProducerService kafkaProducerService;

    private final PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

    @Scheduled(fixedRate = 15000)
    public void scanAndIngest() {
        try {
            Resource[] resources = resolver.getResources("classpath:offline-payloads/*.json");

            if (resources.length == 0) {
                log.debug("No offline payloads found in classpath:offline-payloads/");
                return;
            }

            for (Resource resource : resources) {
                try (InputStream is = resource.getInputStream()) {
                    PRPayloadDTO payload = objectMapper.readValue(is, PRPayloadDTO.class);
                    kafkaProducerService.publishPayload(payload);
                    log.info("Ingested offline payload [{}] from {}", payload.prId(), resource.getFilename());
                } catch (Exception e) {
                    log.error("Failed to deserialize payload from {}: {}", resource.getFilename(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.error("Error scanning offline-payloads directory: {}", e.getMessage());
        }
    }
}
