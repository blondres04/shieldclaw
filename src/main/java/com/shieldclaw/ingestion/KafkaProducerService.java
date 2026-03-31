package com.shieldclaw.ingestion;

import com.shieldclaw.audit.PRPayloadDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KafkaProducerService {

    private static final String TOPIC = "audit.pr.ingested";

    private final KafkaTemplate<String, PRPayloadDTO> kafkaTemplate;

    public void publishPayload(String key, PRPayloadDTO payload) {
        kafkaTemplate.send(TOPIC, key, payload);
    }
}
