package com.aegisgate.ingestion;

import com.aegisgate.audit.PRPayloadDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KafkaProducerService {

    private static final String TOPIC = "audit.pr.ingested";

    private final KafkaTemplate<String, PRPayloadDTO> kafkaTemplate;

    public void publishPayload(PRPayloadDTO payload) {
        kafkaTemplate.send(TOPIC, payload.prId(), payload);
    }
}
